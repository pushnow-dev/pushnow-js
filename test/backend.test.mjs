import test from 'node:test';
import assert from 'node:assert/strict';
import {createECDH,webcrypto} from 'node:crypto';
import {startBackendFixture} from './helpers/backend-fixture.mjs';
import {openV2} from '../../../cli/test/v2-fixtures.js';
import {suite,bytes,base64,decode} from '../../../cli/src/crypto.js';
import * as sdk from '../dist/index.js';

test('actual sound routing accepts every enum and omission, preserves retries and rejects changed sound',{timeout:60000},async()=>{
  const h=await startBackendFixture();
  try {
    const directory=await sdk.recipientsV2(h.config);
    for(const sound of [undefined,'default','silent','chime']) {
      const message=await sdk.prepareMessageV2(h.config,directory,{title:'Sound metadata',body:'Still encrypted'},
        {sound,scheduledAt:new Date(Date.now()+60000).toISOString()});
      const bodies=[],fetcher=async(url,init)=>{bodies.push(init.body);return fetch(url,init);};
      assert.equal((await sdk.submitMessageV2(h.config,message,{fetcher})).deduplicated,false);
      assert.equal((await sdk.submitMessageV2(h.config,message,{fetcher})).deduplicated,true);
      assert.equal(bodies[0],bodies[1]);
      const row=await h.db.prepare('SELECT * FROM v2_messages WHERE id=?').bind(message.message_id).first();
      if(sound!==undefined)assert.equal(row.sound,sound);
      const clear=await openV2(h.fixture,{...row,message_id:row.id});assert.ok(!Object.hasOwn(clear,'sound'));
      const changed=await fetch(`${h.apiURL}/v2/messages`,{method:'POST',headers:{authorization:`Bearer ${h.config.source_key}`,
        'content-type':'application/json','idempotency-key':message.message_id},body:JSON.stringify({...message,sound:sound==='silent'?'chime':'silent'})});
      assert.equal(changed.status,409);
    }
  } finally {await h.close();}
});

test('actual Worker HTTP/D1/R2: account, authorization, encrypted content/files, scheduling, targets and per-key logs',{timeout:60000},async()=>{
  const h=await startBackendFixture();
  try {
    const {config,fixture:f,db,session}=h;
    async function call(method,path,body,expected=200) {
      const response=await fetch(`${h.apiURL}${path}`,{method,headers:{authorization:`Bearer ${session.accessToken}`,'content-type':'application/json'},
        ...(body===undefined?{}:{body:JSON.stringify(body)})});
      assert.equal(response.status,expected,`${method} ${path}`);
      return expected===204?null:response.json();
    }
    assert.equal((await call('GET','/v1/me')).user.id,config.user_id);
    const logs=[],options={onRequest:event=>logs.push(event)};
    const directory=await sdk.recipientsV2(config,options);assert.equal(directory.devices.length,2);
    const data=new TextEncoder().encode('Actual private file');
    const descriptor=await sdk.uploadAttachment(config,data,{name:'secret.txt',mime:'text/plain'},options);
    const content={title:'Actual private title',body:'Private body',links:['https://example.com'],attachments:[descriptor],image_id:descriptor.id,icon_id:descriptor.id};
    const scheduledAt=new Date(Date.now()+60000).toISOString(),expiresAt=new Date(Date.now()+120000).toISOString();
    const message=await sdk.prepareMessageV2(config,directory,content,{inboxOnly:true,scheduledAt,expiresAt});
    assert.equal((await sdk.submitMessageV2(config,message,options)).deduplicated,false);
    assert.equal((await sdk.submitMessageV2(config,message,options)).deduplicated,true);
    const history=await call('GET','/v2/messages');
    assert.deepEqual(await openV2(f,history.messages[0]),content);
    assert.equal(history.messages[0].scheduled_at,scheduledAt);assert.equal(history.messages[0].expires_at,expiresAt);
    const blob=await fetch(`${h.apiURL}/v2/attachments/${descriptor.id}`,{headers:{authorization:`Attachment ${descriptor.read_token}`}});
    assert.equal(blob.status,200);const ciphertext=await blob.arrayBuffer();assert.ok(!Buffer.from(ciphertext).includes(data));
    const aes=await webcrypto.subtle.importKey('raw',decode(descriptor.key),'AES-GCM',false,['decrypt']);
    assert.deepEqual(new Uint8Array(await webcrypto.subtle.decrypt({name:'AES-GCM',iv:decode(descriptor.nonce),
      additionalData:bytes(JSON.stringify([2,'attachment',config.user_id,config.source_id,descriptor.id]))},aes,ciphertext)),data);
    for(const [targetOptions,count] of [[{},2],[{deviceIds:[directory.devices[0].id]},1],[{inboxOnly:true},0]]) {
      const sent=await sdk.sendNotification(config,{title:'Targets',body:'Only selected devices'}, {...options,...targetOptions,scheduledAt});
      assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM v2_deliveries WHERE message_id=?').bind(sent.message_id).first()).n,count);
    }
    const result=await call('GET',`/v2/logs?key_id=${h.keyID}`);
    assert.equal(result.logs.length,4);assert.ok(result.logs.every(m=>m.key_id===h.keyID));
    assert.ok(!JSON.stringify(result).includes(content.title));
    const uploadSend=await sdk.sendNotification(config,{title:'Uploaded fields',body:'body',files:[{data,name:'a.txt'}],
      image:{data,name:'image.png',mime:'image/png'},icon:{data,name:'icon.png',mime:'image/png'}},{inboxOnly:true});
    const uploaded=(await call('GET',`/v2/messages/${uploadSend.message_id}`)).message;
    const decoded=await openV2(f,uploaded);assert.equal(decoded.attachments.length,3);
    assert.equal(decoded.attachments[1].id,decoded.image_id);assert.equal(decoded.attachments[2].id,decoded.icon_id);
    for(const secret of [config.source_key,config.sender_private_key,descriptor.key,descriptor.read_token,content.title])assert.ok(!JSON.stringify(logs).includes(secret));

    const pending=await sdk.beginLogin(h.apiURL,'Approved SDK',options);
    const source=(await call('POST','/v1/sources',{name:'Approved SDK'},201)).source;
    const created=await call('POST',`/v1/sources/${source.id}/keys`,{},201);
    const ec=createECDH('prime256v1');ec.setPrivateKey(decode(f.identityPrivateKey));const pub=ec.getPublicKey();
    const identity=await webcrypto.subtle.importKey('jwk',{kty:'EC',crv:'P-256',d:decode(f.identityPrivateKey).toString('base64url'),
      x:pub.subarray(1,33).toString('base64url'),y:pub.subarray(33).toString('base64url')},{name:'ECDSA',namedCurve:'P-256'},false,['sign']);
    const certificate=base64(await webcrypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},identity,bytes(`pushnow-source-v1\n${config.user_id}\n${source.id}\n${pending.key.publicKey}`)));
    await call('PUT',`/v1/secure/sources/${source.id}`,{public_key:pending.key.publicKey,certificate});
    const grantConfig={api_url:h.apiURL,user_id:config.user_id,source_id:source.id,source_key:created.source_key,identity_public_key:config.identity_public_key,archive:config.archive};
    const sender=await suite.createSenderContext({recipientPublicKey:await suite.kem.deserializePublicKey(decode(pending.key.publicKey)),info:bytes('pushnow-sender-grant-v2')});
    await call('POST',`/v2/authorizations/${pending.authorization.id}/approve`,{source_id:source.id,enc:base64(sender.enc),
      ciphertext:base64(await sender.seal(bytes(JSON.stringify(grantConfig)),bytes(JSON.stringify([2,'sender-grant',pending.authorization.id,pending.key.publicKey]))))},204);
    const authorized=await sdk.finishLogin(pending,{expectedIdentityFingerprint:await sdk.fingerprint(config.identity_public_key),...options});
    assert.equal(authorized.source_id,source.id);assert.equal(authorized.sender_private_key,pending.key.privateKey);
    await assert.rejects(sdk.recipientsV2({...config,source_key:authorized.source_key}),/identity changed/);
    await db.prepare('UPDATE source_keys SET expires_at=? WHERE id=?').bind('2020-01-01T00:00:00.000Z',h.keyID).run();
    await assert.rejects(sdk.recipientsV2(config),error=>error instanceof sdk.APIError&&error.status===401);
  } finally {await h.close();}
});
