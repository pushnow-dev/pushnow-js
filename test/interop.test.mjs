import test from 'node:test';
import assert from 'node:assert/strict';
import {fixtureV2, openV2} from '../../../cli/test/v2-fixtures.js';
import {suite, bytes, base64, decode} from '../../../cli/src/crypto.js';
import {createECDH, webcrypto} from 'node:crypto';
import * as sdk from '../dist/index.js';

export async function sign(f, kind, id, publicKey) {
  const ec = createECDH('prime256v1'); ec.setPrivateKey(decode(f.identityPrivateKey)); const pub = ec.getPublicKey();
  const key = await webcrypto.subtle.importKey('jwk', {kty:'EC', crv:'P-256', d:decode(f.identityPrivateKey).toString('base64url'),
    x:pub.subarray(1,33).toString('base64url'),y:pub.subarray(33).toString('base64url')}, {name:'ECDSA',namedCurve:'P-256'}, false, ['sign']);
  return base64(await webcrypto.subtle.sign({name:'ECDSA',hash:'SHA-256'}, key, bytes(`pushnow-${kind}-v1\n${f.config.user_id}\n${id}\n${publicKey}`)));
}
const json = value => new Response(JSON.stringify(value));

test('SDK manifests/previews decrypt in existing CLI with UTF-8 bounds and schedule', async () => {
  const f = await fixtureV2();
  const content = {title:'Private \u4f60\u597d'.repeat(50),body:'\u4f60\u597d content '.repeat(1000),links:['https://example.com'],attachments:[]};
  const message = await sdk.prepareMessageV2(f.config,f.directory,content,{inboxOnly:true,scheduledAt:new Date(Date.now()+60000).toISOString(),expiresAt:new Date(Date.now()+120000).toISOString()});
  assert.deepEqual(await openV2(f,message),content);
  const preview = await openV2(f,message,'preview');
  assert.ok(Buffer.byteLength(preview.title)<=400);assert.ok(Buffer.byteLength(preview.body)<=700);
  assert.deepEqual(message.notify_device_ids,[]);
  assert.ok(!JSON.stringify(message).includes(content.title));
  await assert.rejects(openV2(f,{...message,preview:message},'preview'));
  await assert.rejects(sdk.submitMessageV2({...f.config,user_id:crypto.randomUUID()},message),/original prepared/);
  await assert.rejects(sdk.submitMessageV2(f.config,JSON.parse(JSON.stringify(message))),/original prepared/);
  assert.throws(()=>{message.message_id=crypto.randomUUID();});
  assert.equal(sdk.validateConfig(f.config).user_id,f.config.user_id);
  assert.throws(()=>sdk.validateConfig({source_key:'token-only'}));
});

test('directory validation protects identity, source, private key, devices and archive at preparation', async () => {
  const f=await fixtureV2(), other=await fixtureV2();
  const get=value=>sdk.recipientsV2(f.config,{fetcher:async()=>json(value)});
  assert.equal((await get(f.directory)).devices.length,2);
  for(const patch of [{user_id:other.config.user_id},{source_id:other.config.source_id},{identity_public_key:other.config.identity_public_key},
    {source_public_key:other.sender.publicKey},{archive:other.config.archive},{devices:[f.devices[0],f.devices[0]]},
    {devices:[{...f.devices[0],notifications_enabled:1}]},{devices:[{...f.devices[0],certificate:other.devices[0].certificate}]}]) {
    await assert.rejects(get({...f.directory,...patch}));
    await assert.rejects(sdk.prepareMessageV2(f.config,{...f.directory,...patch},{title:'x',body:'y'}));
  }
  await assert.rejects(sdk.recipientsV2({...f.config,sender_private_key:other.sender.privateKey},{fetcher:async()=>json(f.directory)}),/does not match/);
  f.directory.devices[1].notifications_enabled=false;
  assert.deepEqual((await sdk.prepareMessageV2(f.config,f.directory,{title:'x',body:'y'},{deviceIds:[f.devices[1].id]})).notify_device_ids,[]);
  assert.equal((await sdk.prepareMessageV2(f.config,f.directory,{title:'x',body:'y'})).notify_device_ids,undefined);
  for(const options of [{deviceIds:[crypto.randomUUID()]},{inboxOnly:true,deviceIds:[]},{deviceIds:[f.devices[0].id,f.devices[0].id]},
    {scheduledAt:'2099-02-30T00:00:00Z'},{expiresAt:new Date(Date.now()-1).toISOString()}]) await assert.rejects(sdk.prepareMessageV2(f.config,f.directory,{title:'x',body:'y'},options));
  await assert.rejects(sdk.prepareMessageV2(f.config,f.directory,{title:'x',body:'y',sound:'critical'}),/Unsupported/);
});

test('attachment AES-GCM wire is CLI-compatible, filename and keys stay off HTTP/logs', async () => {
  const f=await fixtureV2(), clear=new TextEncoder().encode('private attachment'),events=[];let cipher, reservation;
  const descriptor=await sdk.uploadAttachment(f.config,clear,{name:'private.txt',mime:'text/plain'}, {onRequest:e=>events.push(e),fetcher:async(url,init)=>{
    assert.equal(init.redirect,'error');assert.equal(init.credentials,'omit');
    if(init.method==='POST'){reservation=JSON.parse(init.body);return json({id:reservation.id});}
    cipher=init.body;return new Response(null,{status:204});
  }});
  const key=await webcrypto.subtle.importKey('raw',decode(descriptor.key),'AES-GCM',false,['decrypt']);
  const params={name:'AES-GCM',iv:decode(descriptor.nonce),additionalData:bytes(JSON.stringify([2,'attachment',f.config.user_id,f.config.source_id,descriptor.id]))};
  assert.deepEqual(new Uint8Array(await webcrypto.subtle.decrypt(params,key,cipher)),clear);
  await assert.rejects(webcrypto.subtle.decrypt({...params,additionalData:bytes('wrong-source')},key,cipher));
  assert.equal(reservation.size,clear.length+16);assert.deepEqual(Object.keys(reservation).sort(),['id','read_token','size']);
  for(const secret of [f.config.source_key,descriptor.key,descriptor.read_token,'private.txt','private attachment']) assert.ok(!JSON.stringify(events).includes(secret));
  assert.equal(events[1].path,'/v2/attachments/:id');
  assert.deepEqual(clear,new TextEncoder().encode('private attachment'));
});

test('account token authorization interoperates with CLI grants and verifies identity and source binding', async () => {
  const f=await fixtureV2();
  const accessToken='test-access-token';
  const pending=await sdk.beginAccountLogin(f.config.api_url,accessToken,'Browser',{fetcher:async(_url,init)=>{
    assert.equal(init.headers.authorization,`Bearer ${accessToken}`);
    assert.deepEqual(Object.keys(JSON.parse(init.body)).sort(),['name','public_key']);
    return json({id:crypto.randomUUID(),device_code:base64(crypto.getRandomValues(new Uint8Array(32))),user_code:'ABCD2345',
      expires_at:new Date(Date.now()+60000).toISOString(),interval:3,user_id:f.config.user_id,identity_public_key:f.config.identity_public_key});
  }});
  const config={...f.config,sender_private_key:pending.key.privateKey},directory={...f.directory,source_public_key:pending.key.publicKey,
    source_certificate:await sign(f,'source',f.config.source_id,pending.key.publicKey)};
  const {sender_private_key,...grantConfig}=config;
  const sender=await suite.createSenderContext({recipientPublicKey:await suite.kem.deserializePublicKey(decode(pending.key.publicKey)),info:bytes('pushnow-sender-grant-v2')});
  const grant={enc:base64(sender.enc),ciphertext:base64(await sender.seal(bytes(JSON.stringify(grantConfig)),bytes(JSON.stringify([2,'sender-grant',pending.authorization.id,pending.key.publicKey]))))};
  const fetcher=async url=>json(url.pathname==='/v2/recipients'?directory:{status:'approved',grant});
  assert.equal((await sdk.finishAccountLogin(pending,{fetcher})).sender_private_key,pending.key.privateKey);
  await assert.rejects(sdk.finishAccountLogin({...pending,expectedIdentityFingerprint:'0'.repeat(64)},{fetcher}),/not confirmed/);
  await assert.rejects(sdk.finishAccountLogin(pending,{fetcher:async url=>json(url.pathname==='/v2/recipients'?f.directory:{status:'approved',grant})}),/does not match/);
  const controller=new AbortController();setTimeout(()=>controller.abort(),25);
  await assert.rejects(sdk.finishAccountLogin(pending,{signal:controller.signal,fetcher:async()=>new Response(null,{status:429})}),{name:'AbortError'});
});

test('safe logging and errors omit credentials and arbitrary server/network text',async()=>{
  const f=await fixtureV2(),events=[];
  await assert.rejects(sdk.recipientsV2(f.config,{onRequest:e=>events.push(e),fetcher:async()=>new Response(f.config.source_key,{status:401})}),e=>e instanceof sdk.APIError&&e.status===401&&!e.message.includes(f.config.source_key));
  await assert.rejects(sdk.recipientsV2(f.config,{onRequest:e=>events.push(e),fetcher:async()=>{throw new Error(f.config.source_key);}}),e=>!e.message.includes(f.config.source_key));
  assert.deepEqual(events.map(e=>e.outcome),['http_error','network_error']);
  assert.ok(!JSON.stringify(events).includes(f.config.source_key));
  await sdk.recipientsV2(f.config,{onRequest:async()=>{throw new Error('logging failed');},fetcher:async()=>json(f.directory)});
});
