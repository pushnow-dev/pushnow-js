import test from 'node:test';
import assert from 'node:assert/strict';
import {fixtureV2,openV2} from '../../../cli/test/v2-fixtures.js';
import * as sdk from '../dist/index.js';

test('all sound values and omission remain routing metadata and retries preserve exact bytes',async()=>{
  const f=await fixtureV2(),content={title:'Sound choice',body:'Private content',links:[],attachments:[]};
  for(const sound of [undefined,'default','silent','chime']) {
    const options=sound===undefined?{}:{sound};
    const message=await sdk.prepareMessageV2(f.config,f.directory,content,options);
    assert.equal(Object.hasOwn(message,'sound'),sound!==undefined);
    assert.equal(message.sound,sound);
    assert.deepEqual(await openV2(f,message),content);
    const preview=await openV2(f,message,'preview');assert.ok(!Object.hasOwn(preview,'sound'));
    const requests=[];
    const fetcher=async(_url,init)=>{
      requests.push({body:init.body,key:init.headers['idempotency-key']});
      if(requests.length===1)throw new Error('Uncertain connection after write');
      return new Response(JSON.stringify({message_id:message.message_id,deduplicated:true}));
    };
    await assert.rejects(sdk.submitMessageV2(f.config,message,{fetcher}));
    assert.equal((await sdk.submitMessageV2(f.config,message,{fetcher})).deduplicated,true);
    assert.deepEqual(requests[0],requests[1]);
    assert.equal(requests[1].body,JSON.stringify(message));
    assert.equal(Object.hasOwn(JSON.parse(requests[1].body),'sound'),sound!==undefined);
    assert.throws(()=>{message.sound='silent';});
  }
  const explicitUndefined=await sdk.prepareMessageV2(f.config,f.directory,content,{sound:undefined});
  assert.ok(!Object.hasOwn(explicitUndefined,'sound'));
});

test('invalid sound fails before high-level HTTP or uploads, including invalid content placement',async()=>{
  const f=await fixtureV2();let calls=0;
  const fetcher=async()=>{calls++;throw new Error('Must not fetch');};
  const content={title:'Test',body:'Body',files:[{name:'private.txt',data:new Uint8Array([1])}]};
  for(const sound of [null,'','DEFAULT','critical','pushnow-chime.wav',false,0,{},['chime']]) {
    await assert.rejects(sdk.sendNotification(f.config,content,{sound,fetcher}),/Invalid sound/);
    await assert.rejects(sdk.prepareMessageV2(f.config,f.directory,{title:'Test',body:'Body'},{sound}),/Invalid sound/);
  }
  await assert.rejects(sdk.sendNotification(f.config,{...content,sound:'chime'},{fetcher}),/MessageOptions/);
  assert.equal(calls,0);
});

test('high-level sender forwards each sound and bounds preview with full chime filename',async()=>{
  const f=await fixtureV2();
  for(const sound of [undefined,'default','silent','chime']) {
    let wire;
    const result=await sdk.sendNotification(f.config,{title:'\u4f60'.repeat(200),body:'\u597d'.repeat(400)}, {sound,fetcher:async(url,init)=>{
      if(url.pathname==='/v2/recipients')return new Response(JSON.stringify(f.directory));
      wire=JSON.parse(init.body);return new Response(JSON.stringify({message_id:wire.message_id,deduplicated:false}));
    }});
    assert.equal(result.message_id,wire.message_id);assert.equal(wire.sound,sound);
    assert.equal(Object.hasOwn(wire,'sound'),sound!==undefined);
    const payload={aps:{alert:{title:'PushNow',body:'You have a new encrypted reminder.'},'mutable-content':1,sound:'pushnow-chime.wav'},
      secure_v2:{message_id:wire.message_id,user_id:f.config.user_id,source_id:f.config.source_id,archive_id:wire.archive_id,
        device_id:f.devices[0].id,...wire.preview,source_public_key:f.directory.source_public_key,
        source_certificate:f.directory.source_certificate,created_at:new Date().toISOString(),read_at:null}};
    assert.ok(Buffer.byteLength(JSON.stringify(payload))<=3900);
  }
});
