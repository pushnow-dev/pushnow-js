import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import {chromium} from 'playwright';
import {startBackendFixture} from './helpers/backend-fixture.mjs';
import {openV2} from '../../../cli/test/v2-fixtures.js';

test('real Chromium imports browser bundle and sends encrypted file over HTTP to actual D1/R2',{timeout:60000},async()=>{
  const script=await readFile(new URL('../dist/browser.js',import.meta.url));
  const server=createServer((req,res)=>{
    res.setHeader('content-type',req.url==='/sdk.js'?'text/javascript':'text/html');
    res.end(req.url==='/sdk.js'?script:'<!doctype html><title>SDK browser fixture</title>');
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const origin=`http://127.0.0.1:${server.address().port}`;
  let backend,browser;
  try {
    backend=await startBackendFixture({corsOrigins:[origin]});
    browser=await chromium.launch({headless:true});
    const page=await browser.newPage();await page.goto(origin);
    const result=await page.evaluate(async({config,session})=>{
      const sdk=await import('/sdk.js');
      if(typeof globalThis.Buffer!=='undefined'||typeof globalThis.process!=='undefined')throw new Error('Unexpected Node globals');
      const me=await fetch(`${config.api_url}/v1/me`,{headers:{authorization:`Bearer ${session.accessToken}`}}).then(r=>r.json());
      if(me.user.id!==config.user_id)throw new Error('Wrong account');
      const events=[];
      const result=await sdk.sendNotification(sdk.validateConfig(config),{title:'Browser secret',body:'Browser body',
        files:[{data:new Blob(['Browser private file']),name:'browser.txt',mime:'text/plain'}]},
        {inboxOnly:true,onRequest:event=>events.push(event)});
      const pending=await sdk.beginLogin(config.api_url,'Browser authorization');
      return {result,events,publicKey:pending.key.publicKey,fingerprint:pending.fingerprint};
    },{config:backend.config,session:backend.session});
    assert.equal(result.publicKey.length,88);assert.equal(result.fingerprint.length,64);
    const message=await backend.db.prepare('SELECT * FROM v2_messages WHERE id=?').bind(result.result.message_id).first();
    const clear=await openV2(backend.fixture,{...message,message_id:message.id});
    assert.equal(clear.title,'Browser secret');assert.equal(clear.attachments[0].name,'browser.txt');
    assert.equal(result.events.filter(e=>e.outcome==='success').length,4);
    assert.ok(!JSON.stringify(result.events).includes(backend.config.source_key));
  } finally {
    await browser?.close();await backend?.close();await new Promise(resolve=>server.close(resolve));
  }
});
