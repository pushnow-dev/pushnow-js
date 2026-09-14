import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {readFile,readdir} from 'node:fs/promises';
import {createHash,randomUUID} from 'node:crypto';
import {fixtureV2} from '../../../../cli/test/v2-fixtures.js';

/** Disposable actual Worker/D1/R2, seeded with test-only signed identities. No production calls. */
export async function startBackendFixture({corsOrigins=['http://localhost:4321','http://127.0.0.1:4321']}={}) {
  const root=fileURLToPath(new URL('../../../../',import.meta.url)), backend=`${root}backend/`;
  const require=createRequire(`${backend}package.json`);
  const {Miniflare,convertV4MiniflareOptions}=require('miniflare'),{build}=require('esbuild');
  const bundled=await build({entryPoints:[`${backend}src/index.ts`],bundle:true,format:'esm',platform:'neutral',external:['cloudflare:*'],write:false});
  const pepper='sdk-disposable-test-only',hash=value=>createHash('sha256').update(`${value}.${pepper}`).digest('hex');
  const mf=new Miniflare(convertV4MiniflareOptions({name:`sdk-${randomUUID()}`,host:'127.0.0.1',port:0,modules:true,
    script:bundled.outputFiles[0].text,d1Databases:['DB'],r2Buckets:['SECURE_BLOBS'],compatibilityDate:'2026-09-12',compatibilityFlags:['nodejs_compat'],
    bindings:{AUTH_TOKEN_PEPPER:pepper,APP_BASE_URL:'http://localhost',AUTH_EMAIL_FROM:'sdk@example.com',CORS_ORIGINS:corsOrigins.join(','),
      ACCESS_TOKEN_TTL_SECONDS:'3600',REFRESH_TOKEN_TTL_SECONDS:'2592000',AUTH_CODE_TTL_SECONDS:'600'}}));
  try {
    const db=await mf.getD1Database('DB'),apiURL=(await mf.ready).origin;
    for(const name of (await readdir(`${backend}migrations`)).filter(n=>n.endsWith('.sql')).sort()) {
      for(const sql of (await readFile(`${backend}migrations/${name}`,'utf8')).split(';').map(s=>s.trim()).filter(Boolean)) await db.prepare(sql).run();
    }
    const f=await fixtureV2(),now=new Date().toISOString(),expires=new Date(Date.now()+3600000).toISOString();
    f.config.api_url=apiURL;
    await db.prepare('INSERT INTO users(id,email,email_hash,email_verified_at,created_at,updated_at) VALUES (?,?,?,?,?,?)')
      .bind(f.config.user_id,'sdk-fixture@example.com',hash(f.config.user_id),now,now,now).run();
    await db.prepare('INSERT INTO secure_identities(user_id,public_key,created_at) VALUES (?,?,?)').bind(f.config.user_id,f.config.identity_public_key,now).run();
    const sessions=[];
    for(const device of f.devices) {
      await db.prepare("INSERT INTO secure_devices(id,user_id,name,platform,public_key,certificate,status,notifications_enabled,last_seen_at,created_at,system_version,app_version,model) VALUES (?,?,?,?,?,?,'active',1,?,?,?,?,?)")
        .bind(device.id,device.user_id,device.name,device.platform,device.public_key,device.certificate,now,now,'18.4','1.0.0','iPhone 16 Pro').run();
      const accessToken=`test-${randomUUID()}`;
      await db.prepare('INSERT INTO sessions(id,user_id,access_token_hash,refresh_token_hash,expires_at,refresh_expires_at,created_at,updated_at,device_id) VALUES (?,?,?,?,?,?,?,?,?)')
        .bind(randomUUID(),f.config.user_id,hash(accessToken),hash(randomUUID()),expires,expires,now,now,device.id).run();
      sessions.push({accessToken,userId:f.config.user_id,deviceId:device.id});
    }
    await db.prepare("INSERT INTO sources(id,user_id,name,source_type,default_priority,default_push_enabled,status,created_at,updated_at) VALUES (?,?,'SDK fixture','cli','normal',1,'active',?,?)")
      .bind(f.config.source_id,f.config.user_id,now,now).run();
    const keyID=randomUUID();
    await db.prepare("INSERT INTO source_keys(id,source_id,user_id,key_prefix,key_hash,scopes,created_at,expires_at) VALUES (?,?,?,?,?,'[\"items:write\"]',?,NULL)")
      .bind(keyID,f.config.source_id,f.config.user_id,f.config.source_key.slice(0,18),hash(f.config.source_key),now).run();
    await db.prepare('INSERT INTO secure_sources(source_id,user_id,public_key,certificate) VALUES (?,?,?,?)')
      .bind(f.config.source_id,f.config.user_id,f.sender.publicKey,f.directory.source_certificate).run();
    await db.prepare('INSERT INTO v2_archives(user_id,id,public_key,certificate,created_at) VALUES (?,?,?,?,?)')
      .bind(f.config.user_id,f.config.archive.id,f.config.archive.public_key,f.config.archive.certificate,now).run();
    return {apiURL,config:f.config,session:sessions[0],sessions,keyID,db,fixture:f,fetcher:fetch,close:()=>mf.dispose()};
  } catch(error) {await mf.dispose();throw error;}
}
