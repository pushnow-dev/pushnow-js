import {Aes256Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256} from '@hpke/core';
import {base64, bytes, cryptoAPI, decode} from './encoding.js';
import {validateArchive} from './config.js';
import type {Archive, AuthorizedConfig, Envelope, PendingAccountLogin} from './types.js';

export const suite = new CipherSuite({kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm()});
export const v2AAD = (purpose: string, config: AuthorizedConfig, messageID: string, archiveID: string) =>
  bytes(JSON.stringify([2, purpose, config.user_id, config.source_id, messageID, archiveID]));

export async function generateAgreementKey(): Promise<PendingAccountLogin['key']> {
  cryptoAPI();
  const pair = await suite.kem.generateKeyPair();
  return {privateKey: base64(await suite.kem.serializePrivateKey(pair.privateKey)), publicKey: base64(await suite.kem.serializePublicKey(pair.publicKey))};
}

export async function senderPublicKey(privateKey: string): Promise<string> {
  const key = await suite.kem.deserializePrivateKey(decode(privateKey, 32));
  const jwk = await cryptoAPI().subtle.exportKey('jwk', key);
  if (!jwk.x || !jwk.y) throw new Error('Sender key cannot be derived');
  const publicJWK = {kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y};
  const pub = await cryptoAPI().subtle.importKey('jwk', publicJWK, {name: 'ECDH', namedCurve: 'P-256'}, true, []);
  return base64(await cryptoAPI().subtle.exportKey('raw', pub));
}

export async function verifyCertificate(root: string, kind: 'source' | 'device' | 'archive', userID: string, id: string, publicKey: string, signature: string): Promise<boolean> {
  try {
    const key = await cryptoAPI().subtle.importKey('raw', decode(root, 65), {name: 'ECDSA', namedCurve: 'P-256'}, false, ['verify']);
    await cryptoAPI().subtle.importKey('raw', decode(publicKey, 65), {name: 'ECDH', namedCurve: 'P-256'}, false, []);
    return await cryptoAPI().subtle.verify({name: 'ECDSA', hash: 'SHA-256'}, key, decode(signature, 64),
      bytes(`pushnow-${kind}-v1\n${userID}\n${id}\n${publicKey}`));
  } catch {return false;}
}

export async function verifyArchive(config: AuthorizedConfig, value: unknown): Promise<Archive> {
  const archive = validateArchive(value);
  if (archive.id !== config.archive.id || archive.public_key !== config.archive.public_key ||
    !await verifyCertificate(config.identity_public_key, 'archive', config.user_id, archive.id, archive.public_key, archive.certificate)) throw new Error('Invalid or changed account archive');
  return archive;
}

export async function sealV2(config: AuthorizedConfig, archive: Archive, purpose: string, messageID: string, plaintext: unknown): Promise<Envelope> {
  cryptoAPI();
  const sender = await suite.createSenderContext({recipientPublicKey: await suite.kem.deserializePublicKey(decode(archive.public_key, 65)),
    senderKey: await suite.kem.deserializePrivateKey(decode(config.sender_private_key, 32)), info: bytes('pushnow-v2')});
  return {enc: base64(sender.enc), ciphertext: base64(await sender.seal(bytes(JSON.stringify(plaintext)), v2AAD(purpose, config, messageID, archive.id)))};
}

export async function openSenderGrant(pending: PendingAccountLogin, grant: Envelope): Promise<unknown> {
  const ciphertext = decode(grant.ciphertext);
  if (ciphertext.length > 8192 || ciphertext.length < 16) throw new Error('Invalid authorization grant size');
  const recipient = await suite.createRecipientContext({recipientKey: await suite.kem.deserializePrivateKey(decode(pending.key.privateKey, 32)),
    enc: decode(grant.enc, 65), info: bytes('pushnow-sender-grant-v2')});
  const plaintext = new Uint8Array(await recipient.open(ciphertext, bytes(JSON.stringify([2, 'sender-grant', pending.authorization.id, pending.key.publicKey]))));
  try {return JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(plaintext));}
  catch {throw new Error('Invalid authorization grant');}
  finally {plaintext.fill(0);}
}
