import {validateAPIURL, validateConfig} from './config.js';
import {generateAgreementKey, openSenderGrant, senderPublicKey, verifyArchive} from './crypto.js';
import {fingerprint, object, uuid} from './encoding.js';
import {APIError, request} from './http.js';
import {recipientsV2} from './recipients.js';
import type {AuthorizedConfig, Envelope, PendingAccountLogin, RequestOptions} from './types.js';

async function wait(ms: number, signal?: AbortSignal): Promise<void> {
  signal?.throwIfAborted();
  await new Promise<void>((resolve, reject) => {
    const abort = () => {clearTimeout(timer); signal?.removeEventListener('abort', abort); reject(new DOMException('Login aborted', 'AbortError'));};
    const timer = setTimeout(() => {signal?.removeEventListener('abort', abort); resolve();}, ms);
    signal?.addEventListener('abort', abort, {once: true});
    if (signal?.aborted) abort();
  });
}

async function finishApprovedAccountLogin(input: PendingAccountLogin, options: RequestOptions = {}): Promise<AuthorizedConfig> {
  const expected = input.expectedIdentityFingerprint.toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(expected)) throw new Error('Expected identity fingerprint must be 64 hexadecimal characters');
  const pending = structuredClone(input), {authorization, key} = pending;
  const api_url = validateAPIURL(pending.api_url);
  if (await senderPublicKey(key.privateKey) !== key.publicKey) throw new Error('Pending authorization key mismatch');
  uuid(authorization.id);
  while (Date.now() < Date.parse(authorization.expires_at)) {
    options.signal?.throwIfAborted();
    let response: Record<string, unknown> | undefined;
    try {response = object(await request(api_url, `/v2/authorizations/${encodeURIComponent(authorization.id)}/token`,
      {...options, method: 'POST', body: {device_code: authorization.device_code}}));}
    catch (error) {if (!(error instanceof APIError) || error.status !== 429) throw error;}
    if (response?.status === 'approved') {
      const grant = object(await openSenderGrant(pending, object(response.grant) as unknown as Envelope));
      const config = validateConfig({...grant, sender_private_key: key.privateKey});
      if (config.api_url !== api_url) throw new Error('Authorization API origin changed');
      await verifyArchive(config, config.archive);
      const accountFingerprint = await fingerprint(config.identity_public_key);
      if (expected !== accountFingerprint) throw new Error('Account identity not confirmed; discard this authorization');
      // The grant must bind this local private key to the claimed account/source before returning it.
      await recipientsV2(config, options);
      return config;
    }
    if (response && response.status !== 'pending') throw new Error('Unexpected authorization state');
    const remaining = Date.parse(authorization.expires_at) - Date.now();
    if (remaining > 0) await wait(Math.min(remaining, Math.max(3, Number(authorization.interval) || 3) * 1000), options.signal);
  }
  throw new Error('Authorization expired; start login again');
}

export async function beginAccountLogin(apiURL: string, accessToken: string, name: string, options: RequestOptions = {}): Promise<PendingAccountLogin> {
  if (!name.trim() || name.trim().length > 80) throw new Error('Invalid sender name');
  const api_url = validateAPIURL(apiURL), key = await generateAgreementKey();
  const value = object(await request(api_url, '/v2/account-authorizations', {...options, token: accessToken, method: 'POST', body: {name: name.trim(), public_key: key.publicKey}}));
  uuid(value.id); uuid(value.user_id);
  if (typeof value.device_code !== 'string' || typeof value.user_code !== 'string' || typeof value.expires_at !== 'string' || !Number.isFinite(Date.parse(value.expires_at)) || Date.parse(value.expires_at) <= Date.now() || typeof value.identity_public_key !== 'string') throw new Error('Invalid account authorization');
  return {api_url, key, authorization: {id: value.id, device_code: value.device_code, user_code: value.user_code, expires_at: value.expires_at, interval: 3}, fingerprint: await fingerprint(key.publicKey), accountUserID: value.user_id, expectedIdentityFingerprint: await fingerprint(value.identity_public_key)};
}

export async function finishAccountLogin(input: PendingAccountLogin, options: RequestOptions = {}): Promise<AuthorizedConfig> {
  const config = await finishApprovedAccountLogin(input, options);
  if (config.user_id !== input.accountUserID) throw new Error('Authorization account changed');
  return config;
}
