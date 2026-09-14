import {validateConfig} from './config.js';
import {senderPublicKey, verifyArchive, verifyCertificate} from './crypto.js';
import {object, uuid} from './encoding.js';
import {authenticated} from './http.js';
import type {AuthorizedConfig, RecipientDirectory, RequestOptions} from './types.js';

export async function verifyDirectory(input: AuthorizedConfig, value: unknown): Promise<RecipientDirectory> {
  const config = validateConfig(input), directory = object(structuredClone(value));
  if (directory.user_id !== config.user_id || directory.source_id !== config.source_id || directory.identity_public_key !== config.identity_public_key) throw new Error('Account or source identity changed');
  if (typeof directory.source_public_key !== 'string' || typeof directory.source_certificate !== 'string' ||
    !await verifyCertificate(config.identity_public_key, 'source', config.user_id, config.source_id, directory.source_public_key, directory.source_certificate)) throw new Error('Invalid source certificate');
  if (await senderPublicKey(config.sender_private_key) !== directory.source_public_key) throw new Error('Sender key does not match source');
  await verifyArchive(config, directory.archive);
  if (!Array.isArray(directory.devices) || directory.devices.length > 1000) throw new Error('Invalid device directory');
  const ids = new Set<string>();
  for (const value of directory.devices) {
    const d = object(value); uuid(d.id);
    if (ids.has(d.id) || d.user_id !== config.user_id || d.status !== 'active' || typeof d.notifications_enabled !== 'boolean' ||
      typeof d.name !== 'string' || typeof d.platform !== 'string' || typeof d.public_key !== 'string' || typeof d.certificate !== 'string' ||
      !await verifyCertificate(config.identity_public_key, 'device', config.user_id, d.id, d.public_key, d.certificate)) throw new Error('Invalid device certificate or metadata');
    ids.add(d.id);
  }
  return directory as unknown as RecipientDirectory;
}

export async function recipientsV2(input: AuthorizedConfig, options: RequestOptions = {}): Promise<RecipientDirectory> {
  const config = validateConfig(input);
  return verifyDirectory(config, await authenticated(config, '/v2/recipients', options));
}
