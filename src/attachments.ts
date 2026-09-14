import {validateConfig} from './config.js';
import {base64, bytes, cryptoAPI, decode, object, sha256, uuid} from './encoding.js';
import {authenticated} from './http.js';
import type {AttachmentData, AttachmentDescriptor, AttachmentMetadata, AuthorizedConfig, RequestOptions} from './types.js';

export const maxAttachmentSize = 20 * 1024 * 1024 - 16;
export function validateAttachmentMetadata(metadata: AttachmentMetadata): AttachmentMetadata {
  if (!metadata || typeof metadata.name !== 'string' || !metadata.name.trim() || metadata.name.length > 255 || /[\x00-\x1f]/.test(metadata.name)) throw new Error('Invalid attachment name');
  if (metadata.mime !== undefined && (typeof metadata.mime !== 'string' || !/^[\w!#$&^.+-]+\/[\w!#$&^.+-]+(?:;[^\r\n]*)?$/.test(metadata.mime) || metadata.mime.length > 255)) throw new Error('Invalid attachment MIME type');
  if (metadata.id !== undefined) uuid(metadata.id);
  return {...metadata};
}
export function validateAttachmentData(data: AttachmentData): void {
  const size = typeof Blob !== 'undefined' && data instanceof Blob ? data.size :
    data instanceof Uint8Array || data instanceof ArrayBuffer ? data.byteLength : NaN;
  if (!Number.isFinite(size)) throw new Error('Attachment must be a Blob, Uint8Array or ArrayBuffer');
  if (size > maxAttachmentSize) throw new Error('Attachment exceeds the 20 MiB encrypted size limit');
}
export function validateDescriptor(value: unknown): AttachmentDescriptor {
  const d = object(value); uuid(d.id);
  validateAttachmentMetadata({id: d.id, name: d.name as string, mime: d.mime as string});
  if (typeof d.mime !== 'string' || !Number.isSafeInteger(d.size) || (d.size as number) < 0 || (d.size as number) > maxAttachmentSize ||
    typeof d.read_token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(d.read_token) || typeof d.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(d.sha256)) throw new Error('Invalid attachment descriptor');
  decode(d.key, 32); decode(d.nonce, 12);
  return {id: d.id, name: d.name as string, mime: d.mime, size: d.size as number, read_token: d.read_token,
    key: d.key as string, nonce: d.nonce as string, sha256: d.sha256};
}

export async function uploadAttachment(input: AuthorizedConfig, data: AttachmentData, metadata: AttachmentMetadata, options: RequestOptions = {}): Promise<AttachmentDescriptor> {
  const config = validateConfig(input), meta = validateAttachmentMetadata(metadata);
  validateAttachmentData(data); options.signal?.throwIfAborted();
  const clear = typeof Blob !== 'undefined' && data instanceof Blob ? new Uint8Array(await data.arrayBuffer()) :
    data instanceof Uint8Array ? new Uint8Array(data) : new Uint8Array((data as ArrayBuffer).slice(0));
  const key = cryptoAPI().getRandomValues(new Uint8Array(32)), nonce = cryptoAPI().getRandomValues(new Uint8Array(12));
  const id = meta.id ?? cryptoAPI().randomUUID();
  try {
    const aes = await cryptoAPI().subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
    const ciphertext = await cryptoAPI().subtle.encrypt({name: 'AES-GCM', iv: nonce,
      additionalData: bytes(JSON.stringify([2, 'attachment', config.user_id, config.source_id, id]))}, aes, clear);
    const descriptor: AttachmentDescriptor = {id, name: meta.name, mime: meta.mime ?? 'application/octet-stream', size: clear.length,
      read_token: base64(cryptoAPI().getRandomValues(new Uint8Array(32))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
      key: base64(key), nonce: base64(nonce), sha256: await sha256(clear)};
    await authenticated(config, '/v2/attachments', {...options, method: 'POST', body: {id, size: ciphertext.byteLength, read_token: descriptor.read_token}});
    await authenticated(config, `/v2/attachments/${id}`, {...options, method: 'PUT', binary: true, body: ciphertext});
    return descriptor;
  } finally {key.fill(0); clear.fill(0);}
}
