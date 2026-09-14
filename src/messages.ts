import {validateConfig} from './config.js';
import {sealV2} from './crypto.js';
import {bytes, cryptoAPI, decode, object, uuid} from './encoding.js';
import {authenticated} from './http.js';
import {validateDescriptor} from './attachments.js';
import {verifyDirectory} from './recipients.js';
import type {AuthorizedConfig, AttachmentDescriptor, Envelope, MessageContent, MessageOptions, PreparedMessage, RecipientDirectory, RequestOptions, SubmitResult} from './types.js';

const bindings = new WeakMap<PreparedMessage, string>();
const binding = (config: AuthorizedConfig) => JSON.stringify([config.api_url, config.user_id, config.source_id, config.identity_public_key, config.sender_private_key, config.archive.id, config.archive.public_key]);
export function validateContent(input: MessageContent): Required<Pick<MessageContent, 'title' | 'body' | 'links' | 'attachments'>> & MessageContent {
  const value = object(input);
  if (Object.keys(value).some(k => !['title', 'body', 'links', 'attachments', 'image_id', 'icon_id'].includes(k))) throw new Error('Unsupported message content field; pass routing fields such as sound in MessageOptions');
  if (typeof value.title !== 'string' || typeof value.body !== 'string') throw new Error('Message needs title and body');
  const links = value.links ?? [], attachments = value.attachments ?? [];
  if (!Array.isArray(links) || links.some(link => typeof link !== 'string') || !Array.isArray(attachments) || attachments.length > 20) throw new Error('Invalid links or attachment count');
  const descriptors = attachments.map(validateDescriptor), ids = new Set(descriptors.map(d => d.id));
  if (ids.size !== descriptors.length) throw new Error('Duplicate attachment');
  for (const id of [value.image_id, value.icon_id]) if (id !== undefined) {uuid(id); if (!ids.has(id)) throw new Error('Image and icon must refer to an attached file');}
  const full = {title: value.title, body: value.body, links: [...links] as string[], attachments: descriptors,
    ...(value.image_id === undefined ? {} : {image_id: value.image_id as string}), ...(value.icon_id === undefined ? {} : {icon_id: value.icon_id as string})};
  if (bytes(JSON.stringify(full)).length + 16 > 256 * 1024) throw new Error('Encrypted message manifest exceeds 256 KiB');
  return full;
}

function timestamp(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string') throw new Error('Invalid ISO timestamp');
  const match = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.(\d{1,3}))?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  if (!match) throw new Error('Invalid ISO timestamp');
  const local = `${match[1]}T${match[2]}.${(match[3] ?? '').padEnd(3, '0')}Z`;
  if (!Number.isFinite(Date.parse(value)) || !Number.isFinite(Date.parse(local)) || new Date(local).toISOString() !== local) throw new Error('Invalid ISO timestamp');
  return new Date(value).toISOString();
}

export function validateMessageOptions(options: MessageOptions): MessageOptions {
  if (options.sound !== undefined && !['default', 'silent', 'chime'].includes(options.sound)) throw new Error('Invalid sound; use default, silent or chime');
  if (options.inboxOnly !== undefined && typeof options.inboxOnly !== 'boolean') throw new Error('inboxOnly must be boolean');
  if (options.inboxOnly && options.deviceIds !== undefined) throw new Error('Choose inboxOnly or deviceIds, not both');
  if (options.deviceIds !== undefined) {
    if (!Array.isArray(options.deviceIds) || options.deviceIds.length > 100) throw new Error('Invalid target count');
    options.deviceIds.forEach(uuid);
    if (new Set(options.deviceIds).size !== options.deviceIds.length) throw new Error('Duplicate target');
  }
  if (options.messageID !== undefined) uuid(options.messageID);
  if(options.sourceKind!==undefined && !["web","cli","api","subscription"].includes(options.sourceKind)) throw new Error("Invalid source kind");
  const scheduledAt = timestamp(options.scheduledAt), expiresAt = timestamp(options.expiresAt), now = Date.now(), end = now + 30 * 86400000;
  if (scheduledAt && (Date.parse(scheduledAt) <= now || Date.parse(scheduledAt) > end)) throw new Error('Schedule must be in the next 30 days');
  if (expiresAt && (Date.parse(expiresAt) <= (scheduledAt ? Date.parse(scheduledAt) : now) || Date.parse(expiresAt) > end)) throw new Error('Expiry must follow delivery and be within 30 days');
  return {...options, deviceIds: options.deviceIds && [...options.deviceIds], scheduledAt, expiresAt};
}
function truncateUTF8(value: string, limit: number): string {
  let result = '', size = 0;
  for (const char of value) {const n = bytes(char).length; if (size + n > limit) break; result += char; size += n;}
  return result;
}

export async function prepareMessageV2(input: AuthorizedConfig, inputDirectory: RecipientDirectory, plaintext: MessageContent, inputOptions: MessageOptions = {}): Promise<PreparedMessage> {
  const config = validateConfig(input), full = validateContent(plaintext), options = validateMessageOptions(inputOptions);
  const directory = await verifyDirectory(config, inputDirectory), messageID = options.messageID ?? cryptoAPI().randomUUID();
  let notify: string[] | undefined;
  if (options.inboxOnly) notify = [];
  else if (options.deviceIds !== undefined) {
    const selected = directory.devices.filter(d => options.deviceIds!.includes(d.id));
    if (selected.length !== options.deviceIds.length) throw new Error('Unknown notification device');
    notify = selected.filter(d => d.notifications_enabled).map(d => d.id);
  }
  const encrypted = await sealV2(config, directory.archive, 'message', messageID, full);
  const previewData: {title: string; body: string; image?: AttachmentDescriptor} = {title: truncateUTF8(full.title, 400), body: truncateUTF8(full.body, 700)};
  const image = full.attachments.find(a => a.id === full.image_id);
  if (image && bytes(JSON.stringify(image)).length <= 600) previewData.image = image;
  // Budget for the longest supported APNs filename, including legacy/default requests.
  const previewSize = (envelope: Envelope) => bytes(JSON.stringify({aps: {alert: {title: 'PushNow', body: 'You have a new encrypted reminder.'}, 'mutable-content': 1, sound: 'pushnow-chime.wav'},
    secure_v2: {message_id: messageID, user_id: config.user_id, source_id: config.source_id, archive_id: directory.archive.id,
      device_id: '00000000-0000-0000-0000-000000000000', ...envelope, source_public_key: directory.source_public_key,
      source_certificate: directory.source_certificate, created_at: new Date().toISOString(), read_at: null}})).length;
  let preview = await sealV2(config, directory.archive, 'preview', messageID, previewData);
  if (previewSize(preview) > 3900 || decode(preview.ciphertext).length > 2400) {
    delete previewData.image; preview = await sealV2(config, directory.archive, 'preview', messageID, previewData);
  }
  if (previewSize(preview) > 3900 || decode(preview.ciphertext).length > 2400) throw new Error('Encrypted preview is too large');
  const message: PreparedMessage = {message_id: messageID, archive_id: directory.archive.id, ...encrypted, preview,
    attachment_ids: full.attachments.map(a => a.id), ...(notify === undefined ? {} : {notify_device_ids: notify}),
    ...(options.sourceKind === undefined ? {} : {source_kind: options.sourceKind}),
    ...(options.scheduledAt === undefined ? {} : {scheduled_at: options.scheduledAt}), ...(options.expiresAt === undefined ? {} : {expires_at: options.expiresAt}),
    ...(options.sound === undefined ? {} : {sound: options.sound})};
  Object.freeze(message.preview); Object.freeze(message.attachment_ids); if (message.notify_device_ids) Object.freeze(message.notify_device_ids); Object.freeze(message);
  bindings.set(message, binding(config)); return message;
}

export async function submitMessageV2(input: AuthorizedConfig, message: PreparedMessage, options: RequestOptions = {}): Promise<SubmitResult> {
  const config = validateConfig(input);
  if (bindings.get(message) !== binding(config)) throw new Error('Use the original prepared message with its authorized account and source');
  const result = object(await authenticated(config, '/v2/messages', {...options, method: 'POST', messageID: message.message_id, body: message}));
  if (result.message_id !== message.message_id || typeof result.deduplicated !== 'boolean') throw new Error('Invalid message response');
  return {message_id: result.message_id, deduplicated: result.deduplicated};
}
