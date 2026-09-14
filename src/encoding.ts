export const bytes = (value: string): Uint8Array<ArrayBuffer> => new TextEncoder().encode(value);
export function base64(value: ArrayBuffer | Uint8Array): string {
  const data = value instanceof Uint8Array ? value : new Uint8Array(value);
  let result = '';
  for (let start = 0; start < data.length; start += 8192) result += String.fromCharCode(...data.subarray(start, start + 8192));
  return btoa(result);
}
export function decode(value: unknown, size?: number): Uint8Array<ArrayBuffer> {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new Error('Invalid Base64 encoding');
  const decoded = Uint8Array.from(atob(value), c => c.charCodeAt(0));
  if ((size !== undefined && decoded.length !== size) || base64(decoded) !== value) throw new Error('Invalid key or encoding');
  return decoded;
}
export function cryptoAPI(): Crypto {
  if (!globalThis.crypto?.subtle) throw new Error('WebCrypto is required; use a secure HTTPS context');
  return globalThis.crypto;
}
export async function sha256(data: Uint8Array<ArrayBuffer>): Promise<string> {
  return [...new Uint8Array(await cryptoAPI().subtle.digest('SHA-256', data))].map(n => n.toString(16).padStart(2, '0')).join('');
}
export const fingerprint = (key: string): Promise<string> => sha256(decode(key, 65));
export function uuid(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) throw new Error('Invalid UUID');
}
export function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Expected an object');
  return value as Record<string, unknown>;
}
