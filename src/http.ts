import {validateAPIURL, validateConfig} from './config.js';
import type {AuthorizedConfig, RequestEvent, RequestOptions} from './types.js';

export class APIError extends Error {
  constructor(public readonly status: number) {super(`PushNow API request failed (HTTP ${status})`); this.name = 'APIError';}
}
type HTTPOptions = RequestOptions & {token?: string; method?: RequestEvent['method']; body?: unknown; binary?: boolean; messageID?: string};

function pathTemplate(path: string): string {
  return path.replace(/\/authorizations\/[^/]+\/token$/, '/authorizations/:id/token').replace(/\/attachments\/[^/]+$/, '/attachments/:id');
}
async function json(response: Response): Promise<unknown> {
  if (!response.body) throw new Error('Missing API response');
  const reader = response.body.getReader(), chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.length;
      if (size > 2 * 1024 * 1024) {await reader.cancel(); throw new Error('API response is too large');}
      chunks.push(part.value);
    }
  } finally {reader.releaseLock();}
  const data = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) {data.set(chunk, offset); offset += chunk.length;}
  try {return JSON.parse(new TextDecoder().decode(data));}
  catch {throw new Error('Invalid API JSON response');}
}

export async function request(apiURL: string, path: string, options: HTTPOptions = {}): Promise<unknown> {
  const origin = validateAPIURL(apiURL), method = options.method ?? 'GET';
  const started = Date.now(), controller = new AbortController();
  let status: number | null = null, outcome: RequestEvent['outcome'] = 'network_error';
  const abort = () => controller.abort();
  options.signal?.addEventListener('abort', abort, {once: true});
  if (options.signal?.aborted) controller.abort();
  const timer = setTimeout(abort, 30000);
  try {
    controller.signal.throwIfAborted();
    const headers: Record<string, string> = {};
    if (options.token) headers.authorization = `Bearer ${options.token}`;
    if (options.body !== undefined) headers['content-type'] = options.binary ? 'application/octet-stream' : 'application/json';
    if (options.messageID) headers['idempotency-key'] = options.messageID;
    const response = await (options.fetcher ?? fetch)(new URL(path, origin), {method, headers, redirect: 'error',
      credentials: 'omit', cache: 'no-store', signal: controller.signal,
      ...(options.body === undefined ? {} : {body: options.binary ? options.body as BodyInit : JSON.stringify(options.body)})});
    status = response.status;
    if (!response.ok) {outcome = 'http_error'; await response.body?.cancel(); throw new APIError(status);}
    const result = status === 204 ? null : await json(response);
    outcome = 'success'; return result;
  } catch (error) {
    if (controller.signal.aborted) {outcome = 'aborted'; throw new DOMException('Request aborted or timed out', 'AbortError');}
    if (error instanceof APIError) throw error;
    // Fetch/JSON error messages can include URLs or response data. Do not forward them.
    throw new Error('PushNow request failed or returned an invalid response');
  } finally {
    clearTimeout(timer); options.signal?.removeEventListener('abort', abort);
    try {void Promise.resolve(options.onRequest?.(Object.freeze({method, path: pathTemplate(path), status,
      durationMs: Math.max(0, Date.now() - started), outcome}))).catch(() => {});} catch {/* Observability must not change delivery. */}
  }
}

export function authenticated(config: AuthorizedConfig, path: string, options: Omit<HTTPOptions, 'token'> = {}): Promise<unknown> {
  const validated = validateConfig(config);
  return request(validated.api_url, path, {...options, token: validated.source_key});
}
