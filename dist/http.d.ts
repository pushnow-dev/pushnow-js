import type { AuthorizedConfig, RequestEvent, RequestOptions } from './types.js';
export declare class APIError extends Error {
    readonly status: number;
    constructor(status: number);
}
type HTTPOptions = RequestOptions & {
    token?: string;
    method?: RequestEvent['method'];
    body?: unknown;
    binary?: boolean;
    messageID?: string;
};
export declare function request(apiURL: string, path: string, options?: HTTPOptions): Promise<unknown>;
export declare function authenticated(config: AuthorizedConfig, path: string, options?: Omit<HTTPOptions, 'token'>): Promise<unknown>;
export {};
