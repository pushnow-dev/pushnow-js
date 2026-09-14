import type { AuthorizedConfig, FinishLoginOptions, PendingLogin, PendingAccountLogin, RequestOptions } from './types.js';
export declare function beginLogin(apiURL: string, name: string, options?: RequestOptions): Promise<PendingLogin>;
export declare function finishLogin(input: PendingLogin, options: FinishLoginOptions): Promise<AuthorizedConfig>;
/** Account login delegates initial approval to an online trusted device. */
export declare function beginAccountLogin(apiURL: string, accessToken: string, name: string, options?: RequestOptions): Promise<PendingAccountLogin>;
export declare function finishAccountLogin(input: PendingAccountLogin, options?: RequestOptions): Promise<AuthorizedConfig>;
