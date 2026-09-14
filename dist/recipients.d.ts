import type { AuthorizedConfig, RecipientDirectory, RequestOptions } from './types.js';
export declare function verifyDirectory(input: AuthorizedConfig, value: unknown): Promise<RecipientDirectory>;
export declare function recipientsV2(input: AuthorizedConfig, options?: RequestOptions): Promise<RecipientDirectory>;
