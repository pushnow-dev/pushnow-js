import type { Archive, AuthorizedConfig } from './types.js';
export declare function validateAPIURL(value: string): string;
export declare function validateArchive(value: unknown): Archive;
/** Structural validation only. finishLogin pins identity; recipientsV2 verifies signed bindings. */
export declare function validateConfig(value: unknown): AuthorizedConfig;
