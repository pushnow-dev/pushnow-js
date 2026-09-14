export declare const bytes: (value: string) => Uint8Array<ArrayBuffer>;
export declare function base64(value: ArrayBuffer | Uint8Array): string;
export declare function decode(value: unknown, size?: number): Uint8Array<ArrayBuffer>;
export declare function cryptoAPI(): Crypto;
export declare function sha256(data: Uint8Array<ArrayBuffer>): Promise<string>;
export declare const fingerprint: (key: string) => Promise<string>;
export declare function uuid(value: unknown): asserts value is string;
export declare function object(value: unknown): Record<string, unknown>;
