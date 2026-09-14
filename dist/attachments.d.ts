import type { AttachmentData, AttachmentDescriptor, AttachmentMetadata, AuthorizedConfig, RequestOptions } from './types.js';
export declare const maxAttachmentSize: number;
export declare function validateAttachmentMetadata(metadata: AttachmentMetadata): AttachmentMetadata;
export declare function validateAttachmentData(data: AttachmentData): void;
export declare function validateDescriptor(value: unknown): AttachmentDescriptor;
export declare function uploadAttachment(input: AuthorizedConfig, data: AttachmentData, metadata: AttachmentMetadata, options?: RequestOptions): Promise<AttachmentDescriptor>;
