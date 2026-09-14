import type { AuthorizedConfig, MessageContent, MessageOptions, PreparedMessage, RecipientDirectory, RequestOptions, SubmitResult } from './types.js';
export declare function validateContent(input: MessageContent): Required<Pick<MessageContent, 'title' | 'body' | 'links' | 'attachments'>> & MessageContent;
export declare function validateMessageOptions(options: MessageOptions): MessageOptions;
export declare function prepareMessageV2(input: AuthorizedConfig, inputDirectory: RecipientDirectory, plaintext: MessageContent, inputOptions?: MessageOptions): Promise<PreparedMessage>;
export declare function submitMessageV2(input: AuthorizedConfig, message: PreparedMessage, options?: RequestOptions): Promise<SubmitResult>;
