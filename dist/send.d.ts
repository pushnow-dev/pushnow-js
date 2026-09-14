import type { AuthorizedConfig, NotificationInput, SendOptions, SubmitResult } from './types.js';
export declare function sendNotification(input: AuthorizedConfig, notification: NotificationInput, inputOptions?: SendOptions): Promise<SubmitResult>;
