export interface Archive {
    id: string;
    public_key: string;
    certificate: string;
}
/** Secret-bearing authorization. Never log or put this in a URL. */
export interface AuthorizedConfig {
    api_url: string;
    user_id: string;
    source_id: string;
    source_key: string;
    identity_public_key: string;
    sender_private_key: string;
    archive: Archive;
}
export interface PendingLogin {
    api_url: string;
    key: {
        privateKey: string;
        publicKey: string;
    };
    authorization: {
        id: string;
        device_code: string;
        user_code: string;
        expires_at: string;
        interval: number;
    };
    /** Sender fingerprint for comparison on the approving device, not the account fingerprint. */
    fingerprint: string;
}
export interface RequestEvent {
    method: 'GET' | 'POST' | 'PUT';
    /** Endpoint template only; identifiers, query strings and API credentials are omitted. */
    path: string;
    status: number | null;
    durationMs: number;
    outcome: 'success' | 'http_error' | 'network_error' | 'aborted';
}
export interface RequestOptions {
    signal?: AbortSignal;
    fetcher?: typeof fetch;
    onRequest?: (event: Readonly<RequestEvent>) => void | Promise<void>;
}
export type IdentityVerification = {
    expectedIdentityFingerprint: string;
    confirmIdentity?: never;
} | {
    expectedIdentityFingerprint?: never;
    confirmIdentity: (identity: {
        fingerprint: string;
        userID: string;
    }) => boolean | Promise<boolean>;
};
export type FinishLoginOptions = RequestOptions & IdentityVerification;
export interface RecipientDevice {
    id: string;
    user_id: string;
    name: string;
    platform: string;
    public_key: string;
    certificate: string;
    status: 'active';
    notifications_enabled: boolean;
    system_version?: string | null;
    app_version?: string | null;
    model?: string | null;
}
export interface RecipientDirectory {
    user_id: string;
    source_id: string;
    identity_public_key: string;
    source_public_key: string;
    source_certificate: string;
    archive: Archive;
    devices: RecipientDevice[];
}
export interface AttachmentDescriptor {
    id: string;
    name: string;
    mime: string;
    size: number;
    read_token: string;
    key: string;
    nonce: string;
    sha256: string;
}
export type AttachmentData = Blob | Uint8Array | ArrayBuffer;
export interface AttachmentMetadata {
    name: string;
    mime?: string;
    id?: string;
}
export interface UploadFile extends AttachmentMetadata {
    data: AttachmentData;
}
export interface MessageContent {
    title: string;
    body: string;
    links?: string[];
    attachments?: AttachmentDescriptor[];
    image_id?: string;
    icon_id?: string;
}
export type NotificationSound = 'default' | 'silent' | 'chime';
export interface MessageOptions {
    /** Public routing metadata; omitted keeps legacy default behavior. */
    sound?: NotificationSound;
    deviceIds?: string[];
    inboxOnly?: boolean;
    scheduledAt?: string;
    expiresAt?: string;
    sourceKind?: "web" | "cli" | "api" | "subscription";
    messageID?: string;
}
export interface NotificationInput extends MessageContent {
    files?: UploadFile[];
    image?: UploadFile;
    icon?: UploadFile;
}
export type SendOptions = MessageOptions & RequestOptions;
export interface Envelope {
    enc: string;
    ciphertext: string;
}
/** Keep this exact object for idempotent retries. Preparing again creates fresh ciphertext. */
export interface PreparedMessage extends Envelope {
    source_kind?: "web" | "cli" | "api" | "subscription";
    sound?: NotificationSound;
    message_id: string;
    archive_id: string;
    preview: Envelope;
    attachment_ids: string[];
    notify_device_ids?: string[];
    scheduled_at?: string;
    expires_at?: string;
}
export interface SubmitResult {
    message_id: string;
    deduplicated: boolean;
}
export interface PendingAccountLogin extends PendingLogin {
    accountUserID: string;
    expectedIdentityFingerprint: string;
}
