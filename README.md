# PushNow TypeScript SDK

Browser-compatible SDK for the existing PushNow v2 encrypted API. Uses
`@hpke/core` 1.9.0 (P-256 / HKDF-SHA256 / AES-256-GCM) and native WebCrypto.
No Node polyfills, persistence, analytics, or automatic publication.

## Local Package

```sh
cd sdk/typescript
npm ci
npm run build
npm pack
```

Install the resulting `pushnow-sdk-0.1.0.tgz` into a consuming project, or use
a local `file:` dependency. Package name: `@pushnow/sdk`. This folder and its
tarball are ready for the owner's upload; no registry publication is performed.

The ESM entry `dist/index.js` includes TypeScript declarations. For an unbundled
browser, serve `dist/browser.js` and import it as an ES module. It includes the
HPKE dependency and needs no import map. A bundler can use `@pushnow/sdk` directly;
`@pushnow/sdk/browser` selects the standalone bundle. There is no CommonJS entry.
Use HTTPS, or loopback HTTP for development, in a runtime with `crypto.subtle`,
`fetch`, `AbortController`, and `structuredClone` (modern browsers or Node 22+).

## Authorize Once

First register, verify email and sign in to the App. Its encrypted account
archive and approving device must already be initialized. SDK sender approval
is separate from email/password login; the SDK does not implement account login.

```ts
import {beginLogin, finishLogin} from '@pushnow/sdk';

const controller = new AbortController();
const pending = await beginLogin('https://api.pushnow.dev', 'My automation', {
  signal: controller.signal,
});
// Display pending.authorization.user_code and pending.fingerprint.
// The user approves this sender in the signed-in App.
// Obtain the ACCOUNT identity fingerprint from that trusted App separately.
const config = await finishLogin(pending, {
  expectedIdentityFingerprint: trustedAccountFingerprint,
  signal: controller.signal,
});
```

`pending.fingerprint` identifies the new sender. It is NOT the account identity
fingerprint. `expectedIdentityFingerprint` must be the independently verified
64-character SHA-256 hex fingerprint of the account identity public key. Never
compute the expected value from the same untrusted grant and auto-accept it.
Alternatively, supply `confirmIdentity: async ({fingerprint, userID}) => boolean`
and require explicit user comparison with their trusted device. These options
are mutually exclusive. Missing verification or a mismatch fails closed.

Polling respects the server interval and handles HTTP 429; aborting cancels
both polling requests and waiting. Authorization grants are single-use. If a
grant is consumed but validation or a subsequent directory request fails, start
a fresh authorization. `finishLogin` checks origin, archive certificate,
account fingerprint, source certificate, sender private/public key match and
device certificates before returning the config.

## Config and Account Binding

`AuthorizedConfig` uses the CLI-compatible fields:

```ts
type AuthorizedConfig = {
  api_url: string;
  user_id: string;
  source_id: string;
  source_key: string;
  identity_public_key: string;
  sender_private_key: string;
  archive: {id: string; public_key: string; certificate: string};
};
```

A bearer token alone cannot encrypt messages. It authorizes HTTP requests but
does not contain the authenticated sender private key, pinned account identity
or certified archive public key. Only the receiving account devices have the
archive private key used to decrypt messages.

`validateConfig(input)` synchronously checks structure and returns a clean copy;
it does not prove ownership or independently confirm identity. For a signed-in
Web dashboard importing a trusted config, keep it in memory, check
`config.user_id === me.user.id` and `config.api_url === expectedAPIOrigin`, then
call `recipientsV2(config)`. Replacing `source_key` is supported, but a token for
another source/account fails directory binding checks. Never embed config in a
public JS bundle, URL, log, or plaintext persistent browser storage. Clear all
references on account logout/change. JavaScript cannot guarantee erasure of
strings or protect secrets from scripts running in the same page.

## Send

```ts
import {sendNotification} from '@pushnow/sdk';

const result = await sendNotification(config, {
  title: 'Build completed',
  body: 'Version 1.2 is ready.',
  links: ['https://example.com/build/42'],
  files: [{data: new Blob(['build output']), name: 'build.txt', mime: 'text/plain'}],
  // image: {data: imageFile, name: imageFile.name, mime: imageFile.type},
  // icon: {data: iconFile, name: iconFile.name, mime: iconFile.type},
}, {
  // deviceIds: [selectedDeviceID], // omitted: all notification-enabled devices
  // inboxOnly: true,              // account inbox only; no APNs request
  // sound: 'chime',               // 'default' | 'silent' | 'chime'
  // scheduledAt: new Date(Date.now() + 60_000).toISOString(),
  // expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
});
```

`files`, `image`, `icon` accept `{data: Blob | Uint8Array | ArrayBuffer, name,
mime?, id?}`. The SDK uploads AES-GCM ciphertext and embeds attachment descriptors
inside the encrypted message. Names, MIME types, keys and clear content are not
sent as plaintext metadata. The server sees attachment IDs, encrypted byte counts
and read capabilities, plus routing/schedule metadata. It does not receive
message text, filenames, or file encryption keys in plaintext.

`MessageContent` supports `title`, `body`, `links`, `attachments`, `image_id`,
`icon_id`. The last two refer to entries in `attachments`. High-level `image`
and `icon` upload files and set these IDs automatically. Maximum 20 attachments;
each encrypted file is at most 20 MiB, so plaintext is at most 20 MiB minus
16 bytes. Full encrypted manifests are limited to 256 KiB. Preview text is
UTF-8 bounded; a preview image is omitted when its descriptor cannot fit.

`deviceIds: []` and `inboxOnly: true` both suppress notifications. Do not combine
`inboxOnly: true` with `deviceIds`. Explicit targets must belong to the account;
disabled devices are filtered. Inbox/history remains account-wide even when
only one device is notified. Sending to a single device does not make content
private from the other account devices.

Schedules must be future ISO timestamps within 30 days. An expiry must follow
the delivery time and be within 30 days. Offset timestamps are normalized to UTC.
`MessageOptions.sound` accepts `'default'`, `'silent'`, or `'chime'`. It is public
routing metadata on the prepared request, like `scheduled_at`, and is not part
of the encrypted content. Omit it to preserve the legacy wire and default sound
behavior. Invalid values are rejected before any HTTP request or file upload.
`'silent'` omits APNs `aps.sound`; it does not suppress the visible notification
(use `inboxOnly` for that). `'chime'` selects `pushnow-chime.wav`, bundled in the
new App version; an older App without the file falls back to the default sound.
Playback remains subject to iOS notification/sound permissions and Focus/Do Not
Disturb settings. Interruption levels and critical alerts are not supported.
Successful API acceptance is not proof of device-visible delivery or audible sound.

## Low-Level Flow and Retries

```ts
import {recipientsV2, uploadAttachment, prepareMessageV2, submitMessageV2} from '@pushnow/sdk';

const directory = await recipientsV2(config);
const attachment = await uploadAttachment(config, file, {name: file.name});
const prepared = await prepareMessageV2(config, directory, {
  title: 'Report', body: 'Attached.', attachments: [attachment],
}, {deviceIds: [directory.devices[0].id]});
const result = await submitMessageV2(config, prepared);
// For an uncertain HTTP result, retry submitMessageV2(config, prepared).
```

Preparation revalidates the entire directory, including account/source/private
key binding, even if callers provide the directory themselves. It returns an
immutable object with an in-memory account/source binding. Submission rejects a
different account/source or a serialized/cloned object that lost that binding.
Keep the original object for retries: retries send the exact original request
bytes, including the selected sound or its omission. Do not change its sound or
prepare again with the same message ID: fresh encryption yields different
ciphertext and an idempotency conflict.
Durable serialized outbox import is not provided by this SDK version.

The high-level helper performs no automatic send retries. Use the low-level
flow when you need to control retries. Cancelled/failed uploads may leave
reserved or uploaded orphan blobs for the backend's existing cleanup process.

## Request Options and Redacted Logging

Every HTTP-producing export accepts `RequestOptions` as its final argument:

```ts
const options = {
  signal: controller.signal,
  fetcher: fetch,
  onRequest(event) {
    // {method, path, status, durationMs, outcome}
    // path is e.g. /v2/attachments/:id, not a URL containing identifiers.
    requestEvents.push(event);
  },
};
```

`prepareMessageV2` is local-only and accepts `MessageOptions` instead.
`sendNotification` accepts the intersection of both option types. Logging fires
once per HTTP attempt and contains no headers, payloads, tokens, keys or raw
server errors. Throwing/rejecting logging callbacks does not change delivery.
Custom `fetcher` implementations necessarily receive credentials and encrypted
request bodies; they are trusted transport code, not a safe logging API.
Requests omit browser cookies, reject redirects and time out after 30 seconds.
`APIError.status` exposes HTTP failures without echoing response text.

## Verification in This Workspace

```sh
npm test
```

The tests use existing CLI cryptography/fixtures, bundle the current backend,
apply every D1 migration and use real Worker HTTP, D1 and R2. They do not contact
production or APNs. Backend and CLI development dependencies must be installed
in this monorepo. The browser test needs `npx playwright install chromium --only-shell`.

The reusable parent-dashboard fixture is
`test/helpers/backend-fixture.mjs`:

```js
const h = await startBackendFixture({corsOrigins: [dashboardOrigin]});
// h.apiURL, h.config, h.session.{accessToken,userId,deviceId}
// h.sessions, h.keyID, h.db, h.fixture, h.fetcher
// Existing /v1/me, membership, /v2/keys, /v2/logs use h.session.accessToken.
await h.close();
```

Crypto dependency reference: [hpke-js](https://github.com/dajiaji/hpke-js).
