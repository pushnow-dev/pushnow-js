# PushNow TypeScript SDK

[English](README.md)

这是 PushNow v2 加密 API 的浏览器与 Node.js SDK。它使用 `@hpke/core` 1.9.0、P-256、HKDF-SHA256、AES-256-GCM 和原生 WebCrypto。包格式是 ESM，包含 TypeScript declarations，没有 CommonJS 入口。

## 安装

发布到 npm 后：

```sh
npm install pushnow-sdk
```

本地开发：

```sh
cd sdk/typescript
npm ci
npm run build
npm pack
```

## 授权

SDK sender 需要先在已登录的 PushNow App 中审批。`pending.fingerprint` 是新 sender 的指纹，不是账号根指纹。`expectedIdentityFingerprint` 必须来自可信设备，不能从同一个未验证 grant 自动计算并接受。

```ts
import {beginLogin, finishLogin} from 'pushnow-sdk';

const pending = await beginLogin('https://api.pushnow.dev', 'My automation');
const config = await finishLogin(pending, {
  expectedIdentityFingerprint: trustedAccountFingerprint,
});
```

## 发送通知

```ts
import {sendNotification} from 'pushnow-sdk';

await sendNotification(config, {
  title: 'Build completed',
  body: 'Version 1.2 is ready.',
  links: ['https://example.com/build/42'],
}, {
  sound: 'chime',
});
```

SDK 会在本地加密标题、正文、链接和附件。服务器只能看到路由、定时、附件密文字节数等必要元数据，看不到明文内容、文件名或附件密钥。

## 测试

```sh
npm test
```

测试覆盖 Worker fixture、浏览器 bundle、授权、加密互通、附件、定时、声音路由和脱敏错误。测试不代表生产 APNs 设备可见送达。
