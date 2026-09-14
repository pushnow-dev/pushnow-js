// src/encoding.ts
var bytes = (value) => new TextEncoder().encode(value);
function base64(value) {
  const data = value instanceof Uint8Array ? value : new Uint8Array(value);
  let result = "";
  for (let start = 0; start < data.length; start += 8192) result += String.fromCharCode(...data.subarray(start, start + 8192));
  return btoa(result);
}
function decode(value, size) {
  if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new Error("Invalid Base64 encoding");
  const decoded = Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
  if (size !== void 0 && decoded.length !== size || base64(decoded) !== value) throw new Error("Invalid key or encoding");
  return decoded;
}
function cryptoAPI() {
  if (!globalThis.crypto?.subtle) throw new Error("WebCrypto is required; use a secure HTTPS context");
  return globalThis.crypto;
}
async function sha256(data) {
  return [...new Uint8Array(await cryptoAPI().subtle.digest("SHA-256", data))].map((n) => n.toString(16).padStart(2, "0")).join("");
}
var fingerprint = (key) => sha256(decode(key, 65));
function uuid(value) {
  if (typeof value !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) throw new Error("Invalid UUID");
}
function object(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Expected an object");
  return value;
}

// src/config.ts
function validateAPIURL(value) {
  const url = new URL(value);
  if (url.username || url.password || url.search || url.hash || url.pathname !== "/" || url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))) {
    throw new Error("Use an HTTPS API origin (HTTP is allowed only on localhost)");
  }
  return url.origin;
}
function validateArchive(value) {
  const archive = object(value);
  uuid(archive.id);
  decode(archive.public_key, 65);
  decode(archive.certificate, 64);
  return { id: archive.id, public_key: archive.public_key, certificate: archive.certificate };
}
function validateConfig(value) {
  const config = object(value);
  for (const field of ["api_url", "user_id", "source_id", "source_key", "identity_public_key", "sender_private_key"]) {
    if (typeof config[field] !== "string" || !config[field] || /[\r\n]/.test(config[field])) throw new Error(`Missing or invalid config field: ${field}`);
  }
  uuid(config.user_id);
  uuid(config.source_id);
  if (!/^[\x21-\x7e]{1,2048}$/.test(config.source_key)) throw new Error("Invalid source credential");
  decode(config.identity_public_key, 65);
  decode(config.sender_private_key, 32);
  return {
    api_url: validateAPIURL(config.api_url),
    user_id: config.user_id,
    source_id: config.source_id,
    source_key: config.source_key,
    identity_public_key: config.identity_public_key,
    sender_private_key: config.sender_private_key,
    archive: validateArchive(config.archive)
  };
}

// node_modules/@hpke/common/esm/src/errors.js
var HpkeError = class extends Error {
  constructor(e) {
    let message;
    if (e instanceof Error) {
      message = e.message;
    } else if (typeof e === "string") {
      message = e;
    } else {
      message = "";
    }
    super(message);
    this.name = this.constructor.name;
  }
};
var InvalidParamError = class extends HpkeError {
};
var SerializeError = class extends HpkeError {
};
var DeserializeError = class extends HpkeError {
};
var EncapError = class extends HpkeError {
};
var DecapError = class extends HpkeError {
};
var ExportError = class extends HpkeError {
};
var SealError = class extends HpkeError {
};
var OpenError = class extends HpkeError {
};
var MessageLimitReachedError = class extends HpkeError {
};
var DeriveKeyPairError = class extends HpkeError {
};
var NotSupportedError = class extends HpkeError {
};

// node_modules/@hpke/common/esm/_dnt.shims.js
var dntGlobals = {};
var dntGlobalThis = createMergeProxy(globalThis, dntGlobals);
function createMergeProxy(baseObj, extObj) {
  return new Proxy(baseObj, {
    get(_target, prop, _receiver) {
      if (prop in extObj) {
        return extObj[prop];
      } else {
        return baseObj[prop];
      }
    },
    set(_target, prop, value) {
      if (prop in extObj) {
        delete extObj[prop];
      }
      baseObj[prop] = value;
      return true;
    },
    deleteProperty(_target, prop) {
      let success = false;
      if (prop in extObj) {
        delete extObj[prop];
        success = true;
      }
      if (prop in baseObj) {
        delete baseObj[prop];
        success = true;
      }
      return success;
    },
    ownKeys(_target) {
      const baseKeys = Reflect.ownKeys(baseObj);
      const extKeys = Reflect.ownKeys(extObj);
      const extKeysSet = new Set(extKeys);
      return [...baseKeys.filter((k) => !extKeysSet.has(k)), ...extKeys];
    },
    defineProperty(_target, prop, desc) {
      if (prop in extObj) {
        delete extObj[prop];
      }
      Reflect.defineProperty(baseObj, prop, desc);
      return true;
    },
    getOwnPropertyDescriptor(_target, prop) {
      if (prop in extObj) {
        return Reflect.getOwnPropertyDescriptor(extObj, prop);
      } else {
        return Reflect.getOwnPropertyDescriptor(baseObj, prop);
      }
    },
    has(_target, prop) {
      return prop in extObj || prop in baseObj;
    }
  });
}

// node_modules/@hpke/common/esm/src/algorithm.js
async function loadSubtleCrypto() {
  if (dntGlobalThis !== void 0 && globalThis.crypto !== void 0) {
    return globalThis.crypto.subtle;
  }
  try {
    const { webcrypto } = await import("crypto");
    return webcrypto.subtle;
  } catch (e) {
    throw new NotSupportedError(e);
  }
}
var NativeAlgorithm = class {
  constructor() {
    Object.defineProperty(this, "_api", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
  }
  async _setup() {
    if (this._api !== void 0) {
      return;
    }
    this._api = await loadSubtleCrypto();
  }
};

// node_modules/@hpke/common/esm/src/identifiers.js
var Mode = {
  Base: 0,
  Psk: 1,
  Auth: 2,
  AuthPsk: 3
};
var KemId = {
  NotAssigned: 0,
  DhkemP256HkdfSha256: 16,
  DhkemP384HkdfSha384: 17,
  DhkemP521HkdfSha512: 18,
  DhkemSecp256k1HkdfSha256: 19,
  DhkemX25519HkdfSha256: 32,
  DhkemX448HkdfSha512: 33,
  HybridkemX25519Kyber768: 48,
  MlKem512: 64,
  MlKem768: 65,
  MlKem1024: 66,
  XWing: 25722
};
var KdfId = {
  HkdfSha256: 1,
  HkdfSha384: 2,
  HkdfSha512: 3,
  Sha3256: 4,
  Sha3384: 5,
  Sha3512: 6,
  Shake128: 16,
  Shake256: 17,
  TurboShake128: 18,
  TurboShake256: 19
};
var AeadId = {
  Aes128Gcm: 1,
  Aes256Gcm: 2,
  Chacha20Poly1305: 3,
  ExportOnly: 65535
};

// node_modules/@hpke/common/esm/src/consts.js
var INPUT_LENGTH_LIMIT = 8192;
var INFO_LENGTH_LIMIT = 268435456;
var MINIMUM_PSK_LENGTH = 32;
var EMPTY = /* @__PURE__ */ new Uint8Array(0);
var BYTE_TO_BIGINT_256 = /* @__PURE__ */ (() => {
  const out = new Array(256);
  let i = 0;
  let value = 0n;
  while (i < 256) {
    out[i] = value;
    i++;
    value += 1n;
  }
  return out;
})();

// node_modules/@hpke/common/esm/src/interfaces/kemInterface.js
var SUITE_ID_HEADER_KEM = /* @__PURE__ */ new Uint8Array([
  75,
  69,
  77,
  0,
  0
]);

// node_modules/@hpke/common/esm/src/kdfs/hkdf.js
var HPKE_VERSION = /* @__PURE__ */ new Uint8Array([
  72,
  80,
  75,
  69,
  45,
  118,
  49
]);
function toUint8Array(input) {
  return new Uint8Array(toArrayBuffer(input));
}
function toArrayBuffer(input) {
  if (input instanceof ArrayBuffer) {
    return input;
  }
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength).slice().buffer;
  }
  return new Uint8Array(input).slice().buffer;
}
var HkdfNative = class extends NativeAlgorithm {
  constructor() {
    super();
    Object.defineProperty(this, "id", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: KdfId.HkdfSha256
    });
    Object.defineProperty(this, "hashSize", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 0
    });
    Object.defineProperty(this, "_suiteId", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: EMPTY
    });
    Object.defineProperty(this, "algHash", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: {
        name: "HMAC",
        hash: "SHA-256",
        length: 256
      }
    });
  }
  init(suiteId) {
    this._suiteId = suiteId;
  }
  buildLabeledIkm(label, ikm) {
    this._checkInit();
    const ret = new Uint8Array(7 + this._suiteId.byteLength + label.byteLength + ikm.byteLength);
    ret.set(HPKE_VERSION, 0);
    ret.set(this._suiteId, 7);
    ret.set(label, 7 + this._suiteId.byteLength);
    ret.set(ikm, 7 + this._suiteId.byteLength + label.byteLength);
    return ret;
  }
  buildLabeledInfo(label, info, len) {
    this._checkInit();
    const ret = new Uint8Array(9 + this._suiteId.byteLength + label.byteLength + info.byteLength);
    ret.set(new Uint8Array([0, len]), 0);
    ret.set(HPKE_VERSION, 2);
    ret.set(this._suiteId, 9);
    ret.set(label, 9 + this._suiteId.byteLength);
    ret.set(info, 9 + this._suiteId.byteLength + label.byteLength);
    return ret;
  }
  async extract(salt, ikm) {
    await this._setup();
    const saltBuf = salt.byteLength === 0 ? new ArrayBuffer(this.hashSize) : toArrayBuffer(salt);
    if (saltBuf.byteLength !== this.hashSize) {
      throw new InvalidParamError("The salt length must be the same as the hashSize");
    }
    const ikmBuf = toArrayBuffer(ikm);
    const key = await this._api.importKey("raw", saltBuf, this.algHash, false, [
      "sign"
    ]);
    return await this._api.sign("HMAC", key, ikmBuf);
  }
  async expand(prk, info, len) {
    await this._setup();
    const prkBuf = toArrayBuffer(prk);
    const key = await this._api.importKey("raw", prkBuf, this.algHash, false, [
      "sign"
    ]);
    const okm = new ArrayBuffer(len);
    const okmBytes = new Uint8Array(okm);
    let prev = EMPTY;
    const mid = toUint8Array(info);
    const tail = new Uint8Array(1);
    if (len > 255 * this.hashSize) {
      throw new Error("Entropy limit reached");
    }
    const tmp = new Uint8Array(this.hashSize + mid.length + 1);
    for (let i = 1, cur = 0; cur < okmBytes.length; i++) {
      tail[0] = i;
      tmp.set(prev, 0);
      tmp.set(mid, prev.length);
      tmp.set(tail, prev.length + mid.length);
      prev = new Uint8Array(await this._api.sign("HMAC", key, tmp.slice(0, prev.length + mid.length + 1)));
      if (okmBytes.length - cur >= prev.length) {
        okmBytes.set(prev, cur);
        cur += prev.length;
      } else {
        okmBytes.set(prev.slice(0, okmBytes.length - cur), cur);
        cur += okmBytes.length - cur;
      }
    }
    return okm;
  }
  async extractAndExpand(salt, ikm, info, len) {
    await this._setup();
    const ikmBuf = toArrayBuffer(ikm);
    const baseKey = await this._api.importKey("raw", ikmBuf, "HKDF", false, ["deriveBits"]);
    return await this._api.deriveBits({
      name: "HKDF",
      hash: this.algHash.hash,
      salt: toArrayBuffer(salt),
      info: toArrayBuffer(info)
    }, baseKey, len * 8);
  }
  async labeledExtract(salt, label, ikm) {
    return await this.extract(salt, this.buildLabeledIkm(label, ikm));
  }
  async labeledExpand(prk, label, info, len) {
    return await this.expand(prk, this.buildLabeledInfo(label, info, len), len);
  }
  _checkInit() {
    if (this._suiteId === EMPTY) {
      throw new Error("Not initialized. Call init()");
    }
  }
};
var HkdfSha256Native = class extends HkdfNative {
  constructor() {
    super(...arguments);
    Object.defineProperty(this, "id", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: KdfId.HkdfSha256
    });
    Object.defineProperty(this, "hashSize", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 32
    });
    Object.defineProperty(this, "algHash", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: {
        name: "HMAC",
        hash: "SHA-256",
        length: 256
      }
    });
  }
};

// node_modules/@hpke/common/esm/src/utils/misc.js
var isCryptoKeyPair = (x) => typeof x === "object" && x !== null && typeof x.privateKey === "object" && typeof x.publicKey === "object";
function i2Osp(n, w) {
  if (w <= 0) {
    throw new Error("i2Osp: too small size");
  }
  if (n >= 256 ** w) {
    throw new Error("i2Osp: too large integer");
  }
  const ret = new Uint8Array(w);
  for (let i = 0; i < w && n; i++) {
    ret[w - (i + 1)] = n % 256;
    n = Math.floor(n / 256);
  }
  return ret;
}
function concat(a, b) {
  const ret = new Uint8Array(a.length + b.length);
  ret.set(a, 0);
  ret.set(b, a.length);
  return ret;
}
function base64UrlToBytes(v) {
  const base642 = v.replace(/-/g, "+").replace(/_/g, "/");
  const byteString = atob(base642);
  const ret = new Uint8Array(byteString.length);
  for (let i = 0; i < byteString.length; i++) {
    ret[i] = byteString.charCodeAt(i);
  }
  return ret;
}
function xor(a, b) {
  if (a.byteLength !== b.byteLength) {
    throw new Error("xor: different length inputs");
  }
  const buf = new Uint8Array(a.byteLength);
  for (let i = 0; i < a.byteLength; i++) {
    buf[i] = a[i] ^ b[i];
  }
  return buf;
}

// node_modules/@hpke/common/esm/src/kems/dhkem.js
var LABEL_EAE_PRK = /* @__PURE__ */ new Uint8Array([
  101,
  97,
  101,
  95,
  112,
  114,
  107
]);
var LABEL_SHARED_SECRET = /* @__PURE__ */ new Uint8Array([
  115,
  104,
  97,
  114,
  101,
  100,
  95,
  115,
  101,
  99,
  114,
  101,
  116
]);
function concat3(a, b, c) {
  const ret = new Uint8Array(a.length + b.length + c.length);
  ret.set(a, 0);
  ret.set(b, a.length);
  ret.set(c, a.length + b.length);
  return ret;
}
var Dhkem = class {
  constructor(id, prim, kdf) {
    Object.defineProperty(this, "id", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    Object.defineProperty(this, "secretSize", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 0
    });
    Object.defineProperty(this, "encSize", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 0
    });
    Object.defineProperty(this, "publicKeySize", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 0
    });
    Object.defineProperty(this, "privateKeySize", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 0
    });
    Object.defineProperty(this, "_prim", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    Object.defineProperty(this, "_kdf", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    this.id = id;
    this._prim = prim;
    this._kdf = kdf;
    const suiteId = new Uint8Array(SUITE_ID_HEADER_KEM);
    suiteId.set(i2Osp(this.id, 2), 3);
    this._kdf.init(suiteId);
  }
  async serializePublicKey(key) {
    return await this._prim.serializePublicKey(key);
  }
  async deserializePublicKey(key) {
    return await this._prim.deserializePublicKey(toArrayBuffer(key));
  }
  async serializePrivateKey(key) {
    return await this._prim.serializePrivateKey(key);
  }
  async deserializePrivateKey(key) {
    return await this._prim.deserializePrivateKey(toArrayBuffer(key));
  }
  async importKey(format, key, isPublic = true) {
    return await this._prim.importKey(format, key, isPublic);
  }
  async generateKeyPair() {
    return await this._prim.generateKeyPair();
  }
  async deriveKeyPair(ikm) {
    const rawIkm = toArrayBuffer(ikm);
    if (rawIkm.byteLength > INPUT_LENGTH_LIMIT) {
      throw new InvalidParamError("Too long ikm");
    }
    return await this._prim.deriveKeyPair(rawIkm);
  }
  async encap(params) {
    let ke;
    if (params.ekm === void 0) {
      ke = await this.generateKeyPair();
    } else if (isCryptoKeyPair(params.ekm)) {
      ke = params.ekm;
    } else {
      ke = await this.deriveKeyPair(params.ekm);
    }
    const enc = await this._prim.serializePublicKey(ke.publicKey);
    const pkrm = await this._prim.serializePublicKey(params.recipientPublicKey);
    try {
      let dh;
      if (params.senderKey === void 0) {
        dh = new Uint8Array(await this._prim.dh(ke.privateKey, params.recipientPublicKey));
      } else {
        const sks = isCryptoKeyPair(params.senderKey) ? params.senderKey.privateKey : params.senderKey;
        const dh1 = new Uint8Array(await this._prim.dh(ke.privateKey, params.recipientPublicKey));
        const dh2 = new Uint8Array(await this._prim.dh(sks, params.recipientPublicKey));
        dh = concat(dh1, dh2);
      }
      let kemContext;
      if (params.senderKey === void 0) {
        kemContext = concat(new Uint8Array(enc), new Uint8Array(pkrm));
      } else {
        const pks = isCryptoKeyPair(params.senderKey) ? params.senderKey.publicKey : await this._prim.derivePublicKey(params.senderKey);
        const pksm = await this._prim.serializePublicKey(pks);
        kemContext = concat3(new Uint8Array(enc), new Uint8Array(pkrm), new Uint8Array(pksm));
      }
      const sharedSecret = await this._generateSharedSecret(dh, kemContext);
      return {
        enc,
        sharedSecret
      };
    } catch (e) {
      throw new EncapError(e);
    }
  }
  async decap(params) {
    const enc = toArrayBuffer(params.enc);
    const pke = await this._prim.deserializePublicKey(enc);
    const skr = isCryptoKeyPair(params.recipientKey) ? params.recipientKey.privateKey : params.recipientKey;
    const pkr = isCryptoKeyPair(params.recipientKey) ? params.recipientKey.publicKey : await this._prim.derivePublicKey(params.recipientKey);
    const pkrm = await this._prim.serializePublicKey(pkr);
    try {
      let dh;
      if (params.senderPublicKey === void 0) {
        dh = new Uint8Array(await this._prim.dh(skr, pke));
      } else {
        const dh1 = new Uint8Array(await this._prim.dh(skr, pke));
        const dh2 = new Uint8Array(await this._prim.dh(skr, params.senderPublicKey));
        dh = concat(dh1, dh2);
      }
      let kemContext;
      if (params.senderPublicKey === void 0) {
        kemContext = concat(new Uint8Array(enc), new Uint8Array(pkrm));
      } else {
        const pksm = await this._prim.serializePublicKey(params.senderPublicKey);
        kemContext = new Uint8Array(enc.byteLength + pkrm.byteLength + pksm.byteLength);
        kemContext.set(new Uint8Array(enc), 0);
        kemContext.set(new Uint8Array(pkrm), enc.byteLength);
        kemContext.set(new Uint8Array(pksm), enc.byteLength + pkrm.byteLength);
      }
      return await this._generateSharedSecret(dh, kemContext);
    } catch (e) {
      throw new DecapError(e);
    }
  }
  async _generateSharedSecret(dh, kemContext) {
    const labeledIkm = this._kdf.buildLabeledIkm(LABEL_EAE_PRK, dh);
    const labeledInfo = this._kdf.buildLabeledInfo(LABEL_SHARED_SECRET, kemContext, this.secretSize);
    return await this._kdf.extractAndExpand(EMPTY, labeledIkm, labeledInfo, this.secretSize);
  }
};

// node_modules/@hpke/common/esm/src/interfaces/dhkemPrimitives.js
var KEM_USAGES = ["deriveBits"];
var LABEL_DKP_PRK = /* @__PURE__ */ new Uint8Array([
  100,
  107,
  112,
  95,
  112,
  114,
  107
]);

// node_modules/@hpke/common/esm/src/utils/bignum.js
var Bignum = class {
  constructor(size) {
    Object.defineProperty(this, "_num", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    this._num = new Uint8Array(size);
  }
  val() {
    return this._num;
  }
  reset() {
    this._num.fill(0);
  }
  set(src) {
    if (src.length !== this._num.length) {
      throw new Error("Bignum.set: invalid argument");
    }
    this._num.set(src);
  }
  isZero() {
    for (let i = 0; i < this._num.length; i++) {
      if (this._num[i] !== 0) {
        return false;
      }
    }
    return true;
  }
  lessThan(v) {
    if (v.length !== this._num.length) {
      throw new Error("Bignum.lessThan: invalid argument");
    }
    for (let i = 0; i < this._num.length; i++) {
      if (this._num[i] < v[i]) {
        return true;
      }
      if (this._num[i] > v[i]) {
        return false;
      }
    }
    return false;
  }
};

// node_modules/@hpke/common/esm/src/kems/dhkemPrimitives/ec.js
var LABEL_CANDIDATE = /* @__PURE__ */ new Uint8Array([
  99,
  97,
  110,
  100,
  105,
  100,
  97,
  116,
  101
]);
var ORDER_P_256 = /* @__PURE__ */ new Uint8Array([
  255,
  255,
  255,
  255,
  0,
  0,
  0,
  0,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  188,
  230,
  250,
  173,
  167,
  23,
  158,
  132,
  243,
  185,
  202,
  194,
  252,
  99,
  37,
  81
]);
var ORDER_P_384 = /* @__PURE__ */ new Uint8Array([
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  199,
  99,
  77,
  129,
  244,
  55,
  45,
  223,
  88,
  26,
  13,
  178,
  72,
  176,
  167,
  122,
  236,
  236,
  25,
  106,
  204,
  197,
  41,
  115
]);
var ORDER_P_521 = /* @__PURE__ */ new Uint8Array([
  1,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  250,
  81,
  134,
  135,
  131,
  191,
  47,
  150,
  107,
  127,
  204,
  1,
  72,
  247,
  9,
  165,
  208,
  59,
  181,
  201,
  184,
  137,
  156,
  71,
  174,
  187,
  111,
  183,
  30,
  145,
  56,
  100,
  9
]);
var PKCS8_ALG_ID_P_256 = /* @__PURE__ */ new Uint8Array([
  48,
  65,
  2,
  1,
  0,
  48,
  19,
  6,
  7,
  42,
  134,
  72,
  206,
  61,
  2,
  1,
  6,
  8,
  42,
  134,
  72,
  206,
  61,
  3,
  1,
  7,
  4,
  39,
  48,
  37,
  2,
  1,
  1,
  4,
  32
]);
var PKCS8_ALG_ID_P_384 = /* @__PURE__ */ new Uint8Array([
  48,
  78,
  2,
  1,
  0,
  48,
  16,
  6,
  7,
  42,
  134,
  72,
  206,
  61,
  2,
  1,
  6,
  5,
  43,
  129,
  4,
  0,
  34,
  4,
  55,
  48,
  53,
  2,
  1,
  1,
  4,
  48
]);
var PKCS8_ALG_ID_P_521 = /* @__PURE__ */ new Uint8Array([
  48,
  96,
  2,
  1,
  0,
  48,
  16,
  6,
  7,
  42,
  134,
  72,
  206,
  61,
  2,
  1,
  6,
  5,
  43,
  129,
  4,
  0,
  35,
  4,
  73,
  48,
  71,
  2,
  1,
  1,
  4,
  66
]);
var EC_P_256_PARAMS = {
  p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
  b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
  gx: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  gy: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
  coordinateSize: 32
};
var EC_P_384_PARAMS = {
  p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffffn,
  b: 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aefn,
  gx: 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7n,
  gy: 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5fn,
  coordinateSize: 48
};
var EC_P_521_PARAMS = {
  p: (1n << 521n) - 1n,
  b: 0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00n,
  gx: 0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66n,
  gy: 0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650n,
  coordinateSize: 66
};
function mod(a, p) {
  const r = a % p;
  return r >= 0n ? r : r + p;
}
function modPow(base, exponent, p) {
  let result = 1n;
  let b = mod(base, p);
  let e = exponent;
  while (e > 0n) {
    if ((e & 1n) === 1n) {
      result = mod(result * b, p);
    }
    b = mod(b * b, p);
    e >>= 1n;
  }
  return result;
}
function modSqrt(rhs, p) {
  const y = modPow(rhs, p + 1n >> 2n, p);
  if (mod(y * y, p) !== mod(rhs, p)) {
    throw new Error("Invalid ECDH point");
  }
  return y;
}
function bytesToBigInt(bytes2) {
  let v = 0n;
  for (const b of bytes2) {
    v = v << 8n | BYTE_TO_BIGINT_256[b];
  }
  return v;
}
function bigIntToBytes(v, len) {
  const out = new Uint8Array(len);
  let n = v;
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  if (n !== 0n) {
    throw new Error("Invalid coordinate length");
  }
  return out;
}
function buildRawUncompressedPublicKey(x, y, coordinateSize) {
  const out = new Uint8Array(1 + coordinateSize * 2);
  out[0] = 4;
  out.set(bigIntToBytes(x, coordinateSize), 1);
  out.set(bigIntToBytes(y, coordinateSize), 1 + coordinateSize);
  return out;
}
var Ec = class extends NativeAlgorithm {
  constructor(kem, hkdf) {
    super();
    Object.defineProperty(this, "_hkdf", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    Object.defineProperty(this, "_alg", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    Object.defineProperty(this, "_nPk", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    Object.defineProperty(this, "_nSk", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    Object.defineProperty(this, "_nDh", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    Object.defineProperty(this, "_order", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    Object.defineProperty(this, "_bitmask", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    Object.defineProperty(this, "_pkcs8AlgId", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    Object.defineProperty(this, "_curveParams", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    this._hkdf = hkdf;
    switch (kem) {
      case KemId.DhkemP256HkdfSha256:
        this._alg = { name: "ECDH", namedCurve: "P-256" };
        this._nPk = 65;
        this._nSk = 32;
        this._nDh = 32;
        this._order = ORDER_P_256;
        this._bitmask = 255;
        this._pkcs8AlgId = PKCS8_ALG_ID_P_256;
        this._curveParams = EC_P_256_PARAMS;
        break;
      case KemId.DhkemP384HkdfSha384:
        this._alg = { name: "ECDH", namedCurve: "P-384" };
        this._nPk = 97;
        this._nSk = 48;
        this._nDh = 48;
        this._order = ORDER_P_384;
        this._bitmask = 255;
        this._pkcs8AlgId = PKCS8_ALG_ID_P_384;
        this._curveParams = EC_P_384_PARAMS;
        break;
      default:
        this._alg = { name: "ECDH", namedCurve: "P-521" };
        this._nPk = 133;
        this._nSk = 66;
        this._nDh = 66;
        this._order = ORDER_P_521;
        this._bitmask = 1;
        this._pkcs8AlgId = PKCS8_ALG_ID_P_521;
        this._curveParams = EC_P_521_PARAMS;
        break;
    }
  }
  async serializePublicKey(key) {
    await this._setup();
    try {
      return await this._api.exportKey("raw", key);
    } catch (e) {
      throw new SerializeError(e);
    }
  }
  async deserializePublicKey(key) {
    await this._setup();
    try {
      return await this._importRawKey(toArrayBuffer(key), true);
    } catch (e) {
      throw new DeserializeError(e);
    }
  }
  async serializePrivateKey(key) {
    await this._setup();
    try {
      const jwk = await this._api.exportKey("jwk", key);
      if (!("d" in jwk)) {
        throw new Error("Not private key");
      }
      return base64UrlToBytes(jwk["d"]).buffer;
    } catch (e) {
      throw new SerializeError(e);
    }
  }
  async deserializePrivateKey(key) {
    await this._setup();
    try {
      return await this._importRawKey(toArrayBuffer(key), false);
    } catch (e) {
      throw new DeserializeError(e);
    }
  }
  async importKey(format, key, isPublic) {
    await this._setup();
    try {
      if (format === "raw") {
        return await this._importRawKey(key, isPublic);
      }
      if (key instanceof ArrayBuffer) {
        throw new Error("Invalid jwk key format");
      }
      return await this._importJWK(key, isPublic);
    } catch (e) {
      throw new DeserializeError(e);
    }
  }
  async generateKeyPair() {
    await this._setup();
    try {
      return await this._api.generateKey(this._alg, true, KEM_USAGES);
    } catch (e) {
      throw new NotSupportedError(e);
    }
  }
  async deriveKeyPair(ikm) {
    await this._setup();
    try {
      const rawIkm = toArrayBuffer(ikm);
      const dkpPrk = await this._hkdf.labeledExtract(EMPTY, LABEL_DKP_PRK, new Uint8Array(rawIkm));
      const bn = new Bignum(this._nSk);
      for (let counter = 0; bn.isZero() || !bn.lessThan(this._order); counter++) {
        if (counter > 255) {
          throw new Error("Faild to derive a key pair");
        }
        const bytes2 = new Uint8Array(await this._hkdf.labeledExpand(dkpPrk, LABEL_CANDIDATE, i2Osp(counter, 1), this._nSk));
        bytes2[0] = bytes2[0] & this._bitmask;
        bn.set(bytes2);
      }
      const sk = await this._deserializePkcs8Key(bn.val());
      bn.reset();
      return {
        privateKey: sk,
        publicKey: await this.derivePublicKey(sk)
      };
    } catch (e) {
      throw new DeriveKeyPairError(e);
    }
  }
  async derivePublicKey(key) {
    await this._setup();
    try {
      const jwk = await this._api.exportKey("jwk", key);
      delete jwk["d"];
      delete jwk["key_ops"];
      return await this._api.importKey("jwk", jwk, this._alg, true, []);
    } catch {
      try {
        return await this._derivePublicKeyWithoutJwkExport(key);
      } catch (e) {
        throw new DeserializeError(e);
      }
    }
  }
  async dh(sk, pk) {
    try {
      await this._setup();
      const bits = await this._api.deriveBits({
        name: "ECDH",
        public: pk
      }, sk, this._nDh * 8);
      return bits;
    } catch (e) {
      throw new SerializeError(e);
    }
  }
  async _importRawKey(key, isPublic) {
    if (isPublic && key.byteLength !== this._nPk) {
      throw new Error("Invalid public key for the ciphersuite");
    }
    if (!isPublic && key.byteLength !== this._nSk) {
      throw new Error("Invalid private key for the ciphersuite");
    }
    if (isPublic) {
      return await this._api.importKey("raw", key, this._alg, true, []);
    }
    return await this._deserializePkcs8Key(new Uint8Array(key));
  }
  async _importJWK(key, isPublic) {
    if (typeof key.crv === "undefined" || key.crv !== this._alg.namedCurve) {
      throw new Error(`Invalid crv: ${key.crv}`);
    }
    if (isPublic) {
      if (typeof key.d !== "undefined") {
        throw new Error("Invalid key: `d` should not be set");
      }
      return await this._api.importKey("jwk", key, this._alg, true, []);
    }
    if (typeof key.d === "undefined") {
      throw new Error("Invalid key: `d` not found");
    }
    return await this._api.importKey("jwk", key, this._alg, true, KEM_USAGES);
  }
  async _deserializePkcs8Key(k) {
    const pkcs8Key = new Uint8Array(this._pkcs8AlgId.length + k.length);
    pkcs8Key.set(this._pkcs8AlgId, 0);
    pkcs8Key.set(k, this._pkcs8AlgId.length);
    return await this._api.importKey("pkcs8", pkcs8Key, this._alg, true, KEM_USAGES);
  }
  async _derivePublicKeyWithoutJwkExport(key) {
    const basePointRaw = buildRawUncompressedPublicKey(this._curveParams.gx, this._curveParams.gy, this._curveParams.coordinateSize);
    const basePoint = await this._api.importKey("raw", basePointRaw.buffer, this._alg, true, []);
    const xBytes = new Uint8Array(await this._api.deriveBits({
      name: "ECDH",
      public: basePoint
    }, key, this._nDh * 8));
    const p = this._curveParams.p;
    const x = bytesToBigInt(xBytes);
    const rhs = mod(modPow(x, 3n, p) - 3n * x + this._curveParams.b, p);
    let y = modSqrt(rhs, p);
    if ((y & 1n) === 1n) {
      y = p - y;
    }
    const pubRaw = buildRawUncompressedPublicKey(x, y, this._curveParams.coordinateSize);
    return await this._api.importKey("raw", pubRaw.buffer, this._alg, true, []);
  }
};

// node_modules/@hpke/common/esm/src/interfaces/aeadEncryptionContext.js
var AEAD_USAGES = ["encrypt", "decrypt"];

// node_modules/@hpke/common/esm/src/utils/noble.js
function isBytes(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
function anumber(n, title = "") {
  if (!Number.isSafeInteger(n) || n < 0) {
    const prefix = title && `"${title}" `;
    throw new Error(`${prefix}expected integer >0, got ${n}`);
  }
}
function abytes(value, length, title = "") {
  const bytes2 = isBytes(value);
  const len = value?.length;
  const needsLen = length !== void 0;
  if (!bytes2 || needsLen && len !== length) {
    const prefix = title && `"${title}" `;
    const ofLen = needsLen ? ` of length ${length}` : "";
    const got = bytes2 ? `length=${len}` : `type=${typeof value}`;
    throw new Error(prefix + "expected Uint8Array" + ofLen + ", got " + got);
  }
  return value;
}
function aexists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished) {
    throw new Error("Hash#digest() has already been called");
  }
}
function clean(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
var _endianTestBuffer = /* @__PURE__ */ new Uint32Array([287454020]);
var _endianTestBytes = /* @__PURE__ */ new Uint8Array(_endianTestBuffer.buffer);
var isLE = _endianTestBytes[0] === 68;

// node_modules/@hpke/common/esm/src/hash/hash.js
function ahash(h) {
  if (typeof h !== "function" || typeof h.create !== "function") {
    throw new Error("Hash must wrapped by utils.createHasher");
  }
  anumber(h.outputLen);
  anumber(h.blockLen);
}

// node_modules/@hpke/common/esm/src/hash/hmac.js
var _HMAC = class {
  constructor(hash, key) {
    Object.defineProperty(this, "oHash", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    Object.defineProperty(this, "iHash", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    Object.defineProperty(this, "blockLen", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    Object.defineProperty(this, "outputLen", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    Object.defineProperty(this, "finished", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: false
    });
    Object.defineProperty(this, "destroyed", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: false
    });
    ahash(hash);
    abytes(key, void 0, "key");
    this.iHash = hash.create();
    if (typeof this.iHash.update !== "function") {
      throw new Error("Expected instance of class which extends utils.Hash");
    }
    this.blockLen = this.iHash.blockLen;
    this.outputLen = this.iHash.outputLen;
    const blockLen = this.blockLen;
    const pad = new Uint8Array(blockLen);
    pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
    for (let i = 0; i < pad.length; i++)
      pad[i] ^= 54;
    this.iHash.update(pad);
    this.oHash = hash.create();
    for (let i = 0; i < pad.length; i++)
      pad[i] ^= 54 ^ 92;
    this.oHash.update(pad);
    clean(pad);
  }
  update(buf) {
    aexists(this);
    this.iHash.update(buf);
    return this;
  }
  digestInto(out) {
    aexists(this);
    abytes(out, this.outputLen, "output");
    this.finished = true;
    this.iHash.digestInto(out);
    this.oHash.update(out);
    this.oHash.digestInto(out);
    this.destroy();
  }
  digest() {
    const out = new Uint8Array(this.oHash.outputLen);
    this.digestInto(out);
    return out;
  }
  _cloneInto(to) {
    to ||= Object.create(Object.getPrototypeOf(this), {});
    const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
    to = to;
    to.finished = finished;
    to.destroyed = destroyed;
    to.blockLen = blockLen;
    to.outputLen = outputLen;
    to.oHash = oHash._cloneInto(to.oHash);
    to.iHash = iHash._cloneInto(to.iHash);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
  destroy() {
    this.destroyed = true;
    this.oHash.destroy();
    this.iHash.destroy();
  }
};
var hmac = (hash, key, message) => new _HMAC(hash, key).update(message).digest();
hmac.create = (hash, key) => new _HMAC(hash, key);

// node_modules/@hpke/common/esm/src/hash/u64.js
var U32_MASK64 = 0xffffffffn;
var _32n = 32n;
function fromBig(n, le = false) {
  if (le) {
    return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
  }
  return {
    h: Number(n >> _32n & U32_MASK64) | 0,
    l: Number(n & U32_MASK64) | 0
  };
}
function split(lst, le = false) {
  const len = lst.length;
  const Ah = new Uint32Array(len);
  const Al = new Uint32Array(len);
  for (let i = 0; i < len; i++) {
    const { h, l } = fromBig(lst[i], le);
    [Ah[i], Al[i]] = [h, l];
  }
  return [Ah, Al];
}

// node_modules/@hpke/common/esm/src/hash/sha3.js
var _0n = 0n;
var _1n = 1n;
var _2n = 2n;
var _7n = 7n;
var _256n = 256n;
var _0x71n = 0x71n;
var SHA3_PI = [];
var SHA3_ROTL = [];
var _SHA3_IOTA = [];
for (let round = 0, R = _1n, x = 1, y = 0; round < 24; round++) {
  [x, y] = [y, (2 * x + 3 * y) % 5];
  SHA3_PI.push(2 * (5 * y + x));
  SHA3_ROTL.push((round + 1) * (round + 2) / 2 % 64);
  let t = _0n;
  for (let j = 0; j < 7; j++) {
    R = (R << _1n ^ (R >> _7n) * _0x71n) % _256n;
    if (R & _2n)
      t ^= _1n << (_1n << BigInt(j)) - _1n;
  }
  _SHA3_IOTA.push(t);
}
var IOTAS = split(_SHA3_IOTA, true);
var SHA3_IOTA_H = IOTAS[0];
var SHA3_IOTA_L = IOTAS[1];

// node_modules/@hpke/core/esm/src/aeads/aesGcm.js
var AesGcmContext = class extends NativeAlgorithm {
  constructor(key) {
    super();
    Object.defineProperty(this, "_rawKey", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    Object.defineProperty(this, "_key", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    this._rawKey = toArrayBuffer(key);
  }
  async seal(iv, data, aad) {
    await this._setupKey();
    const alg = {
      name: "AES-GCM",
      iv: toArrayBuffer(iv),
      additionalData: toArrayBuffer(aad)
    };
    const ct = await this._api.encrypt(alg, this._key, toArrayBuffer(data));
    return ct;
  }
  async open(iv, data, aad) {
    await this._setupKey();
    const alg = {
      name: "AES-GCM",
      iv: toArrayBuffer(iv),
      additionalData: toArrayBuffer(aad)
    };
    const pt = await this._api.decrypt(alg, this._key, toArrayBuffer(data));
    return pt;
  }
  async _setupKey() {
    if (this._key !== void 0) {
      return;
    }
    await this._setup();
    const key = await this._importKey(this._rawKey);
    new Uint8Array(this._rawKey).fill(0);
    this._key = key;
    return;
  }
  async _importKey(key) {
    return await this._api.importKey("raw", key, { name: "AES-GCM" }, true, AEAD_USAGES);
  }
};
var Aes128Gcm = class {
  constructor() {
    Object.defineProperty(this, "id", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: AeadId.Aes128Gcm
    });
    Object.defineProperty(this, "keySize", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 16
    });
    Object.defineProperty(this, "nonceSize", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 12
    });
    Object.defineProperty(this, "tagSize", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 16
    });
  }
  createEncryptionContext(key) {
    return new AesGcmContext(key);
  }
};
var Aes256Gcm = class extends Aes128Gcm {
  constructor() {
    super(...arguments);
    Object.defineProperty(this, "id", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: AeadId.Aes256Gcm
    });
    Object.defineProperty(this, "keySize", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 32
    });
    Object.defineProperty(this, "nonceSize", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 12
    });
    Object.defineProperty(this, "tagSize", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 16
    });
  }
};

// node_modules/@hpke/core/esm/src/utils/emitNotSupported.js
function emitNotSupported() {
  return new Promise((_resolve, reject) => {
    reject(new NotSupportedError("Not supported"));
  });
}

// node_modules/@hpke/core/esm/src/exporterContext.js
var LABEL_SEC = new Uint8Array([115, 101, 99]);
var ExporterContextImpl = class {
  constructor(api, kdf, exporterSecret) {
    Object.defineProperty(this, "_api", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    Object.defineProperty(this, "exporterSecret", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    Object.defineProperty(this, "_kdf", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    this._api = api;
    this._kdf = kdf;
    this.exporterSecret = exporterSecret;
  }
  async seal(_data, _aad) {
    return await emitNotSupported();
  }
  async open(_data, _aad) {
    return await emitNotSupported();
  }
  async export(exporterContext, len) {
    const rawExporterContext = toArrayBuffer(exporterContext);
    if (rawExporterContext.byteLength > INPUT_LENGTH_LIMIT) {
      throw new InvalidParamError("Too long exporter context");
    }
    try {
      return await this._kdf.labeledExpand(this.exporterSecret, LABEL_SEC, new Uint8Array(rawExporterContext), len);
    } catch (e) {
      throw new ExportError(e);
    }
  }
};
var RecipientExporterContextImpl = class extends ExporterContextImpl {
};
var SenderExporterContextImpl = class extends ExporterContextImpl {
  constructor(api, kdf, exporterSecret, enc) {
    super(api, kdf, exporterSecret);
    Object.defineProperty(this, "enc", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    this.enc = enc;
    return;
  }
};

// node_modules/@hpke/core/esm/src/encryptionContext.js
var EncryptionContextImpl = class extends ExporterContextImpl {
  constructor(api, kdf, params) {
    super(api, kdf, params.exporterSecret);
    Object.defineProperty(this, "_aead", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    Object.defineProperty(this, "_nK", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    Object.defineProperty(this, "_nN", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    Object.defineProperty(this, "_nT", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    Object.defineProperty(this, "_ctx", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    if (params.key === void 0 || params.baseNonce === void 0 || params.seq === void 0) {
      throw new Error("Required parameters are missing");
    }
    this._aead = params.aead;
    this._nK = this._aead.keySize;
    this._nN = this._aead.nonceSize;
    this._nT = this._aead.tagSize;
    const key = this._aead.createEncryptionContext(params.key);
    this._ctx = {
      key,
      baseNonce: params.baseNonce,
      seq: params.seq
    };
  }
  computeNonce(k) {
    const seqBytes = i2Osp(k.seq, k.baseNonce.byteLength);
    return xor(k.baseNonce, seqBytes).buffer;
  }
  incrementSeq(k) {
    if (k.seq > Number.MAX_SAFE_INTEGER) {
      throw new MessageLimitReachedError("Message limit reached");
    }
    k.seq += 1;
    return;
  }
};

// node_modules/@hpke/core/esm/src/mutex.js
var __classPrivateFieldGet = function(receiver, state, kind, f) {
  if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
  if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
  return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var __classPrivateFieldSet = function(receiver, state, value, kind, f) {
  if (kind === "m") throw new TypeError("Private method is not writable");
  if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a setter");
  if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
  return kind === "a" ? f.call(receiver, value) : f ? f.value = value : state.set(receiver, value), value;
};
var _Mutex_locked;
var Mutex = class {
  constructor() {
    _Mutex_locked.set(this, Promise.resolve());
  }
  async lock() {
    let releaseLock;
    const nextLock = new Promise((resolve) => {
      releaseLock = resolve;
    });
    const previousLock = __classPrivateFieldGet(this, _Mutex_locked, "f");
    __classPrivateFieldSet(this, _Mutex_locked, nextLock, "f");
    await previousLock;
    return releaseLock;
  }
};
_Mutex_locked = /* @__PURE__ */ new WeakMap();

// node_modules/@hpke/core/esm/src/recipientContext.js
var __classPrivateFieldGet2 = function(receiver, state, kind, f) {
  if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
  if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
  return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var __classPrivateFieldSet2 = function(receiver, state, value, kind, f) {
  if (kind === "m") throw new TypeError("Private method is not writable");
  if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a setter");
  if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
  return kind === "a" ? f.call(receiver, value) : f ? f.value = value : state.set(receiver, value), value;
};
var _RecipientContextImpl_mutex;
var RecipientContextImpl = class extends EncryptionContextImpl {
  constructor() {
    super(...arguments);
    _RecipientContextImpl_mutex.set(this, void 0);
  }
  async open(data, aad = EMPTY.buffer) {
    __classPrivateFieldSet2(this, _RecipientContextImpl_mutex, __classPrivateFieldGet2(this, _RecipientContextImpl_mutex, "f") ?? new Mutex(), "f");
    const release = await __classPrivateFieldGet2(this, _RecipientContextImpl_mutex, "f").lock();
    let pt;
    try {
      pt = await this._ctx.key.open(this.computeNonce(this._ctx), toArrayBuffer(data), toArrayBuffer(aad));
    } catch (e) {
      throw new OpenError(e);
    } finally {
      release();
    }
    this.incrementSeq(this._ctx);
    return pt;
  }
};
_RecipientContextImpl_mutex = /* @__PURE__ */ new WeakMap();

// node_modules/@hpke/core/esm/src/senderContext.js
var __classPrivateFieldGet3 = function(receiver, state, kind, f) {
  if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
  if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
  return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var __classPrivateFieldSet3 = function(receiver, state, value, kind, f) {
  if (kind === "m") throw new TypeError("Private method is not writable");
  if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a setter");
  if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
  return kind === "a" ? f.call(receiver, value) : f ? f.value = value : state.set(receiver, value), value;
};
var _SenderContextImpl_mutex;
var SenderContextImpl = class extends EncryptionContextImpl {
  constructor(api, kdf, params, enc) {
    super(api, kdf, params);
    Object.defineProperty(this, "enc", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    _SenderContextImpl_mutex.set(this, void 0);
    this.enc = enc;
  }
  async seal(data, aad = EMPTY.buffer) {
    __classPrivateFieldSet3(this, _SenderContextImpl_mutex, __classPrivateFieldGet3(this, _SenderContextImpl_mutex, "f") ?? new Mutex(), "f");
    const release = await __classPrivateFieldGet3(this, _SenderContextImpl_mutex, "f").lock();
    let ct;
    try {
      ct = await this._ctx.key.seal(this.computeNonce(this._ctx), toArrayBuffer(data), toArrayBuffer(aad));
    } catch (e) {
      throw new SealError(e);
    } finally {
      release();
    }
    this.incrementSeq(this._ctx);
    return ct;
  }
};
_SenderContextImpl_mutex = /* @__PURE__ */ new WeakMap();

// node_modules/@hpke/core/esm/src/cipherSuiteNative.js
var LABEL_BASE_NONCE = new Uint8Array([
  98,
  97,
  115,
  101,
  95,
  110,
  111,
  110,
  99,
  101
]);
var LABEL_EXP = new Uint8Array([101, 120, 112]);
var LABEL_INFO_HASH = new Uint8Array([
  105,
  110,
  102,
  111,
  95,
  104,
  97,
  115,
  104
]);
var LABEL_KEY = new Uint8Array([107, 101, 121]);
var LABEL_PSK_ID_HASH = new Uint8Array([
  112,
  115,
  107,
  95,
  105,
  100,
  95,
  104,
  97,
  115,
  104
]);
var LABEL_SECRET = new Uint8Array([115, 101, 99, 114, 101, 116]);
var SUITE_ID_HEADER_HPKE = new Uint8Array([
  72,
  80,
  75,
  69,
  0,
  0,
  0,
  0,
  0,
  0
]);
var CipherSuiteNative = class extends NativeAlgorithm {
  /**
   * @param params A set of parameters for building a cipher suite.
   *
   * If the error occurred, throws {@link InvalidParamError}.
   *
   * @throws {@link InvalidParamError}
   */
  constructor(params) {
    super();
    Object.defineProperty(this, "_kem", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    Object.defineProperty(this, "_kdf", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    Object.defineProperty(this, "_aead", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    Object.defineProperty(this, "_suiteId", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    if (typeof params.kem === "number") {
      throw new InvalidParamError("KemId cannot be used");
    }
    this._kem = params.kem;
    if (typeof params.kdf === "number") {
      throw new InvalidParamError("KdfId cannot be used");
    }
    this._kdf = params.kdf;
    if (typeof params.aead === "number") {
      throw new InvalidParamError("AeadId cannot be used");
    }
    this._aead = params.aead;
    this._suiteId = new Uint8Array(SUITE_ID_HEADER_HPKE);
    this._suiteId.set(i2Osp(this._kem.id, 2), 4);
    this._suiteId.set(i2Osp(this._kdf.id, 2), 6);
    this._suiteId.set(i2Osp(this._aead.id, 2), 8);
    this._kdf.init(this._suiteId);
  }
  /**
   * Gets the KEM context of the ciphersuite.
   */
  get kem() {
    return this._kem;
  }
  /**
   * Gets the KDF context of the ciphersuite.
   */
  get kdf() {
    return this._kdf;
  }
  /**
   * Gets the AEAD context of the ciphersuite.
   */
  get aead() {
    return this._aead;
  }
  /**
   * Creates an encryption context for a sender.
   *
   * If the error occurred, throws {@link DecapError} | {@link ValidationError}.
   *
   * @param params A set of parameters for the sender encryption context.
   * @returns A sender encryption context.
   * @throws {@link EncapError}, {@link ValidationError}
   */
  async createSenderContext(params) {
    this._validateInputLength(params);
    await this._setup();
    const dh = await this._kem.encap(params);
    let mode;
    if (params.psk !== void 0) {
      mode = params.senderKey !== void 0 ? Mode.AuthPsk : Mode.Psk;
    } else {
      mode = params.senderKey !== void 0 ? Mode.Auth : Mode.Base;
    }
    return await this._keyScheduleS(mode, dh.sharedSecret, dh.enc, params);
  }
  /**
   * Creates an encryption context for a recipient.
   *
   * If the error occurred, throws {@link DecapError}
   * | {@link DeserializeError} | {@link ValidationError}.
   *
   * @param params A set of parameters for the recipient encryption context.
   * @returns A recipient encryption context.
   * @throws {@link DecapError}, {@link DeserializeError}, {@link ValidationError}
   */
  async createRecipientContext(params) {
    this._validateInputLength(params);
    await this._setup();
    const sharedSecret = await this._kem.decap(params);
    let mode;
    if (params.psk !== void 0) {
      mode = params.senderPublicKey !== void 0 ? Mode.AuthPsk : Mode.Psk;
    } else {
      mode = params.senderPublicKey !== void 0 ? Mode.Auth : Mode.Base;
    }
    return await this._keyScheduleR(mode, sharedSecret, params);
  }
  /**
   * Encrypts a message to a recipient.
   *
   * If the error occurred, throws `EncapError` | `MessageLimitReachedError` | `SealError` | `ValidationError`.
   *
   * @param params A set of parameters for building a sender encryption context.
   * @param pt A plain text as bytes to be encrypted.
   * @param aad Additional authenticated data as bytes fed by an application.
   * @returns A cipher text and an encapsulated key as bytes.
   * @throws {@link EncapError}, {@link MessageLimitReachedError}, {@link SealError}, {@link ValidationError}
   */
  async seal(params, pt, aad = EMPTY.buffer) {
    const ctx = await this.createSenderContext(params);
    return {
      ct: await ctx.seal(pt, aad),
      enc: ctx.enc
    };
  }
  /**
   * Decrypts a message from a sender.
   *
   * If the error occurred, throws `DecapError` | `DeserializeError` | `OpenError` | `ValidationError`.
   *
   * @param params A set of parameters for building a recipient encryption context.
   * @param ct An encrypted text as bytes to be decrypted.
   * @param aad Additional authenticated data as bytes fed by an application.
   * @returns A decrypted plain text as bytes.
   * @throws {@link DecapError}, {@link DeserializeError}, {@link OpenError}, {@link ValidationError}
   */
  async open(params, ct, aad = EMPTY.buffer) {
    const ctx = await this.createRecipientContext(params);
    return await ctx.open(ct, aad);
  }
  // private verifyPskInputs(mode: Mode, params: KeyScheduleParams) {
  //   const gotPsk = (params.psk !== undefined);
  //   const gotPskId = (params.psk !== undefined && params.psk.id.byteLength > 0);
  //   if (gotPsk !== gotPskId) {
  //     throw new Error('Inconsistent PSK inputs');
  //   }
  //   if (gotPsk && (mode === Mode.Base || mode === Mode.Auth)) {
  //     throw new Error('PSK input provided when not needed');
  //   }
  //   if (!gotPsk && (mode === Mode.Psk || mode === Mode.AuthPsk)) {
  //     throw new Error('Missing required PSK input');
  //   }
  //   return;
  // }
  async _keySchedule(mode, sharedSecret, params) {
    const pskId = params.psk === void 0 ? EMPTY : toUint8Array(params.psk.id);
    const pskIdHash = await this._kdf.labeledExtract(EMPTY, LABEL_PSK_ID_HASH, pskId);
    const info = params.info === void 0 ? EMPTY : toUint8Array(params.info);
    const infoHash = await this._kdf.labeledExtract(EMPTY, LABEL_INFO_HASH, info);
    const keyScheduleContext = new Uint8Array(1 + pskIdHash.byteLength + infoHash.byteLength);
    keyScheduleContext.set(new Uint8Array([mode]), 0);
    keyScheduleContext.set(new Uint8Array(pskIdHash), 1);
    keyScheduleContext.set(new Uint8Array(infoHash), 1 + pskIdHash.byteLength);
    const psk = params.psk === void 0 ? EMPTY : toUint8Array(params.psk.key);
    const ikm = this._kdf.buildLabeledIkm(LABEL_SECRET, psk);
    const exporterSecretInfo = this._kdf.buildLabeledInfo(LABEL_EXP, keyScheduleContext, this._kdf.hashSize);
    const exporterSecret = await this._kdf.extractAndExpand(sharedSecret, ikm, exporterSecretInfo, this._kdf.hashSize);
    if (this._aead.id === AeadId.ExportOnly) {
      return { aead: this._aead, exporterSecret };
    }
    const keyInfo = this._kdf.buildLabeledInfo(LABEL_KEY, keyScheduleContext, this._aead.keySize);
    const key = await this._kdf.extractAndExpand(sharedSecret, ikm, keyInfo, this._aead.keySize);
    const baseNonceInfo = this._kdf.buildLabeledInfo(LABEL_BASE_NONCE, keyScheduleContext, this._aead.nonceSize);
    const baseNonce = await this._kdf.extractAndExpand(sharedSecret, ikm, baseNonceInfo, this._aead.nonceSize);
    return {
      aead: this._aead,
      exporterSecret,
      key,
      baseNonce: new Uint8Array(baseNonce),
      seq: 0
    };
  }
  async _keyScheduleS(mode, sharedSecret, enc, params) {
    const res = await this._keySchedule(mode, sharedSecret, params);
    if (res.key === void 0) {
      return new SenderExporterContextImpl(this._api, this._kdf, res.exporterSecret, enc);
    }
    return new SenderContextImpl(this._api, this._kdf, res, enc);
  }
  async _keyScheduleR(mode, sharedSecret, params) {
    const res = await this._keySchedule(mode, sharedSecret, params);
    if (res.key === void 0) {
      return new RecipientExporterContextImpl(this._api, this._kdf, res.exporterSecret);
    }
    return new RecipientContextImpl(this._api, this._kdf, res);
  }
  _validateInputLength(params) {
    if (params.info !== void 0 && params.info.byteLength > INFO_LENGTH_LIMIT) {
      throw new InvalidParamError("Too long info");
    }
    if (params.psk !== void 0) {
      if (params.psk.key.byteLength < MINIMUM_PSK_LENGTH) {
        throw new InvalidParamError(`PSK must have at least ${MINIMUM_PSK_LENGTH} bytes`);
      }
      if (params.psk.key.byteLength > INPUT_LENGTH_LIMIT) {
        throw new InvalidParamError("Too long psk.key");
      }
      if (params.psk.id.byteLength > INPUT_LENGTH_LIMIT) {
        throw new InvalidParamError("Too long psk.id");
      }
    }
    return;
  }
};

// node_modules/@hpke/core/esm/src/kems/dhkemNative.js
var DhkemP256HkdfSha256Native = class extends Dhkem {
  constructor() {
    const kdf = new HkdfSha256Native();
    const prim = new Ec(KemId.DhkemP256HkdfSha256, kdf);
    super(KemId.DhkemP256HkdfSha256, prim, kdf);
    Object.defineProperty(this, "id", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: KemId.DhkemP256HkdfSha256
    });
    Object.defineProperty(this, "secretSize", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 32
    });
    Object.defineProperty(this, "encSize", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 65
    });
    Object.defineProperty(this, "publicKeySize", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 65
    });
    Object.defineProperty(this, "privateKeySize", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 32
    });
  }
};

// node_modules/@hpke/core/esm/src/native.js
var CipherSuite = class extends CipherSuiteNative {
};
var DhkemP256HkdfSha256 = class extends DhkemP256HkdfSha256Native {
};
var HkdfSha256 = class extends HkdfSha256Native {
};

// node_modules/@hpke/core/esm/src/kems/dhkemPrimitives/x25519.js
var PKCS8_ALG_ID_X25519 = new Uint8Array([
  48,
  46,
  2,
  1,
  0,
  48,
  5,
  6,
  3,
  43,
  101,
  110,
  4,
  34,
  4,
  32
]);

// node_modules/@hpke/core/esm/src/kems/dhkemPrimitives/x448.js
var PKCS8_ALG_ID_X448 = new Uint8Array([
  48,
  70,
  2,
  1,
  0,
  48,
  5,
  6,
  3,
  43,
  101,
  111,
  4,
  58,
  4,
  56
]);

// src/crypto.ts
var suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });
var v2AAD = (purpose, config, messageID, archiveID) => bytes(JSON.stringify([2, purpose, config.user_id, config.source_id, messageID, archiveID]));
async function generateAgreementKey() {
  cryptoAPI();
  const pair = await suite.kem.generateKeyPair();
  return { privateKey: base64(await suite.kem.serializePrivateKey(pair.privateKey)), publicKey: base64(await suite.kem.serializePublicKey(pair.publicKey)) };
}
async function senderPublicKey(privateKey) {
  const key = await suite.kem.deserializePrivateKey(decode(privateKey, 32));
  const jwk = await cryptoAPI().subtle.exportKey("jwk", key);
  if (!jwk.x || !jwk.y) throw new Error("Sender key cannot be derived");
  const publicJWK = { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y };
  const pub = await cryptoAPI().subtle.importKey("jwk", publicJWK, { name: "ECDH", namedCurve: "P-256" }, true, []);
  return base64(await cryptoAPI().subtle.exportKey("raw", pub));
}
async function verifyCertificate(root, kind, userID, id, publicKey, signature) {
  try {
    const key = await cryptoAPI().subtle.importKey("raw", decode(root, 65), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    await cryptoAPI().subtle.importKey("raw", decode(publicKey, 65), { name: "ECDH", namedCurve: "P-256" }, false, []);
    return await cryptoAPI().subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      decode(signature, 64),
      bytes(`pushnow-${kind}-v1
${userID}
${id}
${publicKey}`)
    );
  } catch {
    return false;
  }
}
async function verifyArchive(config, value) {
  const archive = validateArchive(value);
  if (archive.id !== config.archive.id || archive.public_key !== config.archive.public_key || !await verifyCertificate(config.identity_public_key, "archive", config.user_id, archive.id, archive.public_key, archive.certificate)) throw new Error("Invalid or changed account archive");
  return archive;
}
async function sealV2(config, archive, purpose, messageID, plaintext) {
  cryptoAPI();
  const sender = await suite.createSenderContext({
    recipientPublicKey: await suite.kem.deserializePublicKey(decode(archive.public_key, 65)),
    senderKey: await suite.kem.deserializePrivateKey(decode(config.sender_private_key, 32)),
    info: bytes("pushnow-v2")
  });
  return { enc: base64(sender.enc), ciphertext: base64(await sender.seal(bytes(JSON.stringify(plaintext)), v2AAD(purpose, config, messageID, archive.id))) };
}
async function openSenderGrant(pending, grant) {
  const ciphertext = decode(grant.ciphertext);
  if (ciphertext.length > 8192 || ciphertext.length < 16) throw new Error("Invalid authorization grant size");
  const recipient = await suite.createRecipientContext({
    recipientKey: await suite.kem.deserializePrivateKey(decode(pending.key.privateKey, 32)),
    enc: decode(grant.enc, 65),
    info: bytes("pushnow-sender-grant-v2")
  });
  const plaintext = new Uint8Array(await recipient.open(ciphertext, bytes(JSON.stringify([2, "sender-grant", pending.authorization.id, pending.key.publicKey]))));
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext));
  } catch {
    throw new Error("Invalid authorization grant");
  } finally {
    plaintext.fill(0);
  }
}

// src/http.ts
var APIError = class extends Error {
  constructor(status) {
    super(`PushNow API request failed (HTTP ${status})`);
    this.status = status;
    this.name = "APIError";
  }
  status;
};
function pathTemplate(path) {
  return path.replace(/\/authorizations\/[^/]+\/token$/, "/authorizations/:id/token").replace(/\/attachments\/[^/]+$/, "/attachments/:id");
}
async function json(response) {
  if (!response.body) throw new Error("Missing API response");
  const reader = response.body.getReader(), chunks = [];
  let size = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.length;
      if (size > 2 * 1024 * 1024) {
        await reader.cancel();
        throw new Error("API response is too large");
      }
      chunks.push(part.value);
    }
  } finally {
    reader.releaseLock();
  }
  const data = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    data.set(chunk, offset);
    offset += chunk.length;
  }
  try {
    return JSON.parse(new TextDecoder().decode(data));
  } catch {
    throw new Error("Invalid API JSON response");
  }
}
async function request(apiURL, path, options = {}) {
  const origin = validateAPIURL(apiURL), method = options.method ?? "GET";
  const started = Date.now(), controller = new AbortController();
  let status = null, outcome = "network_error";
  const abort = () => controller.abort();
  options.signal?.addEventListener("abort", abort, { once: true });
  if (options.signal?.aborted) controller.abort();
  const timer = setTimeout(abort, 3e4);
  try {
    controller.signal.throwIfAborted();
    const headers = {};
    if (options.token) headers.authorization = `Bearer ${options.token}`;
    if (options.body !== void 0) headers["content-type"] = options.binary ? "application/octet-stream" : "application/json";
    if (options.messageID) headers["idempotency-key"] = options.messageID;
    const response = await (options.fetcher ?? fetch)(new URL(path, origin), {
      method,
      headers,
      redirect: "error",
      credentials: "omit",
      cache: "no-store",
      signal: controller.signal,
      ...options.body === void 0 ? {} : { body: options.binary ? options.body : JSON.stringify(options.body) }
    });
    status = response.status;
    if (!response.ok) {
      outcome = "http_error";
      await response.body?.cancel();
      throw new APIError(status);
    }
    const result = status === 204 ? null : await json(response);
    outcome = "success";
    return result;
  } catch (error) {
    if (controller.signal.aborted) {
      outcome = "aborted";
      throw new DOMException("Request aborted or timed out", "AbortError");
    }
    if (error instanceof APIError) throw error;
    throw new Error("PushNow request failed or returned an invalid response");
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", abort);
    try {
      void Promise.resolve(options.onRequest?.(Object.freeze({
        method,
        path: pathTemplate(path),
        status,
        durationMs: Math.max(0, Date.now() - started),
        outcome
      }))).catch(() => {
      });
    } catch {
    }
  }
}
function authenticated(config, path, options = {}) {
  const validated = validateConfig(config);
  return request(validated.api_url, path, { ...options, token: validated.source_key });
}

// src/recipients.ts
async function verifyDirectory(input, value) {
  const config = validateConfig(input), directory = object(structuredClone(value));
  if (directory.user_id !== config.user_id || directory.source_id !== config.source_id || directory.identity_public_key !== config.identity_public_key) throw new Error("Account or source identity changed");
  if (typeof directory.source_public_key !== "string" || typeof directory.source_certificate !== "string" || !await verifyCertificate(config.identity_public_key, "source", config.user_id, config.source_id, directory.source_public_key, directory.source_certificate)) throw new Error("Invalid source certificate");
  if (await senderPublicKey(config.sender_private_key) !== directory.source_public_key) throw new Error("Sender key does not match source");
  await verifyArchive(config, directory.archive);
  if (!Array.isArray(directory.devices) || directory.devices.length > 1e3) throw new Error("Invalid device directory");
  const ids = /* @__PURE__ */ new Set();
  for (const value2 of directory.devices) {
    const d = object(value2);
    uuid(d.id);
    if (ids.has(d.id) || d.user_id !== config.user_id || d.status !== "active" || typeof d.notifications_enabled !== "boolean" || typeof d.name !== "string" || typeof d.platform !== "string" || typeof d.public_key !== "string" || typeof d.certificate !== "string" || !await verifyCertificate(config.identity_public_key, "device", config.user_id, d.id, d.public_key, d.certificate)) throw new Error("Invalid device certificate or metadata");
    ids.add(d.id);
  }
  return directory;
}
async function recipientsV2(input, options = {}) {
  const config = validateConfig(input);
  return verifyDirectory(config, await authenticated(config, "/v2/recipients", options));
}

// src/auth.ts
async function beginLogin(apiURL, name, options = {}) {
  if (typeof name !== "string" || !name.trim() || name.trim().length > 80) throw new Error("Sender name must have 1 to 80 characters");
  options.signal?.throwIfAborted();
  const api_url = validateAPIURL(apiURL), key = await generateAgreementKey();
  const value = object(await request(api_url, "/v2/authorizations", { ...options, method: "POST", body: { name: name.trim(), public_key: key.publicKey } }));
  uuid(value.id);
  if (typeof value.device_code !== "string" || typeof value.user_code !== "string" || typeof value.expires_at !== "string" || !Number.isFinite(Date.parse(value.expires_at)) || Date.parse(value.expires_at) <= Date.now()) throw new Error("Invalid authorization response");
  return {
    api_url,
    key,
    authorization: {
      id: value.id,
      device_code: value.device_code,
      user_code: value.user_code,
      expires_at: value.expires_at,
      interval: typeof value.interval === "number" && Number.isFinite(value.interval) ? Math.max(3, value.interval) : 3
    },
    fingerprint: await fingerprint(key.publicKey)
  };
}
async function wait(ms, signal) {
  signal?.throwIfAborted();
  await new Promise((resolve, reject) => {
    const abort = () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      reject(new DOMException("Login aborted", "AbortError"));
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", abort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) abort();
  });
}
async function finishLogin(input, options) {
  if (!options || options.expectedIdentityFingerprint === void 0 && typeof options.confirmIdentity !== "function") throw new Error("Explicit account identity verification is required");
  const expected = options.expectedIdentityFingerprint?.toLowerCase();
  if (expected !== void 0 && !/^[a-f0-9]{64}$/.test(expected)) throw new Error("Expected identity fingerprint must be 64 hexadecimal characters");
  const pending = structuredClone(input), { authorization, key } = pending;
  const api_url = validateAPIURL(pending.api_url);
  if (await senderPublicKey(key.privateKey) !== key.publicKey) throw new Error("Pending authorization key mismatch");
  uuid(authorization.id);
  while (Date.now() < Date.parse(authorization.expires_at)) {
    options.signal?.throwIfAborted();
    let response;
    try {
      response = object(await request(
        api_url,
        `/v2/authorizations/${encodeURIComponent(authorization.id)}/token`,
        { ...options, method: "POST", body: { device_code: authorization.device_code } }
      ));
    } catch (error) {
      if (!(error instanceof APIError) || error.status !== 429) throw error;
    }
    if (response?.status === "approved") {
      const grant = object(await openSenderGrant(pending, object(response.grant)));
      const config = validateConfig({ ...grant, sender_private_key: key.privateKey });
      if (config.api_url !== api_url) throw new Error("Authorization API origin changed");
      await verifyArchive(config, config.archive);
      const accountFingerprint = await fingerprint(config.identity_public_key);
      const confirmed = expected !== void 0 ? expected === accountFingerprint : await options.confirmIdentity?.({ fingerprint: accountFingerprint, userID: config.user_id });
      if (confirmed !== true) throw new Error("Account identity not confirmed; discard this authorization");
      await recipientsV2(config, options);
      return config;
    }
    if (response && response.status !== "pending") throw new Error("Unexpected authorization state");
    const remaining = Date.parse(authorization.expires_at) - Date.now();
    if (remaining > 0) await wait(Math.min(remaining, Math.max(3, Number(authorization.interval) || 3) * 1e3), options.signal);
  }
  throw new Error("Authorization expired; start login again");
}
async function beginAccountLogin(apiURL, accessToken, name, options = {}) {
  if (!name.trim() || name.trim().length > 80) throw new Error("Invalid sender name");
  const api_url = validateAPIURL(apiURL), key = await generateAgreementKey();
  const value = object(await request(api_url, "/v2/account-authorizations", { ...options, token: accessToken, method: "POST", body: { name: name.trim(), public_key: key.publicKey } }));
  uuid(value.id);
  uuid(value.user_id);
  if (typeof value.device_code !== "string" || typeof value.user_code !== "string" || typeof value.expires_at !== "string" || !Number.isFinite(Date.parse(value.expires_at)) || Date.parse(value.expires_at) <= Date.now() || typeof value.identity_public_key !== "string") throw new Error("Invalid account authorization");
  return { api_url, key, authorization: { id: value.id, device_code: value.device_code, user_code: value.user_code, expires_at: value.expires_at, interval: 3 }, fingerprint: await fingerprint(key.publicKey), accountUserID: value.user_id, expectedIdentityFingerprint: await fingerprint(value.identity_public_key) };
}
async function finishAccountLogin(input, options = {}) {
  const config = await finishLogin(input, { ...options, expectedIdentityFingerprint: input.expectedIdentityFingerprint });
  if (config.user_id !== input.accountUserID) throw new Error("Authorization account changed");
  return config;
}

// src/attachments.ts
var maxAttachmentSize = 20 * 1024 * 1024 - 16;
function validateAttachmentMetadata(metadata) {
  if (!metadata || typeof metadata.name !== "string" || !metadata.name.trim() || metadata.name.length > 255 || /[\x00-\x1f]/.test(metadata.name)) throw new Error("Invalid attachment name");
  if (metadata.mime !== void 0 && (typeof metadata.mime !== "string" || !/^[\w!#$&^.+-]+\/[\w!#$&^.+-]+(?:;[^\r\n]*)?$/.test(metadata.mime) || metadata.mime.length > 255)) throw new Error("Invalid attachment MIME type");
  if (metadata.id !== void 0) uuid(metadata.id);
  return { ...metadata };
}
function validateAttachmentData(data) {
  const size = typeof Blob !== "undefined" && data instanceof Blob ? data.size : data instanceof Uint8Array || data instanceof ArrayBuffer ? data.byteLength : NaN;
  if (!Number.isFinite(size)) throw new Error("Attachment must be a Blob, Uint8Array or ArrayBuffer");
  if (size > maxAttachmentSize) throw new Error("Attachment exceeds the 20 MiB encrypted size limit");
}
function validateDescriptor(value) {
  const d = object(value);
  uuid(d.id);
  validateAttachmentMetadata({ id: d.id, name: d.name, mime: d.mime });
  if (typeof d.mime !== "string" || !Number.isSafeInteger(d.size) || d.size < 0 || d.size > maxAttachmentSize || typeof d.read_token !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(d.read_token) || typeof d.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(d.sha256)) throw new Error("Invalid attachment descriptor");
  decode(d.key, 32);
  decode(d.nonce, 12);
  return {
    id: d.id,
    name: d.name,
    mime: d.mime,
    size: d.size,
    read_token: d.read_token,
    key: d.key,
    nonce: d.nonce,
    sha256: d.sha256
  };
}
async function uploadAttachment(input, data, metadata, options = {}) {
  const config = validateConfig(input), meta = validateAttachmentMetadata(metadata);
  validateAttachmentData(data);
  options.signal?.throwIfAborted();
  const clear = typeof Blob !== "undefined" && data instanceof Blob ? new Uint8Array(await data.arrayBuffer()) : data instanceof Uint8Array ? new Uint8Array(data) : new Uint8Array(data.slice(0));
  const key = cryptoAPI().getRandomValues(new Uint8Array(32)), nonce = cryptoAPI().getRandomValues(new Uint8Array(12));
  const id = meta.id ?? cryptoAPI().randomUUID();
  try {
    const aes = await cryptoAPI().subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
    const ciphertext = await cryptoAPI().subtle.encrypt({
      name: "AES-GCM",
      iv: nonce,
      additionalData: bytes(JSON.stringify([2, "attachment", config.user_id, config.source_id, id]))
    }, aes, clear);
    const descriptor = {
      id,
      name: meta.name,
      mime: meta.mime ?? "application/octet-stream",
      size: clear.length,
      read_token: base64(cryptoAPI().getRandomValues(new Uint8Array(32))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
      key: base64(key),
      nonce: base64(nonce),
      sha256: await sha256(clear)
    };
    await authenticated(config, "/v2/attachments", { ...options, method: "POST", body: { id, size: ciphertext.byteLength, read_token: descriptor.read_token } });
    await authenticated(config, `/v2/attachments/${id}`, { ...options, method: "PUT", binary: true, body: ciphertext });
    return descriptor;
  } finally {
    key.fill(0);
    clear.fill(0);
  }
}

// src/messages.ts
var bindings = /* @__PURE__ */ new WeakMap();
var binding = (config) => JSON.stringify([config.api_url, config.user_id, config.source_id, config.identity_public_key, config.sender_private_key, config.archive.id, config.archive.public_key]);
function validateContent(input) {
  const value = object(input);
  if (Object.keys(value).some((k) => !["title", "body", "links", "attachments", "image_id", "icon_id"].includes(k))) throw new Error("Unsupported message content field; pass routing fields such as sound in MessageOptions");
  if (typeof value.title !== "string" || typeof value.body !== "string") throw new Error("Message needs title and body");
  const links = value.links ?? [], attachments = value.attachments ?? [];
  if (!Array.isArray(links) || links.some((link) => typeof link !== "string") || !Array.isArray(attachments) || attachments.length > 20) throw new Error("Invalid links or attachment count");
  const descriptors = attachments.map(validateDescriptor), ids = new Set(descriptors.map((d) => d.id));
  if (ids.size !== descriptors.length) throw new Error("Duplicate attachment");
  for (const id of [value.image_id, value.icon_id]) if (id !== void 0) {
    uuid(id);
    if (!ids.has(id)) throw new Error("Image and icon must refer to an attached file");
  }
  const full = {
    title: value.title,
    body: value.body,
    links: [...links],
    attachments: descriptors,
    ...value.image_id === void 0 ? {} : { image_id: value.image_id },
    ...value.icon_id === void 0 ? {} : { icon_id: value.icon_id }
  };
  if (bytes(JSON.stringify(full)).length + 16 > 256 * 1024) throw new Error("Encrypted message manifest exceeds 256 KiB");
  return full;
}
function timestamp(value) {
  if (value === void 0) return void 0;
  if (typeof value !== "string") throw new Error("Invalid ISO timestamp");
  const match = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.(\d{1,3}))?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  if (!match) throw new Error("Invalid ISO timestamp");
  const local = `${match[1]}T${match[2]}.${(match[3] ?? "").padEnd(3, "0")}Z`;
  if (!Number.isFinite(Date.parse(value)) || !Number.isFinite(Date.parse(local)) || new Date(local).toISOString() !== local) throw new Error("Invalid ISO timestamp");
  return new Date(value).toISOString();
}
function validateMessageOptions(options) {
  if (options.sound !== void 0 && !["default", "silent", "chime"].includes(options.sound)) throw new Error("Invalid sound; use default, silent or chime");
  if (options.inboxOnly !== void 0 && typeof options.inboxOnly !== "boolean") throw new Error("inboxOnly must be boolean");
  if (options.inboxOnly && options.deviceIds !== void 0) throw new Error("Choose inboxOnly or deviceIds, not both");
  if (options.deviceIds !== void 0) {
    if (!Array.isArray(options.deviceIds) || options.deviceIds.length > 100) throw new Error("Invalid target count");
    options.deviceIds.forEach(uuid);
    if (new Set(options.deviceIds).size !== options.deviceIds.length) throw new Error("Duplicate target");
  }
  if (options.messageID !== void 0) uuid(options.messageID);
  if (options.sourceKind !== void 0 && !["web", "cli", "api", "subscription"].includes(options.sourceKind)) throw new Error("Invalid source kind");
  const scheduledAt = timestamp(options.scheduledAt), expiresAt = timestamp(options.expiresAt), now = Date.now(), end = now + 30 * 864e5;
  if (scheduledAt && (Date.parse(scheduledAt) <= now || Date.parse(scheduledAt) > end)) throw new Error("Schedule must be in the next 30 days");
  if (expiresAt && (Date.parse(expiresAt) <= (scheduledAt ? Date.parse(scheduledAt) : now) || Date.parse(expiresAt) > end)) throw new Error("Expiry must follow delivery and be within 30 days");
  return { ...options, deviceIds: options.deviceIds && [...options.deviceIds], scheduledAt, expiresAt };
}
function truncateUTF8(value, limit) {
  let result = "", size = 0;
  for (const char of value) {
    const n = bytes(char).length;
    if (size + n > limit) break;
    result += char;
    size += n;
  }
  return result;
}
async function prepareMessageV2(input, inputDirectory, plaintext, inputOptions = {}) {
  const config = validateConfig(input), full = validateContent(plaintext), options = validateMessageOptions(inputOptions);
  const directory = await verifyDirectory(config, inputDirectory), messageID = options.messageID ?? cryptoAPI().randomUUID();
  let notify;
  if (options.inboxOnly) notify = [];
  else if (options.deviceIds !== void 0) {
    const selected = directory.devices.filter((d) => options.deviceIds.includes(d.id));
    if (selected.length !== options.deviceIds.length) throw new Error("Unknown notification device");
    notify = selected.filter((d) => d.notifications_enabled).map((d) => d.id);
  }
  const encrypted = await sealV2(config, directory.archive, "message", messageID, full);
  const previewData = { title: truncateUTF8(full.title, 400), body: truncateUTF8(full.body, 700) };
  const image = full.attachments.find((a) => a.id === full.image_id);
  if (image && bytes(JSON.stringify(image)).length <= 600) previewData.image = image;
  const previewSize = (envelope) => bytes(JSON.stringify({
    aps: { alert: { title: "PushNow", body: "You have a new encrypted reminder." }, "mutable-content": 1, sound: "pushnow-chime.wav" },
    secure_v2: {
      message_id: messageID,
      user_id: config.user_id,
      source_id: config.source_id,
      archive_id: directory.archive.id,
      device_id: "00000000-0000-0000-0000-000000000000",
      ...envelope,
      source_public_key: directory.source_public_key,
      source_certificate: directory.source_certificate,
      created_at: (/* @__PURE__ */ new Date()).toISOString(),
      read_at: null
    }
  })).length;
  let preview = await sealV2(config, directory.archive, "preview", messageID, previewData);
  if (previewSize(preview) > 3900 || decode(preview.ciphertext).length > 2400) {
    delete previewData.image;
    preview = await sealV2(config, directory.archive, "preview", messageID, previewData);
  }
  if (previewSize(preview) > 3900 || decode(preview.ciphertext).length > 2400) throw new Error("Encrypted preview is too large");
  const message = {
    message_id: messageID,
    archive_id: directory.archive.id,
    ...encrypted,
    preview,
    attachment_ids: full.attachments.map((a) => a.id),
    ...notify === void 0 ? {} : { notify_device_ids: notify },
    ...options.sourceKind === void 0 ? {} : { source_kind: options.sourceKind },
    ...options.scheduledAt === void 0 ? {} : { scheduled_at: options.scheduledAt },
    ...options.expiresAt === void 0 ? {} : { expires_at: options.expiresAt },
    ...options.sound === void 0 ? {} : { sound: options.sound }
  };
  Object.freeze(message.preview);
  Object.freeze(message.attachment_ids);
  if (message.notify_device_ids) Object.freeze(message.notify_device_ids);
  Object.freeze(message);
  bindings.set(message, binding(config));
  return message;
}
async function submitMessageV2(input, message, options = {}) {
  const config = validateConfig(input);
  if (bindings.get(message) !== binding(config)) throw new Error("Use the original prepared message with its authorized account and source");
  const result = object(await authenticated(config, "/v2/messages", { ...options, method: "POST", messageID: message.message_id, body: message }));
  if (result.message_id !== message.message_id || typeof result.deduplicated !== "boolean") throw new Error("Invalid message response");
  return { message_id: result.message_id, deduplicated: result.deduplicated };
}

// src/send.ts
async function sendNotification(input, notification, inputOptions = {}) {
  const config = validateConfig(input), options = { ...inputOptions, ...validateMessageOptions(inputOptions) };
  const { files = [], image, icon, ...content } = notification;
  const full = validateContent(content);
  if (!Array.isArray(files)) throw new Error("files must be an array");
  if (image && full.image_id || icon && full.icon_id) throw new Error("Choose a file upload or an existing attachment ID");
  const uploads = [...files, ...image ? [image] : [], ...icon ? [icon] : []].map((file) => {
    const meta = validateAttachmentMetadata(file);
    validateAttachmentData(file.data);
    return { ...meta, data: file.data };
  });
  if (full.attachments.length + uploads.length > 20) throw new Error("Maximum 20 attachments per notification");
  const knownIDs = [...full.attachments.map((a) => a.id), ...uploads.flatMap((a) => a.id ? [a.id] : [])];
  if (new Set(knownIDs).size !== knownIDs.length) throw new Error("Duplicate attachment");
  const directory = await recipientsV2(config, options);
  if (options.deviceIds?.some((id) => !directory.devices.some((d) => d.id === id))) throw new Error("Unknown notification device");
  for (let index = 0; index < uploads.length; index++) {
    const file = uploads[index];
    const descriptor = await uploadAttachment(config, file.data, file, options);
    full.attachments.push(descriptor);
    if (image && index === files.length) full.image_id = descriptor.id;
    if (icon && index === files.length + (image ? 1 : 0)) full.icon_id = descriptor.id;
  }
  const message = await prepareMessageV2(config, directory, full, options);
  return submitMessageV2(config, message, options);
}
export {
  APIError,
  beginAccountLogin,
  beginLogin,
  fingerprint,
  finishAccountLogin,
  finishLogin,
  prepareMessageV2,
  recipientsV2,
  sendNotification,
  submitMessageV2,
  uploadAttachment,
  validateConfig
};
/*! Bundled license information:

@hpke/common/esm/src/curve/modular.js:
@hpke/common/esm/src/curve/montgomery.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)
*/
