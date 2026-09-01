# PC LAN Web Client Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在普通局域网 HTTP 地址中提供一个与手机端风格一致的简洁 PC 页面，完成临时配对、密码库查看/搜索/新增/修改/删除/复制以及分类和标签管理，并确保密码库数据只保存在手机。

**Architecture:** APK 直接携带固定版本 Noble ESM 和 PC 静态页面；浏览器通过本地 import map 使用纯 JavaScript P-256、HKDF-SHA-256、AES-256-GCM，不依赖 `crypto.subtle`。一个可注入、串行化的 `LanVaultClient` 负责配对与加密 API，一个无 DOM 的 view model 负责搜索/筛选/命令映射，`app.mjs` 只负责页面状态和安全渲染。NanoHTTPD 从 APK 内的精确清单提供静态文件，密码库仍只由手机端 `VaultService` 读写。

**Tech Stack:** Android Java 8、NanoHTTPD 2.3.1、原生 HTML/CSS/ES modules、`@noble/curves@2.4.0`、`@noble/hashes@2.4.0`、`@noble/ciphers@2.4.0`、Node 24 内置 test runner、GitHub Actions。

**Spec:** `docs/superpowers/specs/2026-08-30-pc-lan-web-client-design.md`

## Global Constraints

- 本计划只补齐 PC Web 客户端和静态资源服务，不改动已经通过审查的 LAN v1 密码协议、手机业务规则或备份语义。
- 三个 Noble 包已经获得用户批准；不得再增加生产依赖、前端框架、打包器、DOM 测试框架或运行时 CDN。
- Noble 文件来自官方 npm 2.4.0 tarball，直接提交进 APK assets；构建和运行时都不得执行 `npm install`。
- 页面必须在 `http://<手机局域网地址>:8080` 工作；不得调用 `crypto.subtle`，只能依赖普通 HTTP 仍可用的安全随机数接口和随 APK 打包的纯 JavaScript 算法。
- 不使用 `localStorage`、`sessionStorage`、`IndexedDB`、Cache API、Service Worker、遥测、远程字体或第三方网络请求。
- 密码默认显示为固定掩码；仅当前记录可切换显示。渲染手机返回的数据时只使用 `textContent`、`value` 和 DOM 属性 API，不把业务数据拼进 `innerHTML`。
- 所有 vault 请求必须经过一个串行 Promise 队列；每次 mutation 成功后必须重新请求 `snapshot`，不得在 PC 端重写手机业务级联规则。
- 断开、超时、网络错误、401、解密失败、重放响应和 `pagehide` 都必须中止请求、主动覆写可控密钥数组、释放引用并清空敏感 DOM。
- 每个任务先使用 `superpowers:test-driven-development` 写出可观察的失败，再做最小实现；任务完成前使用 `superpowers:verification-before-completion` 获取新的验证证据。
- 每个任务独立提交，不混入无关重构。所有真实设备、Chrome/Edge、同 Wi-Fi 与手机热点验收若当前环境无法执行，必须记录为 deferred evidence。

---

### Task 1: Vendor Approved Noble 2.4.0 ESM Artifacts

**Files:**

- Create: `app/src/main/assets/web/vendor-manifest.json`
- Create: `app/src/main/assets/web/node_modules/@noble/curves/package.json`
- Create: `app/src/main/assets/web/node_modules/@noble/curves/LICENSE`
- Create: `app/src/main/assets/web/node_modules/@noble/curves/{bls12-381,bn254,ed25519,ed448,index,misc,nist,secp256k1,utils,webcrypto}.js`
- Create: `app/src/main/assets/web/node_modules/@noble/curves/abstract/{bls,curve,der,edwards,fft,frost,hash-to-curve,modular,montgomery,oprf,poseidon,tower,weierstrass}.js`
- Create: `app/src/main/assets/web/node_modules/@noble/hashes/package.json`
- Create: `app/src/main/assets/web/node_modules/@noble/hashes/LICENSE`
- Create: `app/src/main/assets/web/node_modules/@noble/hashes/{_blake,_md,_u64,argon2,blake1,blake2,blake3,eskdf,hkdf,hmac,index,legacy,pbkdf2,scrypt,sha2,sha3-addons,sha3,utils,webcrypto}.js`
- Create: `app/src/main/assets/web/node_modules/@noble/ciphers/package.json`
- Create: `app/src/main/assets/web/node_modules/@noble/ciphers/LICENSE`
- Create: `app/src/main/assets/web/node_modules/@noble/ciphers/{_arx,_poly1305,_polyval,aes,chacha,ff1,index,salsa,utils,webcrypto}.js`
- Create: `scripts/verify-web-vendor.mjs`
- Create: `web-tests/web-vendor.test.mjs`

**Locked upstream artifacts:**

| Package | Tarball | npm `dist.integrity` | Tarball SHA-256 |
|---|---|---|---|
| `@noble/curves@2.4.0` | `https://registry.npmjs.org/@noble/curves/-/curves-2.4.0.tgz` | `sha512-P4/62zrgfH33CneE3Dn4WhJVA22YUU0eR51wKIan4NVRvwsA0YnPTwWGpNbpuacSujmSFLvyzpyuR30+fbq2Ew==` | `55279c71b0201d6c0e58d0206d15825359e02a3932f326ba7b7909ac2d334aa9` |
| `@noble/hashes@2.4.0` | `https://registry.npmjs.org/@noble/hashes/-/hashes-2.4.0.tgz` | `sha512-X5XaVWZIBCT7HHZGm5I7ZQXDwLG+bGXuSrMQAW+7Zvl87h1kmc1ZB1VSRJcpUfoUrGQp4Fkoxm5kZ+Ms+aW+eA==` | `e1946149b780017b2564fcc092cb01c04e1d7f20627d0296c17da8868f4436dc` |
| `@noble/ciphers@2.4.0` | `https://registry.npmjs.org/@noble/ciphers/-/ciphers-2.4.0.tgz` | `sha512-AnjFn0Jv92laAkvMrghlFZq4qQCIN/4DxFV/eooqtC2YTjB7kBeLMS2T9KJX4Dn+ZVXLOwK0lSgqDtx9gvxtiw==` | `4a398bcc280c8742d474f9162f6d3c153e52ab1078e8ab592b4720410fb3c3e9` |

**Manifest contract:**

```json
{
  "schemaVersion": 1,
  "packages": [
    {
      "name": "@noble/curves",
      "version": "2.4.0",
      "tarball": "https://registry.npmjs.org/@noble/curves/-/curves-2.4.0.tgz",
      "integrity": "sha512-P4/62zrgfH33CneE3Dn4WhJVA22YUU0eR51wKIan4NVRvwsA0YnPTwWGpNbpuacSujmSFLvyzpyuR30+fbq2Ew==",
      "tarballSha256": "55279c71b0201d6c0e58d0206d15825359e02a3932f326ba7b7909ac2d334aa9",
      "license": "MIT"
    }
  ],
  "files": [
    {
      "path": "node_modules/@noble/curves/nist.js",
      "sha256": "0a692b98e22c56c0354f78eb1759cfbf6aec89eafc78cd2984a4f2e8428081e6"
    }
  ]
}
```

The committed manifest must contain all three package records and one concrete digest entry for every committed `.js`, `package.json`, and `LICENSE` file. The shown `nist.js` digest is from the verified official 2.4.0 tarball; the remaining entries are calculated from the same verified archives before the first GREEN run.

- [ ] Write `web-tests/web-vendor.test.mjs` first. It imports `verifyVendor`, resolves the repository root from `import.meta.url`, and asserts that verification succeeds and exactly the approved package/version pairs are present.

```js
import assert from "node:assert/strict";
import test from "node:test";
import { verifyVendor } from "../scripts/verify-web-vendor.mjs";

test("vendored Noble files match the approved immutable manifest", async () => {
  const report = await verifyVendor(new URL("../", import.meta.url));
  assert.deepEqual(report.packages, [
    "@noble/ciphers@2.4.0",
    "@noble/curves@2.4.0",
    "@noble/hashes@2.4.0",
  ]);
  assert.equal(report.filesVerified, 58);
});
```

- [ ] Run `node --test web-tests/web-vendor.test.mjs` and confirm RED because the verifier and committed files do not exist.
- [ ] Download the three exact tarballs to a temporary directory, verify both the registry SRI and the tarball SHA-256 above, and copy only the exact file set listed in this task. Do not copy source maps, declarations, TypeScript sources, benchmarks, tests, or development dependencies.
- [ ] Create `vendor-manifest.json` with all 58 concrete file digests. Keep package files byte-for-byte identical to the verified tarballs.
- [ ] Implement `scripts/verify-web-vendor.mjs` using only `node:crypto`, `node:fs/promises`, and `node:path`. It must reject missing/unlisted files, duplicate paths, path traversal, version mismatch, license mismatch, and digest mismatch.

```js
export async function verifyVendor(projectRootUrl) {
  const webRoot = new URL("app/src/main/assets/web/", projectRootUrl);
  const manifest = JSON.parse(await readFile(new URL("vendor-manifest.json", webRoot), "utf8"));
  assertManifestShape(manifest);
  for (const entry of manifest.files) {
    const bytes = await readFile(new URL(entry.path, webRoot));
    const actual = createHash("sha256").update(bytes).digest("hex");
    if (actual !== entry.sha256) throw new Error(`vendor digest mismatch: \${entry.path}`);
  }
  await rejectUnlistedVendorFiles(webRoot, manifest.files);
  return {
    packages: manifest.packages.map(({ name, version }) => `\${name}@\${version}`).sort(),
    filesVerified: manifest.files.length,
  };
}
```

- [ ] Run `node --test web-tests/web-vendor.test.mjs` and confirm GREEN.
- [ ] Run `git diff --check` and inspect `git diff --stat` to ensure no tarball, cache directory, generated declaration, or source map was committed.
- [ ] Commit with `git commit -m "build: vendor Noble browser crypto"`.

### Task 2: Replace Secure-Context Web Crypto with Pure JavaScript LAN Crypto

**Files:**

- Modify: `web-tests/lan-crypto.test.mjs`
- Modify: `app/src/main/assets/web/lan-crypto.mjs`

**Required exports:**

```js
export function encodeBase64Url(bytes)
export function decodeBase64Url(value)
export function generateClientKeyPair()
export async function importPublicSec1(publicKey)
export async function importPrivateScalar(privateScalar, publicKey)
export async function deriveSharedSecret(privateKey, publicKey)
export async function deriveSessionKeys(sharedSecret, runId)
export async function encryptPairingCode(options)
export async function decryptPairingReply(options)
export function destroyBytes(...values)
export class LanClientCryptoSession
```

**Compatibility rules:**

- P-256 public keys remain 65-byte uncompressed SEC1 points.
- Noble `p256.getSharedSecret(secret, publicKey, false)` returns the complete uncompressed shared point; LAN v1 uses bytes `1..32`, the x-coordinate, matching Java ECDH.
- HKDF calls are `hkdf(sha256, sharedSecret, runId, info, 32)`.
- AES-GCM calls are `gcm(key, nonce, aad).encrypt(plaintext)` and `.decrypt(ciphertextWithTag)`.
- Pairing AAD remains `runId || serverPublic || clientPublic`.
- Message nonce remains four zero bytes plus the unsigned 64-bit big-endian counter.
- Message AAD remains `METHOD + "\\n" + PATH + "\\n" + sessionId + "\\n" + counter`.

- [ ] Extend `web-tests/lan-crypto.test.mjs` before changing production code. Preserve the four existing Java-vector tests and add cases for pairing-reply decryption, tampered ciphertext rejection, invalid SEC1 points, base64url rejection, `destroy()`, and successful vector execution when `globalThis.crypto` exposes `getRandomValues` but no `subtle`.

```js
test("does not require crypto.subtle", async () => {
  const originalCrypto = globalThis.crypto;
  Object.defineProperty(globalThis, "crypto", {
    configurable: true,
    value: {
      getRandomValues: originalCrypto.getRandomValues.bind(originalCrypto),
    },
  });
  try {
    const keys = await deriveSessionKeys(decode(vector.sharedSecret), decode(vector.runId));
    assert.deepEqual(keys.clientToServerKey, decode(vector.clientToServerKey));
  } finally {
    Object.defineProperty(globalThis, "crypto", {
      configurable: true,
      value: originalCrypto,
    });
  }
});
```

- [ ] Run `node --test web-tests/lan-crypto.test.mjs` and confirm RED because the current implementation calls `crypto.subtle` and lacks pairing-reply/deletion APIs.
- [ ] Replace Web Crypto imports and calls with the approved local packages.

```js
import { gcm } from "@noble/ciphers/aes.js";
import { p256 } from "@noble/curves/nist.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

const sharedPoint = p256.getSharedSecret(privateScalar, publicSec1, false);
const sharedSecret = sharedPoint.slice(1, 33);
const handshakeKey = hkdf(sha256, sharedSecret, runId, HANDSHAKE_INFO, 32);
const ciphertext = gcm(handshakeKey, nonce, pairingAad).encrypt(plaintext);
```

- [ ] Keep existing async function signatures so existing callers/tests do not need protocol-level changes. Validate all byte lengths before invoking Noble and copy caller-owned arrays before storing them.
- [ ] Add `LanClientCryptoSession.destroy()`. It sets a destroyed flag, fills both key arrays with zero, clears queued references, and makes future encrypt/decrypt calls reject with `"LAN crypto session is destroyed"`.
- [ ] Ensure temporary shared secrets, handshake keys and plaintext byte arrays are wiped in `finally` blocks. Do not claim immutable JavaScript strings or garbage-collected memory can be synchronously erased.
- [ ] Run `node --test web-tests/lan-crypto.test.mjs web-tests/web-vendor.test.mjs` and confirm GREEN.
- [ ] Run `rg -n "crypto\\.subtle|SubtleCrypto" app/src/main/assets/web web-tests` and confirm no runtime use remains.
- [ ] Commit with `git commit -m "feat: add browser-compatible LAN crypto"`.

### Task 3: Add the DOM-Free Vault View Model

**Files:**

- Create: `app/src/main/assets/web/vault-ui-model.mjs`
- Create: `web-tests/vault-ui-model.test.mjs`

**Required exports:**

```js
export const ALL_CATEGORIES = "all"
export const UNCATEGORIZED = "uncategorized"
export function emptySnapshot()
export function normalizeSnapshot(value)
export function filterCredentials(snapshot, filters)
export function credentialFormValue(credential)
export function credentialCreateCommand(form)
export function credentialUpdateCommand(credential, form)
export function credentialDeleteCommand(credential)
export function categoryCreateCommand(name)
export function categoryRenameCommand(category, name)
export function categoryDeleteCommand(category)
export function tagCreateCommand(name)
export function tagRenameCommand(tag, name)
export function tagDeleteCommand(tag)
export function reconcileRevealedIds(revealedIds, snapshot)
```

**Model rules:**

- `normalizeSnapshot` returns new arrays/objects, validates IDs, versions, timestamp numbers and string/null field shapes, and rejects duplicate IDs.
- Search is trimmed and case-insensitive over credential name/account/url plus resolved category/tag names. It never inspects password or notes.
- Category and tag filters combine with search using AND semantics.
- `UNCATEGORIZED` matches only `categoryId === null`.
- Draft mapping trims name, account, URL and notes at form boundaries, preserves password exactly, converts empty optional fields to `null`, and deduplicates tag IDs.
- Update/delete/rename commands take `expectedVersion` from the currently displayed entity.

| Factory | Exact `op` |
|---|---|
| `credentialCreateCommand` | `credential.create` |
| `credentialUpdateCommand` | `credential.update` |
| `credentialDeleteCommand` | `credential.delete` |
| `categoryCreateCommand` | `category.create` |
| `categoryRenameCommand` | `category.rename` |
| `categoryDeleteCommand` | `category.delete` |
| `tagCreateCommand` | `tag.create` |
| `tagRenameCommand` | `tag.rename` |
| `tagDeleteCommand` | `tag.delete` |

The tenth LAN operation is the client-owned refresh command `{op: "snapshot"}` in Task 4.

- [ ] Write `web-tests/vault-ui-model.test.mjs` first with a representative immutable snapshot. Cover normalization/copying, invalid shapes, every search field, exclusion of password/notes, combined filters, uncategorized, form normalization, tag deduplication, all nine mutation command shapes, and revealed-ID reconciliation.

```js
test("search excludes password and notes and combines with taxonomy filters", () => {
  assert.deepEqual(ids(filterCredentials(snapshot, { query: "mail", categoryId: "cat-1" })), ["cred-1"]);
  assert.deepEqual(ids(filterCredentials(snapshot, { query: "secret-only", categoryId: "all" })), []);
  assert.deepEqual(ids(filterCredentials(snapshot, { query: "notes-only", tagId: null })), []);
});

test("update commands preserve optimistic concurrency", () => {
  assert.deepEqual(credentialUpdateCommand(snapshot.credentials[0], form), {
    op: "credential.update",
    id: "cred-1",
    expectedVersion: 3,
    name: "邮箱",
    account: "me@example.com",
    password: "new-secret",
    url: "https://example.com",
    categoryId: "cat-1",
    tagIds: ["tag-1"],
    notes: null,
  });
});
```

- [ ] Run `node --test web-tests/vault-ui-model.test.mjs` and confirm RED because the module is missing.
- [ ] Implement only the pure functions above; do not import `document`, `window`, `fetch`, clipboard APIs or the crypto layer.
- [ ] Use locale-independent lowercase matching and stable source order so Node results equal browser results.
- [ ] Run `node --test web-tests/vault-ui-model.test.mjs` and confirm GREEN.
- [ ] Commit with `git commit -m "feat: add PC vault view model"`.

### Task 4: Implement Pairing and the Serialized Encrypted LAN Client

**Files:**

- Create: `app/src/main/assets/web/lan-client.mjs`
- Create: `web-tests/lan-client.test.mjs`

**Public interface:**

```js
export class LanApiError extends Error {
  constructor(code, message, { disconnect = false } = {})
}

export class LanVaultClient {
  constructor({
    fetchImpl = globalThis.fetch.bind(globalThis),
    cryptoImpl = defaultCryptoImpl,
    onDisconnect = () => {},
  } = {})

  get status()
  get snapshot()
  async pair(accessCode)
  async refreshSnapshot()
  async mutate(command)
  disconnect(reason = "DISCONNECTED")
}
```

**State and wire rules:**

- Status values are `"idle"`, `"pairing"`, `"connected"`, and `"disconnected"`.
- Pairing performs GET `/api/v1/pairing-info`, creates an ephemeral client key pair, encrypts the six-digit code, POSTs `/api/v1/pairing-submit`, decrypts `sessionId`, creates `LanClientCryptoSession`, then fetches `snapshot`.
- Vault requests POST JSON to `/api/v1/vault` with `{v:1,sessionId,counter,ciphertext}`; binary values are unpadded base64url.
- One private Promise tail serializes every vault command. Counter assignment occurs inside the queued operation, never before it.
- `mutate(command)` sends the mutation and, only after `ok:true`, sends `{op:"snapshot"}` in the same queue. It returns the normalized new snapshot.
- The client never persists the access code, key material, session ID or snapshot outside in-memory fields.

- [ ] Write `web-tests/lan-client.test.mjs` first with injected fake `fetchImpl` and `cryptoImpl`. Cover successful pairing, malformed pairing metadata, wrong code/rate limit messages, strict request serialization, counters `1,2,3`, mutation followed by refresh, encrypted business errors, outer 401 disconnect, network failure abort, replay/decrypt failure, one-shot disconnect callback, and rejection of queued work after disconnect.

```js
test("serializes mutations and refreshes after each success", async () => {
  const first = client.mutate({ op: "category.create", name: "工作" });
  const second = client.mutate({ op: "tag.create", name: "常用" });
  const [firstSnapshot, secondSnapshot] = await Promise.all([first, second]);

  assert.equal(fakeServer.maxConcurrentVaultRequests, 1);
  assert.deepEqual(fakeServer.operations, [
    "category.create", "snapshot", "tag.create", "snapshot",
  ]);
  assert.equal(firstSnapshot.revision, 1);
  assert.equal(secondSnapshot.revision, 2);
});
```

- [ ] Run `node --test web-tests/lan-client.test.mjs` and confirm RED because the client module is missing.
- [ ] Implement small schema helpers for pairing info, pairing reply, encrypted envelope and decrypted `{ok,...}` payloads. Any unexpected shape is a protocol failure.
- [ ] Implement outer response mapping:

| Condition | Result |
|---|---|
| Pairing 401 | `LanApiError("UNAUTHORIZED", "访问码错误或已失效")` without exposing attempts |
| Pairing 429 | `LanApiError("RATE_LIMITED", "操作过快，请稍后重试")` |
| Vault 401 / body `DISCONNECTED` | immediate disconnect |
| `VALIDATION` | keep editor data; caller shows validation message |
| `NOT_FOUND` | caller refreshes snapshot and reports missing entity |
| `STALE_VERSION` | caller refreshes snapshot and reports conflict |
| `BAD_REQUEST` / `INTERNAL` | generic operation failure |
| Fetch abort/network/decrypt/replay | immediate disconnect |

- [ ] Implement `disconnect()` as idempotent: abort the shared `AbortController`, destroy crypto session, zero retained key material, clear snapshot/session references, reject future queued operations, then invoke `onDisconnect` once.
- [ ] Clear all pairing temporary byte arrays in `finally`, including client private key, shared secret and handshake keys.
- [ ] Run `node --test web-tests/lan-client.test.mjs web-tests/lan-crypto.test.mjs web-tests/vault-ui-model.test.mjs` and confirm GREEN.
- [ ] Commit with `git commit -m "feat: add encrypted LAN web client"`.

### Task 5: Build the Simple Responsive PC Vault Interface

**Files:**

- Modify: `app/src/main/assets/web/index.html`
- Create: `app/src/main/assets/web/styles.css`
- Create: `app/src/main/assets/web/app.mjs`
- Create: `web-tests/web-page-contract.test.mjs`

**Page structure:**

```html
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <title>密码记录器 · PC 访问</title>
  <link rel="stylesheet" href="/styles.css">
  <script type="importmap">
    {
      "imports": {
        "@noble/curves/": "/node_modules/@noble/curves/",
        "@noble/hashes/": "/node_modules/@noble/hashes/",
        "@noble/ciphers/": "/node_modules/@noble/ciphers/"
      }
    }
  </script>
  <script type="module" src="/app.mjs"></script>
</head>
```

The body contains:

- `#pairing-view`: title, six-digit `#access-code`, `#connect-button`, `#pairing-status`.
- `#vault-view`: `#sidebar`, `#search-input`, `#current-filter`, `#refresh-button`, `#add-credential-button`, `#credential-list`, empty/loading states and disconnect banner.
- `#credential-dialog`: one create/edit form with name, account, password, URL, category, tag checkboxes and notes.
- `#taxonomy-dialog`: category/tag lists with create, rename and delete controls.
- `#confirm-dialog`: one reusable destructive confirmation.
- `#toast-region`: `aria-live="polite"` feedback without secret values.

**Visual tokens:**

```css
:root {
  color-scheme: light;
  --page: #f5f7fa;
  --surface: #ffffff;
  --primary: #2563eb;
  --primary-soft: #eff6ff;
  --success: #16a34a;
  --text: #0f172a;
  --muted: #64748b;
  --border: #e2e8f0;
  --danger: #dc2626;
  --danger-soft: #fff1f2;
  --radius: 12px;
}
```

- [ ] Write `web-tests/web-page-contract.test.mjs` before replacing the placeholder page. Assert the required element IDs, module/import-map paths, responsive viewport, local-only resource URLs, password input types, accessible labels, and absence of persistence/service-worker APIs, remote origins, inline event handlers, and `crypto.subtle`.

```js
test("page is local-only and has no browser persistence", async () => {
  const sources = await readWebSources(["index.html", "styles.css", "app.mjs"]);
  assert.doesNotMatch(sources, /https?:\\/\\//i);
  assert.doesNotMatch(sources, /localStorage|sessionStorage|indexedDB|serviceWorker/i);
  assert.doesNotMatch(sources, /crypto\\.subtle/i);
});
```

- [ ] Run `node --test web-tests/web-page-contract.test.mjs` and confirm RED because the current `index.html` is only a placeholder and the CSS/controller files are missing.
- [ ] Implement the pairing view. Sanitize input to six ASCII digits, disable duplicate submissions, clear the input immediately after reading it, and display the same failure text for wrong/expired codes.
- [ ] Implement the main layout and pure rendering functions. Create elements with `document.createElement`; assign every server value through `textContent` or `value`. Never interpolate a credential/category/tag into HTML markup.
- [ ] Implement search and category/tag filters through `filterCredentials`. Keep one `Set<string>` of revealed credential IDs and reconcile it after every snapshot.
- [ ] Render every password as `••••••••` unless that credential ID is revealed. Eye-button labels must switch between “显示密码” and “隐藏密码”; revealing one row does not reveal any other row.
- [ ] Implement user-initiated copy with a secure-context path and an ordinary-HTTP fallback:

```js
async function copyText(value) {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      return;
    } catch {
      // Continue to the user-gesture fallback used on private-IP HTTP.
    }
  }
  const field = document.createElement("textarea");
  field.value = value;
  field.setAttribute("readonly", "");
  field.className = "copy-buffer";
  document.body.append(field);
  try {
    field.select();
    if (!document.execCommand("copy")) throw new Error("COPY_FAILED");
  } finally {
    field.value = "";
    field.remove();
  }
}
```

The temporary textarea must be removed in `finally`, and toast/error messages must not echo the copied value.

- [ ] Implement create/edit dialogs using the command factories. Preserve form values for `VALIDATION`; on `NOT_FOUND` or `STALE_VERSION`, close the stale editor, refresh and show the specified message.
- [ ] Implement credential/category/tag deletion with `#confirm-dialog`. Category deletion copy explicitly says credentials become uncategorized; tag deletion copy says associations are removed.
- [ ] Implement taxonomy creation/rename/delete in `#taxonomy-dialog`; each successful mutation receives and renders the refreshed snapshot returned by `client.mutate`.
- [ ] Implement `clearSensitiveUi()` and register both client disconnect callback and `pagehide`. It clears rows, forms, revealed IDs, filters and toast text, closes dialogs, and replaces the vault view with the disconnected message.
- [ ] Add desktop table and narrow-screen card layouts at `max-width: 760px`. Preserve action order and keyboard focus styles; do not hide any field only because the viewport is narrow.
- [ ] Run `node --test web-tests/*.test.mjs` and confirm GREEN.
- [ ] Manually open `index.html` only for visual inspection if a browser is locally available; protocol behavior still requires serving through the phone address and is covered in Task 7.
- [ ] Commit with `git commit -m "feat: add PC vault web interface"`.

### Task 6: Serve an Exact Static Asset Catalog from NanoHTTPD

**Files:**

- Create: `app/src/main/assets/web/runtime-assets.tsv`
- Create: `app/src/main/java/com/passwordvault/local/lan/WebAssetCatalog.java`
- Create: `app/src/test/java/com/passwordvault/local/lan/WebAssetCatalogTest.java`
- Modify: `app/src/main/java/com/passwordvault/local/lan/LanHttpServer.java`
- Modify: `app/src/main/java/com/passwordvault/local/lan/LanAccessService.java`
- Modify: `app/src/test/java/com/passwordvault/local/lan/LanHttpServerTest.java`
- Modify: `app/src/androidTest/java/com/passwordvault/local/lan/LanAccessServiceContractTest.java`
- Modify: `scripts/test-lan-http.sh`

**Catalog format:**

```text
styles.css	text/css; charset=utf-8
app.mjs	text/javascript; charset=utf-8
lan-client.mjs	text/javascript; charset=utf-8
lan-crypto.mjs	text/javascript; charset=utf-8
vault-ui-model.mjs	text/javascript; charset=utf-8
node_modules/@noble/curves/nist.js	text/javascript; charset=utf-8
```

The committed file must enumerate all browser-requestable app modules and every vendored `.js` file. It must not list `runtime-assets.tsv`, `vendor-manifest.json`, any `package.json`, or any `LICENSE`.

**Java interface:**

```java
public final class WebAssetCatalog {
    public static WebAssetCatalog parse(InputStream input) throws IOException;
    public String contentType(String relativePath);
    public Set<String> paths();
}

public interface StaticAssetSource {
    StaticAsset load(String relativePath) throws IOException;
}

public static final class StaticAsset {
    public StaticAsset(byte[] content, String contentType);
    public byte[] getContent();
    public String getContentType();
}
```

- [ ] Add `WebAssetCatalogTest` and extend `LanHttpServerTest` first. Cover valid parsing, blank/comment lines, duplicates, absolute paths, backslashes, `..`, missing MIME, correct CSS/JS MIME, `no-store`, `nosniff`, HEAD/POST rejection, unknown path 404, traversal 404, manifest/license 404, and missing whitelisted asset 500 without leaking its path.

```java
private static void rejectsUnlistedAndTraversalPaths() throws Exception {
    LanHttpServer server = startStaticServer(assetMap());
    try {
        assertEquals(404, request(server, "/vendor-manifest.json").getResponseCode());
        assertEquals(404, request(server, "/node_modules/@noble/curves/LICENSE").getResponseCode());
        assertEquals(404, request(server, "/../index.html").getResponseCode());
        assertEquals(404, request(server, "/%2e%2e/index.html").getResponseCode());
    } finally {
        server.shutdown();
    }
}
```

- [ ] Update `scripts/test-lan-http.sh` to compile/run `WebAssetCatalog.java` and `WebAssetCatalogTest.java`, then run `sh scripts/test-lan-http.sh` and confirm RED against the current one-module route.
- [ ] Implement `WebAssetCatalog.parse` with UTF-8, a 64 KiB maximum manifest size, exact duplicate detection, and path validation. Return an unmodifiable path set/map.
- [ ] Generalize `LanHttpServer` static GET handling: `/` and `/index.html` retain the index source; other paths are stripped of one leading slash, rejected if malformed, then resolved only through `StaticAssetSource`. Apply `Cache-Control: no-store` and `X-Content-Type-Options: nosniff` to every static/API response, including errors.
- [ ] In `LanAccessService`, lazily parse and cache `web/runtime-assets.tsv`. Resolve MIME from the catalog before opening `web/<relativePath>`; a path absent from the catalog returns `null` without touching `AssetManager`.
- [ ] Extend `LanAccessServiceContractTest` to read `runtime-assets.tsv`, open every listed APK asset, assert a non-empty stream, and separately assert `vendor-manifest.json` plus all three licenses are packaged.
- [ ] Run `sh scripts/test-lan-http.sh` and confirm GREEN.
- [ ] Run `node --test web-tests/*.test.mjs`; add a contract assertion that every HTML/CSS/ESM static import is listed in `runtime-assets.tsv` and every catalog file exists.
- [ ] Commit with `git commit -m "feat: serve PC web client assets"`.

### Task 7: CI, Documentation, Full Verification, and Review

**Files:**

- Modify: `.github/workflows/build-apk.yml`
- Modify: `protocol/lan-api-v1.md`
- Modify: `README.md`
- Modify: `docs/superpowers/plans/2026-08-30-pc-lan-web-client.md` (checkbox evidence only)

- [x] Change the browser step to run the complete suite and verify the vendored files before Android build:

```yaml
- name: Run browser client tests
  run: node --test web-tests/*.test.mjs
```

- [x] Update `protocol/lan-api-v1.md` with the exact static routes, local import-map behavior, pairing flow, command names, browser request queue, refresh-after-mutation rule, error mapping and non-persistence guarantees. Do not change wire fields or cryptographic constants.
- [x] Update `README.md` with the personal-use flow:

1. Phone and PC join the same Wi-Fi, or PC joins the phone hotspot.
2. Phone opens “PC 访问” and starts the foreground service.
3. PC opens the exact address shown by the phone.
4. PC enters the six-digit code and manages the vault.
5. User stops PC access from the phone or notification when finished.

- [x] Document that PC import/export/clear, multiple PCs, browser persistence, certificates, extensions and cloud sync are intentionally absent from this version.
- [x] Run fresh local verification from repository root:

```sh
node --test web-tests/*.test.mjs
sh scripts/test-core.sh
sh scripts/test-lan-http.sh
git diff --check
git status --short
```

- [x] Run the source safety scans and inspect every match:

```sh
rg -n "crypto\\.subtle|localStorage|sessionStorage|indexedDB|serviceWorker|https?://" app/src/main/assets/web --glob '!vendor-manifest.json' --glob '!node_modules/**'
rg -n "accessCode|sessionId|password|notes" app/src/main/java/com/passwordvault/local/lan app/src/main/assets/web --glob '!vendor-manifest.json' --glob '!node_modules/**'
rg -n "console\\.|android\\.util\\.Log|System\\.out|printStackTrace" app/src/main/java/com/passwordvault/local/lan app/src/main/assets/web --glob '!node_modules/**'
rg -n 'TO''DO|TB''D|implement[[:space:]]+later' app/src/main app/src/test app/src/androidTest web-tests scripts
```

Expected results: the first scan has no runtime-policy violations; the second contains only required data-flow code; the logging scan contains no sensitive-value output; the final scan is empty.

- [ ] If Gradle/Android SDK is available, run:

```sh
gradle --no-daemon lintDebug
gradle --no-daemon pixel2Api35DebugAndroidTest -Pandroid.testoptions.manageddevices.emulator.gpu=swiftshader_indirect
gradle --no-daemon assembleDebug
```

If unavailable, record the exact missing executable/SDK evidence and rely on the existing GitHub Actions job after a remote is configured; do not claim these checks passed.

- [x] Use `superpowers:requesting-code-review` for an independent review of the complete branch. Require zero Critical and zero Important findings; fix accepted findings with new failing tests and rerun the full applicable suite.
- [ ] When a real APK/device is available, execute and record this acceptance matrix:

| Environment | Pair | Search/filter | Credential CRUD/copy/reveal | Category/tag CRUD | Phone stop/timeout/network change | Refresh requires re-pair |
|---|---|---|---|---|---|---|
| Chrome + same Wi-Fi | pass/fail | pass/fail | pass/fail | pass/fail | pass/fail | pass/fail |
| Edge + same Wi-Fi | pass/fail | pass/fail | pass/fail | pass/fail | pass/fail | pass/fail |
| Chrome + phone hotspot | pass/fail | pass/fail | pass/fail | pass/fail | pass/fail | pass/fail |

Unexecuted cells remain explicitly deferred; they are not converted to passes.

- [x] Commit documentation/workflow changes with `git commit -m "docs: document PC LAN web client"`.
- [x] Use `superpowers:verification-before-completion` once more against the final HEAD, record exact commands and exit codes, and only then report the phase complete.

## Plan Self-Review

- [x] Trace every “must implement” item in the design spec to at least one task and automated or deferred acceptance check.
- [x] Confirm the dependency route uses only the three user-approved versions and introduces no package-manager install during build/runtime.
- [x] Confirm type/field names match `LanWireCodec` and `LanApiDispatcher`: `runId`, `serverPublicKey`, `clientPublicKey`, `nonce`, `ciphertext`, `sessionId`, `counter`, `expectedVersion`, `revision`, `createdAt`, `updatedAt`, and all ten operation names.
- [x] Confirm every code-producing step includes a preceding RED assertion and a following GREEN command.
- [x] Confirm static serving cannot expose vendor manifests, licenses, package metadata, arbitrary Android assets or path traversal.
- [x] Confirm no task promises evidence that this machine cannot currently produce.
