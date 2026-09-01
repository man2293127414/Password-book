import * as defaultCryptoImpl from "./lan-crypto.mjs";
import { normalizeSnapshot } from "./vault-ui-model.mjs";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

const DISCONNECTED_MESSAGE = "与手机连接已断开，请在手机重新开启 PC 访问";
const PROTOCOL_MESSAGE = "手机返回了无效响应";
const GENERIC_OPERATION_MESSAGE = "操作失败，请稍后重试";
const HEALTH_CHECK_INTERVAL_MS = 5_000;
const HEALTH_CHECK_TIMEOUT_MS = 5_000;

const BUSINESS_MESSAGES = Object.freeze({
  VALIDATION: "输入内容不符合要求",
  NOT_FOUND: "请求的内容已不存在",
  STALE_VERSION: "记录已变化，请刷新后重试",
  BAD_REQUEST: GENERIC_OPERATION_MESSAGE,
  INTERNAL: GENERIC_OPERATION_MESSAGE,
});

export class LanApiError extends Error {
  constructor(code, message, { disconnect = false } = {}) {
    super(message);
    this.name = "LanApiError";
    this.code = code;
    this.disconnect = disconnect;
  }
}

export class LanVaultClient {
  #fetch;
  #crypto;
  #onDisconnect;
  #status = "idle";
  #snapshot = null;
  #session = null;
  #sessionId = null;
  #controller = new AbortController();
  #tail = Promise.resolve();
  #pairingBytes = new Set();
  #disconnectNotified = false;
  #lifecycle = 0;
  #scheduler;
  #healthTimer = null;
  #healthPromise = null;
  #healthController = null;
  #pairingIdentity = null;

  constructor({
    fetchImpl = globalThis.fetch.bind(globalThis),
    cryptoImpl = defaultCryptoImpl,
    onDisconnect = () => {},
    scheduler = globalThis,
  } = {}) {
    if (typeof fetchImpl !== "function") throw new TypeError("fetchImpl must be a function");
    if (cryptoImpl === null || typeof cryptoImpl !== "object") {
      throw new TypeError("cryptoImpl must be an object");
    }
    if (typeof onDisconnect !== "function") throw new TypeError("onDisconnect must be a function");
    if (
      scheduler === null
      || typeof scheduler.setTimeout !== "function"
      || typeof scheduler.clearTimeout !== "function"
    ) {
      throw new TypeError("scheduler must provide setTimeout and clearTimeout");
    }
    this.#fetch = fetchImpl;
    this.#crypto = cryptoImpl;
    this.#onDisconnect = onDisconnect;
    this.#scheduler = scheduler;
  }

  get status() {
    return this.#status;
  }

  get snapshot() {
    return this.#snapshot;
  }

  async pair(accessCode) {
    if (this.#status === "disconnected") throw disconnectedError();
    if (this.#status !== "idle") {
      throw new LanApiError("BAD_REQUEST", GENERIC_OPERATION_MESSAGE);
    }
    if (typeof accessCode !== "string" || !/^\d{6}$/.test(accessCode)) {
      throw new LanApiError("VALIDATION", "访问码必须为六位数字");
    }

    this.#status = "pairing";
    let authenticatedReply = false;
    let installedSession = false;
    try {
      const infoResponse = await this.#request("/api/v1/pairing-info", {
        method: "GET",
        signal: this.#controller.signal,
      });
      this.#assertPairingActive();
      if (!infoResponse.ok) throw this.#pairingOuterError(infoResponse.status);
      const infoText = await this.#readBody(infoResponse);
      this.#assertPairingActive();
      const info = parsePairingInfo(infoText, this.#crypto);
      this.#trackPairingBytes(info.runId, info.serverPublicKey);

      const clientPair = this.#crypto.generateClientKeyPair();
      const rawClientPrivateKey = clientPair?.privateKey;
      const rawClientPublicKey = clientPair?.publicKey;
      this.#trackPairingBytes(rawClientPrivateKey, rawClientPublicKey);
      const clientPrivateKey = requireBytesLength(rawClientPrivateKey, 32, "client private key");
      const clientPublicKey = requireBytesLength(rawClientPublicKey, 65, "client public key");
      if (clientPublicKey[0] !== 0x04) throw new TypeError("client public key must be uncompressed");

      const rawSharedSecret = await this.#crypto.deriveSharedSecret(
        clientPrivateKey,
        info.serverPublicKey,
      );
      this.#trackPairingBytes(rawSharedSecret);
      const sharedSecret = requireBytesLength(rawSharedSecret, 32, "shared secret");
      this.#assertPairingActive();
      const encryptedCode = await this.#crypto.encryptPairingCode({
        sharedSecret,
        runId: info.runId,
        serverPublic: info.serverPublicKey,
        clientPublic: clientPublicKey,
        accessCode,
      });
      const rawRequestNonce = encryptedCode?.nonce;
      const rawRequestCiphertext = encryptedCode?.ciphertext;
      this.#trackPairingBytes(rawRequestNonce, rawRequestCiphertext);
      const requestNonce = requireBytesLength(rawRequestNonce, 12, "pairing nonce");
      const requestCiphertext = requireBytesLength(
        rawRequestCiphertext,
        22,
        "pairing ciphertext",
      );
      this.#assertPairingActive();

      const submitResponse = await this.#request("/api/v1/pairing-submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        signal: this.#controller.signal,
        body: JSON.stringify({
          v: 1,
          clientPublicKey: this.#crypto.encodeBase64Url(clientPublicKey),
          nonce: this.#crypto.encodeBase64Url(requestNonce),
          ciphertext: this.#crypto.encodeBase64Url(requestCiphertext),
        }),
      });
      this.#assertPairingActive();
      if (!submitResponse.ok) throw this.#pairingOuterError(submitResponse.status);
      authenticatedReply = true;

      const replyText = await this.#readBody(submitResponse);
      this.#assertPairingActive();
      const reply = parsePairingReply(replyText, this.#crypto);
      this.#trackPairingBytes(reply.nonce, reply.ciphertext);
      const pairingPlaintext = await this.#crypto.decryptPairingReply({
        sharedSecret,
        runId: info.runId,
        serverPublic: info.serverPublicKey,
        clientPublic: clientPublicKey,
        nonce: reply.nonce,
        ciphertext: reply.ciphertext,
      });
      this.#assertPairingActive();
      const sessionId = parsePairingSuccess(pairingPlaintext);
      const keys = await this.#crypto.deriveSessionKeys(sharedSecret, info.runId);
      const rawHandshakeKey = keys?.handshakeKey;
      const rawClientToServerKey = keys?.clientToServerKey;
      const rawServerToClientKey = keys?.serverToClientKey;
      this.#trackPairingBytes(rawHandshakeKey, rawClientToServerKey, rawServerToClientKey);
      const handshakeKey = requireBytesLength(rawHandshakeKey, 32, "handshake key");
      const clientToServerKey = requireBytesLength(
        rawClientToServerKey,
        32,
        "client-to-server key",
      );
      const serverToClientKey = requireBytesLength(
        rawServerToClientKey,
        32,
        "server-to-client key",
      );
      this.#assertPairingActive();

      this.#session = new this.#crypto.LanClientCryptoSession({
        sessionId,
        clientToServerKey,
        serverToClientKey,
      });
      this.#sessionId = sessionId;
      this.#status = "connected";
      this.#pairingIdentity = pairingIdentity(info, this.#crypto);
      installedSession = true;
      const initialSnapshot = await this.refreshSnapshot();
      this.#scheduleHealthCheck(this.#lifecycle);
      return initialSnapshot;
    } catch (error) {
      if (error instanceof LanApiError) {
        if (installedSession && !error.disconnect) {
          this.disconnect(error.code);
          throw disconnectedError();
        }
        if (error.disconnect && this.#status !== "disconnected") this.disconnect(error.code);
        if (this.#status === "pairing") this.#status = "idle";
        throw error;
      }
      if (authenticatedReply || installedSession) {
        this.disconnect("PROTOCOL");
        throw protocolError(true);
      }
      if (this.#status === "pairing") this.#status = "idle";
      throw protocolError(false);
    } finally {
      this.#clearPairingBytes();
    }
  }

  refreshSnapshot() {
    return this.#enqueue(async (lifecycle) => {
      const result = await this.#sendVaultCommand({ op: "snapshot" }, lifecycle);
      this.#assertConnected(lifecycle);
      this.#snapshot = result.snapshot;
      this.#assertConnected(lifecycle);
      return this.#snapshot;
    });
  }

  mutate(command) {
    return this.#enqueue(async (lifecycle) => {
      await this.#sendVaultCommand(command, lifecycle);
      this.#assertConnected(lifecycle);
      const result = await this.#sendVaultCommand({ op: "snapshot" }, lifecycle);
      this.#assertConnected(lifecycle);
      this.#snapshot = result.snapshot;
      this.#assertConnected(lifecycle);
      return this.#snapshot;
    });
  }

  disconnect(reason = "DISCONNECTED") {
    if (this.#status === "disconnected") return;
    this.#status = "disconnected";
    this.#lifecycle += 1;
    const session = this.#session;
    this.#session = null;
    this.#sessionId = null;
    this.#snapshot = null;
    this.#pairingIdentity = null;
    this.#cancelHealthCheck();
    try {
      this.#controller.abort();
    } catch {
      // Cleanup is best-effort; later cleanup steps must still run.
    }
    try {
      session?.destroy();
    } catch {
      // The session reference is already cleared and disconnect remains one-way.
    }
    this.#clearPairingBytes();
    if (!this.#disconnectNotified) {
      this.#disconnectNotified = true;
      try {
        this.#onDisconnect(reason);
      } catch {
        // UI callback failures must not replace the API's disconnect error.
      }
    }
  }

  checkHealth() {
    if (this.#status !== "connected") return Promise.reject(disconnectedError());
    if (this.#healthPromise !== null) return this.#healthPromise;
    const lifecycle = this.#lifecycle;
    this.#healthPromise = this.#runHealthCheck(lifecycle).finally(() => {
      this.#healthPromise = null;
      if (this.#status === "connected" && this.#lifecycle === lifecycle) {
        this.#scheduleHealthCheck(lifecycle);
      }
    });
    return this.#healthPromise;
  }

  async #runHealthCheck(lifecycle) {
    this.#assertConnected(lifecycle);
    const controller = new AbortController();
    const timeout = this.#setTimer(() => controller.abort(), HEALTH_CHECK_TIMEOUT_MS);
    const abortActiveHealth = () => controller.abort();
    this.#controller.signal.addEventListener("abort", abortActiveHealth, { once: true });
    this.#healthController = controller;
    let info;
    try {
      const response = await this.#request("/api/v1/pairing-info", {
        method: "GET",
        signal: controller.signal,
      });
      this.#assertConnected(lifecycle);
      if (!response.ok) {
        this.disconnect("DISCONNECTED");
        throw disconnectedError();
      }
      const text = await this.#readBody(response);
      this.#assertConnected(lifecycle);
      try {
        info = parsePairingInfo(text, this.#crypto);
        if (!samePairingIdentity(this.#pairingIdentity, info, this.#crypto)) {
          this.disconnect("DISCONNECTED");
          throw disconnectedError();
        }
      } catch (error) {
        if (error instanceof LanApiError) throw error;
        this.disconnect("PROTOCOL");
        throw protocolError(true);
      } finally {
        if (info !== undefined) this.#destroyBytes(info.runId, info.serverPublicKey);
      }
    } finally {
      this.#scheduler.clearTimeout(timeout);
      this.#controller.signal.removeEventListener("abort", abortActiveHealth);
      if (this.#healthController === controller) this.#healthController = null;
    }
  }

  #scheduleHealthCheck(lifecycle) {
    if (this.#status !== "connected" || this.#lifecycle !== lifecycle || this.#healthTimer !== null) return;
    this.#healthTimer = this.#setTimer(() => {
      this.#healthTimer = null;
      this.checkHealth().catch(() => {});
    }, HEALTH_CHECK_INTERVAL_MS);
  }

  #setTimer(callback, delay) {
    const timer = this.#scheduler.setTimeout(callback, delay);
    timer?.unref?.();
    return timer;
  }

  #cancelHealthCheck() {
    if (this.#healthTimer !== null) {
      this.#scheduler.clearTimeout(this.#healthTimer);
      this.#healthTimer = null;
    }
    try {
      this.#healthController?.abort();
    } catch {
      // Disconnect remains one-way if aborting a browser request fails.
    }
    this.#healthController = null;
  }

  #enqueue(operation) {
    if (this.#status !== "connected") return Promise.reject(disconnectedError());
    const lifecycle = this.#lifecycle;
    const result = this.#tail.then(async () => {
      this.#assertConnected(lifecycle);
      const value = await operation(lifecycle);
      this.#assertConnected(lifecycle);
      return value;
    });
    this.#tail = result.then(() => undefined, () => undefined);
    return result;
  }

  async #sendVaultCommand(command, lifecycle) {
    this.#assertConnected(lifecycle);
    if (!isObject(command) || typeof command.op !== "string" || command.op.length === 0) {
      throw new LanApiError("BAD_REQUEST", GENERIC_OPERATION_MESSAGE);
    }

    let plaintext;
    let requestCiphertext;
    try {
      plaintext = encoder.encode(JSON.stringify(command));
      const encrypted = await this.#session.encryptRequest({
        method: "POST",
        path: "/api/v1/vault",
        plaintext,
      });
      this.#assertConnected(lifecycle);
      const counter = encrypted?.counter;
      requestCiphertext = requireBytes(encrypted?.ciphertext, "request ciphertext");
      if (!Number.isSafeInteger(counter) || counter < 1) throw new TypeError("invalid request counter");
      const outerResponse = await this.#request("/api/v1/vault", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        signal: this.#controller.signal,
        body: JSON.stringify({
          v: 1,
          sessionId: this.#sessionId,
          counter,
          ciphertext: this.#crypto.encodeBase64Url(requestCiphertext),
        }),
      });
      this.#assertConnected(lifecycle);
      if (outerResponse.status === 401) {
        this.disconnect("DISCONNECTED");
        throw disconnectedError();
      }
      if (!outerResponse.ok) throw outerVaultError(outerResponse.status);

      const outerText = await this.#readBody(outerResponse);
      this.#assertConnected(lifecycle);
      let envelope;
      try {
        envelope = parseVaultEnvelope(
          outerText,
          this.#sessionId,
          this.#crypto,
        );
      } catch {
        this.disconnect("PROTOCOL");
        throw protocolError(true);
      }
      let decrypted;
      try {
        decrypted = await this.#session.decryptResponse({
          method: "POST",
          path: "/api/v1/vault",
          envelope,
        });
        this.#assertConnected(lifecycle);
      } catch {
        this.disconnect("DISCONNECTED");
        throw disconnectedError();
      } finally {
        this.#destroyBytes(envelope.ciphertext);
      }

      try {
        this.#assertConnected(lifecycle);
        const result = parseDecryptedResult(decrypted, command.op);
        if (!result.ok) throw businessError(result.error);
        this.#assertConnected(lifecycle);
        return result;
      } catch (error) {
        if (error instanceof LanApiError) {
          if (error.disconnect) this.disconnect(error.code);
          throw error;
        }
        this.disconnect("PROTOCOL");
        throw protocolError(true);
      } finally {
        this.#destroyBytes(decrypted);
      }
    } finally {
      this.#destroyBytes(plaintext, requestCiphertext);
    }
  }

  async #request(url, options) {
    try {
      return await this.#fetch(url, options);
    } catch {
      if (this.#status !== "disconnected") this.disconnect("DISCONNECTED");
      throw disconnectedError();
    }
  }

  async #readBody(response) {
    try {
      return await readResponseText(response);
    } catch {
      if (this.#status !== "disconnected") this.disconnect("DISCONNECTED");
      throw disconnectedError();
    }
  }

  #pairingOuterError(status) {
    if (status === 401) {
      return new LanApiError("UNAUTHORIZED", "访问码错误或已失效");
    }
    if (status === 429) {
      return new LanApiError("RATE_LIMITED", "操作过快，请稍后重试");
    }
    if (status === 400) return new LanApiError("BAD_REQUEST", GENERIC_OPERATION_MESSAGE);
    if (status >= 500) return new LanApiError("INTERNAL", GENERIC_OPERATION_MESSAGE);
    return protocolError(false);
  }

  #assertPairingActive() {
    if (this.#status !== "pairing") throw disconnectedError();
  }

  #assertConnected(lifecycle) {
    if (
      this.#status !== "connected"
      || this.#lifecycle !== lifecycle
      || this.#session === null
      || this.#sessionId === null
    ) {
      throw disconnectedError();
    }
  }

  #trackPairingBytes(...values) {
    for (const value of values) {
      if (value instanceof Uint8Array) this.#pairingBytes.add(value);
    }
  }

  #clearPairingBytes() {
    const bytes = [...this.#pairingBytes];
    this.#pairingBytes.clear();
    this.#destroyBytes(...bytes);
  }

  #destroyBytes(...bytes) {
    try {
      this.#crypto.destroyBytes(...bytes);
    } catch {
      // The client no longer retains the arrays even if injected cleanup fails.
    }
  }
}

function parsePairingInfo(text, crypto) {
  const value = parseJsonObject(text);
  requireExactKeys(value, ["v", "runId", "serverPublicKey"]);
  if (value.v !== 1) throw new TypeError("unsupported protocol version");
  let runId;
  let serverPublicKey;
  try {
    runId = crypto.decodeBase64Url(value.runId);
    serverPublicKey = crypto.decodeBase64Url(value.serverPublicKey);
    if (runId.length !== 32) throw new TypeError("live runId must contain 32 bytes");
    if (serverPublicKey.length !== 65 || serverPublicKey[0] !== 0x04) {
      throw new TypeError("invalid server public key");
    }
    return { runId, serverPublicKey };
  } catch (error) {
    destroyBytesSafely(crypto, runId, serverPublicKey);
    throw error;
  }
}

function pairingIdentity(info, crypto) {
  return Object.freeze({
    runId: crypto.encodeBase64Url(info.runId),
    serverPublicKey: crypto.encodeBase64Url(info.serverPublicKey),
  });
}

function samePairingIdentity(identity, info, crypto) {
  return identity !== null
    && identity.runId === crypto.encodeBase64Url(info.runId)
    && identity.serverPublicKey === crypto.encodeBase64Url(info.serverPublicKey);
}

function parsePairingReply(text, crypto) {
  const value = parseJsonObject(text);
  requireExactKeys(value, ["v", "nonce", "ciphertext"]);
  if (value.v !== 1) throw new TypeError("unsupported protocol version");
  let nonce;
  let ciphertext;
  try {
    nonce = crypto.decodeBase64Url(value.nonce);
    ciphertext = crypto.decodeBase64Url(value.ciphertext);
    if (nonce.length !== 12 || ciphertext.length < 16) throw new TypeError("invalid pairing reply");
    return { nonce, ciphertext };
  } catch (error) {
    destroyBytesSafely(crypto, nonce, ciphertext);
    throw error;
  }
}

function parsePairingSuccess(text) {
  const value = parseJsonObject(text);
  requireExactKeys(value, ["sessionId"]);
  if (typeof value.sessionId !== "string" || value.sessionId.length === 0) {
    throw new TypeError("invalid sessionId");
  }
  return value.sessionId;
}

function parseVaultEnvelope(text, sessionId, crypto) {
  const value = parseJsonObject(text);
  requireExactKeys(value, ["v", "sessionId", "counter", "ciphertext"]);
  if (
    value.v !== 1
    || value.sessionId !== sessionId
    || !Number.isSafeInteger(value.counter)
    || value.counter < 1
  ) {
    throw new TypeError("invalid vault envelope");
  }
  return { counter: value.counter, ciphertext: crypto.decodeBase64Url(value.ciphertext) };
}

function parseDecryptedResult(plaintext, operation) {
  const value = parseJsonObject(decoder.decode(requireBytes(plaintext, "decrypted response")));
  if (value.ok === false) {
    requireExactKeys(value, ["ok", "error"]);
    if (typeof value.error !== "string") throw new TypeError("invalid business error");
    if (value.error === "UNAUTHORIZED" || value.error === "DISCONNECTED") {
      throw disconnectedError();
    }
    if (!Object.hasOwn(BUSINESS_MESSAGES, value.error)) {
      throw new TypeError("unknown business error");
    }
    return value;
  }
  if (value.ok !== true) throw new TypeError("invalid success response");
  if (operation === "snapshot") {
    requireExactKeys(value, ["ok", "snapshot"]);
    validateSnapshotWireShape(value.snapshot);
    return { ok: true, snapshot: normalizeSnapshot(value.snapshot) };
  }

  const resultKey = mutationResultKey(operation);
  if (resultKey === null) {
    requireExactKeys(value, ["ok"]);
    return value;
  }
  requireExactKeys(value, ["ok", resultKey]);
  validateMutationEntity(resultKey, value[resultKey]);
  return value;
}

function mutationResultKey(operation) {
  if (operation === "credential.create" || operation === "credential.update") return "credential";
  if (operation === "category.create" || operation === "category.rename") return "category";
  if (operation === "tag.create" || operation === "tag.rename") return "tag";
  if (
    operation === "credential.delete"
    || operation === "category.delete"
    || operation === "tag.delete"
  ) {
    return null;
  }
  throw new TypeError("unknown vault operation");
}

function validateMutationEntity(kind, entity) {
  if (kind === "credential") {
    requireObjectWithKeys(entity, [
      "id", "name", "account", "password", "url", "categoryId", "tagIds", "notes",
      "version", "createdAt", "updatedAt",
    ]);
    normalizeSnapshot({ revision: 0, credentials: [entity], categories: [], tags: [] });
  } else if (kind === "category") {
    requireObjectWithKeys(entity, ["id", "name", "version"]);
    normalizeSnapshot({ revision: 0, credentials: [], categories: [entity], tags: [] });
  } else {
    requireObjectWithKeys(entity, ["id", "name", "version"]);
    normalizeSnapshot({ revision: 0, credentials: [], categories: [], tags: [entity] });
  }
}

function validateSnapshotWireShape(value) {
  requireObjectWithKeys(value, ["revision", "credentials", "categories", "tags"]);
  if (!Array.isArray(value.credentials) || !Array.isArray(value.categories) || !Array.isArray(value.tags)) {
    throw new TypeError("invalid snapshot collections");
  }
  for (const credential of value.credentials) {
    requireObjectWithKeys(credential, [
      "id", "name", "account", "password", "url", "categoryId", "tagIds", "notes",
      "version", "createdAt", "updatedAt",
    ]);
  }
  for (const category of value.categories) {
    requireObjectWithKeys(category, ["id", "name", "version"]);
  }
  for (const tag of value.tags) {
    requireObjectWithKeys(tag, ["id", "name", "version"]);
  }
}

function businessError(code) {
  return new LanApiError(code, BUSINESS_MESSAGES[code]);
}

function outerVaultError(status) {
  if (status === 400) return new LanApiError("BAD_REQUEST", GENERIC_OPERATION_MESSAGE);
  if (status >= 500) return new LanApiError("INTERNAL", GENERIC_OPERATION_MESSAGE);
  return new LanApiError("BAD_REQUEST", GENERIC_OPERATION_MESSAGE);
}

function disconnectedError() {
  return new LanApiError("DISCONNECTED", DISCONNECTED_MESSAGE, { disconnect: true });
}

function protocolError(disconnect) {
  return new LanApiError("PROTOCOL", PROTOCOL_MESSAGE, { disconnect });
}

async function readResponseText(response) {
  if (
    response === null
    || typeof response !== "object"
    || !Number.isInteger(response.status)
    || typeof response.ok !== "boolean"
    || typeof response.text !== "function"
  ) {
    throw new TypeError("invalid HTTP response");
  }
  return response.text();
}

function parseJsonObject(text) {
  if (typeof text !== "string") throw new TypeError("JSON response must be text");
  const value = JSON.parse(text);
  if (!isObject(value)) throw new TypeError("JSON response must be an object");
  return value;
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requireExactKeys(value, expected) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new TypeError("unexpected response shape");
  }
}

function requireObjectWithKeys(value, expected) {
  if (!isObject(value)) throw new TypeError("response value must be an object");
  requireExactKeys(value, expected);
}

function requireBytes(value, name) {
  if (!(value instanceof Uint8Array)) throw new TypeError(`${name} must be a byte array`);
  return value;
}

function requireBytesLength(value, length, name) {
  const bytes = requireBytes(value, name);
  if (bytes.length !== length) throw new TypeError(`${name} must contain ${length} bytes`);
  return bytes;
}

function destroyBytesSafely(crypto, ...values) {
  try {
    crypto.destroyBytes(...values);
  } catch {
    // Cleanup failures must not replace the protocol or transport error.
  }
}
