import assert from "node:assert/strict";
import test from "node:test";

import {
  LanApiError,
  LanVaultClient,
} from "../app/src/main/assets/web/lan-client.mjs";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function encodeBytes(value) {
  return Buffer.from(value).toString("base64url");
}

function decodeBytes(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) {
    throw new TypeError("invalid base64url");
  }
  const bytes = Uint8Array.from(Buffer.from(value, "base64url"));
  if (encodeBytes(bytes) !== value) throw new TypeError("invalid base64url");
  return bytes;
}

function jsonBytes(value) {
  return encoder.encode(JSON.stringify(value));
}

function parseJsonBytes(value) {
  return JSON.parse(decoder.decode(value));
}

function snapshot(revision) {
  return {
    revision,
    credentials: [],
    categories: [],
    tags: [],
  };
}

function validPublicKey(length = 65) {
  const value = new Uint8Array(length);
  if (length > 0) value[0] = 0x04;
  return value;
}

function assertExactKeys(value, keys) {
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort());
}

function response(status, body, contentType = "application/json") {
  const text = contentType === "application/json" ? JSON.stringify(body) : String(body);
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers({ "Content-Type": contentType }),
    async text() {
      return text;
    },
  };
}

function rejectingBodyResponse(error) {
  const value = response(200, {});
  value.text = async () => { throw error; };
  return value;
}

function abortError() {
  return new DOMException("The operation was aborted", "AbortError");
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function createFakeScheduler() {
  let now = 0;
  let nextId = 1;
  const timers = new Map();
  return {
    setTimeout(callback, delay) {
      const id = nextId++;
      timers.set(id, { callback, due: now + delay });
      return id;
    },
    clearTimeout(id) {
      timers.delete(id);
    },
    async advance(delay) {
      now += delay;
      for (;;) {
        const due = [...timers.entries()].find(([, timer]) => timer.due <= now);
        if (!due) return;
        timers.delete(due[0]);
        due[1].callback();
        await Promise.resolve();
      }
    },
    get size() {
      return timers.size;
    },
  };
}

async function waitUntil(predicate) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error("condition was not reached");
}

function createFakeCrypto() {
  const ephemeralBytes = [];
  const sessions = [];

  class FakeSession {
    #sessionId;
    #clientToServerKey;
    #serverToClientKey;
    #nextCounter = 1;
    #lastResponseCounter = 0;
    #destroyed = false;

    constructor({ sessionId, clientToServerKey, serverToClientKey }) {
      this.#sessionId = sessionId;
      this.#clientToServerKey = clientToServerKey.slice();
      this.#serverToClientKey = serverToClientKey.slice();
      this.ownedKeys = [this.#clientToServerKey, this.#serverToClientKey];
      sessions.push(this);
    }

    async encryptRequest({ method, path, plaintext }) {
      if (this.#destroyed) throw new Error("LAN crypto session is destroyed");
      assert.equal(method, "POST");
      assert.equal(path, "/api/v1/vault");
      const counter = this.#nextCounter;
      this.#nextCounter += 1;
      return { counter, ciphertext: Uint8Array.from(plaintext) };
    }

    async decryptResponse({ method, path, envelope }) {
      if (this.#destroyed) throw new Error("LAN crypto session is destroyed");
      assert.equal(method, "POST");
      assert.equal(path, "/api/v1/vault");
      if (
        !Number.isSafeInteger(envelope?.counter)
        || envelope.counter <= this.#lastResponseCounter
        || envelope.counter >= this.#nextCounter
      ) {
        throw new Error("response counter is replayed or was not requested");
      }
      if (decoder.decode(envelope.ciphertext) === "DECRYPT_FAILURE") {
        throw new Error("authentication failed");
      }
      this.#lastResponseCounter = envelope.counter;
      return Uint8Array.from(envelope.ciphertext);
    }

    destroy() {
      if (this.#destroyed) return;
      this.#destroyed = true;
      this.#clientToServerKey.fill(0);
      this.#serverToClientKey.fill(0);
    }

    get destroyed() {
      return this.#destroyed;
    }

    get sessionId() {
      return this.#sessionId;
    }
  }

  function tracked(length, fill) {
    const value = new Uint8Array(length).fill(fill);
    ephemeralBytes.push(value);
    return value;
  }

  return {
    ephemeralBytes,
    sessions,
    encodeBase64Url: encodeBytes,
    decodeBase64Url: decodeBytes,
    generateClientKeyPair() {
      const publicKey = tracked(65, 0x22);
      publicKey[0] = 0x04;
      return { privateKey: tracked(32, 0x11), publicKey };
    },
    async deriveSharedSecret(privateKey, publicKey) {
      assert.equal(privateKey.length, 32);
      assert.equal(publicKey.length, 65);
      return tracked(32, 0x33);
    },
    async encryptPairingCode({ sharedSecret, runId, serverPublic, clientPublic, accessCode }) {
      assert.equal(sharedSecret.length, 32);
      assert.equal(runId.length, 32);
      assert.equal(serverPublic.length, 65);
      assert.equal(clientPublic.length, 65);
      assert.match(accessCode, /^\d{6}$/);
      return { nonce: tracked(12, 0x44), ciphertext: tracked(22, 0x55) };
    },
    async decryptPairingReply({ sharedSecret, runId, serverPublic, clientPublic, nonce, ciphertext }) {
      assert.equal(sharedSecret.length, 32);
      assert.equal(runId.length, 32);
      assert.equal(serverPublic.length, 65);
      assert.equal(clientPublic.length, 65);
      assert.equal(nonce.length, 12);
      return decoder.decode(ciphertext);
    },
    async deriveSessionKeys(sharedSecret, runId) {
      assert.equal(sharedSecret.length, 32);
      assert.equal(runId.length, 32);
      return {
        handshakeKey: tracked(32, 0x66),
        clientToServerKey: tracked(32, 0x77),
        serverToClientKey: tracked(32, 0x88),
      };
    },
    destroyBytes(...values) {
      for (const value of values) {
        if (value instanceof Uint8Array) value.fill(0);
      }
    },
    LanClientCryptoSession: FakeSession,
  };
}

class FakeLanServer {
  constructor() {
    this.runId = new Uint8Array(32).fill(0xa1);
    this.serverPublicKey = new Uint8Array(65).fill(0xb2);
    this.serverPublicKey[0] = 0x04;
    this.sessionId = "session-1";
    this.revision = 0;
    this.operations = [];
    this.counters = [];
    this.vaultBodies = [];
    this.pairingSubmits = [];
    this.pairingInfoRequests = 0;
    this.maxConcurrentVaultRequests = 0;
    this.concurrentVaultRequests = 0;
    this.infoResponse = null;
    this.submitResponse = null;
    this.nextBusinessError = null;
    this.nextOuter = null;
    this.nextEnvelope = null;
    this.nextPlaintext = null;
    this.nextNetworkError = null;
    this.blockNextVault = null;
    this.blockNextPairingInfo = null;
  }

  fetch = async (url, options = {}) => {
    if (options.signal?.aborted) throw abortError();
    if (this.nextNetworkError) {
      const error = this.nextNetworkError;
      this.nextNetworkError = null;
      throw error;
    }
    if (url === "/api/v1/pairing-info") return this.#pairingInfo(options);
    if (url === "/api/v1/pairing-submit") return this.#pairingSubmit(options);
    if (url === "/api/v1/vault") return this.#vault(options);
    throw new Error(`unexpected URL ${url}`);
  };

  async #pairingInfo(options) {
    assertExactKeys(options, ["method", "signal"]);
    assert.equal(options.method, "GET");
    this.pairingInfoRequests += 1;
    if (this.blockNextPairingInfo) {
      const gate = this.blockNextPairingInfo;
      this.blockNextPairingInfo = null;
      await new Promise((resolve, reject) => {
        const onAbort = () => reject(abortError());
        options.signal.addEventListener("abort", onAbort, { once: true });
        gate.promise.then(resolve, reject).finally(() => {
          options.signal.removeEventListener("abort", onAbort);
        });
      });
    }
    if (this.infoResponse) return this.infoResponse;
    return response(200, {
      v: 1,
      runId: encodeBytes(this.runId),
      serverPublicKey: encodeBytes(this.serverPublicKey),
    });
  }

  #pairingSubmit(options) {
    assert.equal(options.method, "POST");
    assert.equal(options.headers["Content-Type"], "application/json");
    assert.ok(options.signal instanceof AbortSignal);
    const body = JSON.parse(options.body);
    assertExactKeys(body, ["v", "clientPublicKey", "nonce", "ciphertext"]);
    assert.equal(body.v, 1);
    assert.equal(decodeBytes(body.clientPublicKey).length, 65);
    assert.equal(decodeBytes(body.nonce).length, 12);
    assert.equal(decodeBytes(body.ciphertext).length, 22);
    this.pairingSubmits.push(body);
    if (this.submitResponse) return this.submitResponse;
    return response(200, {
      v: 1,
      nonce: encodeBytes(new Uint8Array(12).fill(0xc3)),
      ciphertext: encodeBytes(jsonBytes({ sessionId: this.sessionId })),
    });
  }

  async #vault(options) {
    assert.equal(options.method, "POST");
    assert.equal(options.headers["Content-Type"], "application/json");
    assert.ok(options.signal instanceof AbortSignal);
    const body = JSON.parse(options.body);
    assertExactKeys(body, ["v", "sessionId", "counter", "ciphertext"]);
    assert.equal(body.v, 1);
    assert.equal(body.sessionId, this.sessionId);
    assert.equal(typeof body.ciphertext, "string");
    assert.doesNotMatch(body.ciphertext, /=/);
    const command = parseJsonBytes(decodeBytes(body.ciphertext));
    assert.equal(typeof command.op, "string");
    this.operations.push(command.op);
    this.counters.push(body.counter);
    this.vaultBodies.push(body);
    this.concurrentVaultRequests += 1;
    this.maxConcurrentVaultRequests = Math.max(
      this.maxConcurrentVaultRequests,
      this.concurrentVaultRequests,
    );
    try {
      if (this.blockNextVault) {
        const gate = this.blockNextVault;
        this.blockNextVault = null;
        await new Promise((resolve, reject) => {
          const onAbort = () => reject(abortError());
          options.signal.addEventListener("abort", onAbort, { once: true });
          gate.promise.then(resolve, reject).finally(() => {
            options.signal.removeEventListener("abort", onAbort);
          });
        });
      }
      if (this.nextOuter) {
        const outer = this.nextOuter;
        this.nextOuter = null;
        return outer;
      }
      let plaintext;
      if (this.nextPlaintext !== null) {
        plaintext = this.nextPlaintext;
        this.nextPlaintext = null;
      } else if (this.nextBusinessError) {
        plaintext = { ok: false, error: this.nextBusinessError };
        this.nextBusinessError = null;
      } else if (command.op === "snapshot") {
        plaintext = { ok: true, snapshot: snapshot(this.revision) };
      } else {
        this.revision += 1;
        plaintext = mutationReply(command);
      }
      const envelope = this.nextEnvelope ?? {
        v: 1,
        sessionId: this.sessionId,
        counter: body.counter,
        ciphertext: encodeBytes(jsonBytes(plaintext)),
      };
      this.nextEnvelope = null;
      return response(200, envelope);
    } finally {
      this.concurrentVaultRequests -= 1;
    }
  }
}

function mutationReply(command) {
  if (command.op === "credential.create" || command.op === "credential.update") {
    return {
      ok: true,
      credential: {
        id: command.id ?? "credential-1",
        name: command.name ?? "Example",
        account: command.account ?? null,
        password: command.password ?? "secret",
        url: command.url ?? null,
        categoryId: command.categoryId ?? null,
        tagIds: command.tagIds ?? [],
        notes: command.notes ?? null,
        version: 1,
        createdAt: 1,
        updatedAt: 1,
      },
    };
  }
  if (command.op === "category.create" || command.op === "category.rename") {
    return { ok: true, category: { id: command.id ?? "category-1", name: command.name, version: 1 } };
  }
  if (command.op === "tag.create" || command.op === "tag.rename") {
    return { ok: true, tag: { id: command.id ?? "tag-1", name: command.name, version: 1 } };
  }
  return { ok: true };
}

function fixture(onDisconnect = () => {}, options = {}) {
  const server = new FakeLanServer();
  const crypto = createFakeCrypto();
  const client = new LanVaultClient({
    fetchImpl: server.fetch,
    cryptoImpl: crypto,
    onDisconnect,
    ...options,
  });
  return { client, crypto, server };
}

async function pairedFixture(onDisconnect = () => {}, options = {}) {
  const value = fixture(onDisconnect, options);
  await value.client.pair("123456");
  return value;
}

test("pairs with full wire envelopes, fetches the initial snapshot, and clears pairing bytes", async () => {
  const { client, crypto, server } = fixture();

  const paired = await client.pair("123456");

  assert.deepEqual(paired, snapshot(0));
  assert.equal(client.status, "connected");
  assert.deepEqual(client.snapshot, snapshot(0));
  assert.equal(server.pairingSubmits.length, 1);
  assert.deepEqual(server.operations, ["snapshot"]);
  assert.deepEqual(server.counters, [1]);
  assert.equal(crypto.sessions.length, 1);
  assert.equal(crypto.sessions[0].sessionId, server.sessionId);
  for (const bytes of crypto.ephemeralBytes) {
    assert.ok(bytes.every((byte) => byte === 0), "all controllable pairing bytes are wiped");
  }
});

test("disconnects an idle paired client when its scheduled health check cannot reach the phone", async () => {
  const scheduler = createFakeScheduler();
  const reasons = [];
  const { client, server } = await pairedFixture((reason) => reasons.push(reason), { scheduler });

  server.nextNetworkError = new TypeError("phone stopped");
  await scheduler.advance(5_000);
  await waitUntil(() => client.status === "disconnected");

  assert.equal(client.snapshot, null);
  assert.deepEqual(reasons, ["DISCONNECTED"]);
  assert.equal(server.operations.length, 1, "health check must not send a vault command");
});

test("disconnects when a health response identifies a new server run at the same address", async () => {
  const scheduler = createFakeScheduler();
  const { client, server } = await pairedFixture(() => {}, { scheduler });
  server.runId = new Uint8Array(32).fill(0xe1);

  await scheduler.advance(5_000);
  await waitUntil(() => client.status === "disconnected");

  assert.equal(client.snapshot, null);
  assert.equal(server.operations.length, 1, "health check must not allocate a vault counter");
});

test("disconnects on non-success or malformed health metadata", async () => {
  for (const infoResponse of [
    response(503, "stopped", "text/plain"),
    response(200, { v: 1, runId: encodeBytes(new Uint8Array(31)), serverPublicKey: encodeBytes(validPublicKey()) }),
  ]) {
    const scheduler = createFakeScheduler();
    const { client, server } = await pairedFixture(() => {}, { scheduler });
    server.infoResponse = infoResponse;

    await scheduler.advance(5_000);
    await waitUntil(() => client.status === "disconnected");
    assert.equal(client.snapshot, null);
    assert.equal(server.operations.length, 1);
  }
});

test("aborts a hung health request at its timeout and does not schedule a replacement after disconnect", async () => {
  const scheduler = createFakeScheduler();
  const { client, server } = await pairedFixture(() => {}, { scheduler });
  const gate = deferred();
  server.blockNextPairingInfo = gate;

  await scheduler.advance(5_000);
  await scheduler.advance(5_000);
  await waitUntil(() => client.status === "disconnected");

  assert.equal(client.snapshot, null);
  assert.equal(scheduler.size, 0);
});

test("shares an in-flight visible health check and cannot revive timers after disconnect", async () => {
  const scheduler = createFakeScheduler();
  const { client, server } = await pairedFixture(() => {}, { scheduler });
  const gate = deferred();
  server.blockNextPairingInfo = gate;

  const first = client.checkHealth();
  const second = client.checkHealth();
  assert.strictEqual(second, first);
  await waitUntil(() => server.pairingInfoRequests === 2);
  client.disconnect("PAGEHIDE");
  gate.resolve();

  await assert.rejects(first, { code: "DISCONNECTED" });
  assert.equal(client.status, "disconnected");
  assert.equal(scheduler.size, 0);
  assert.equal(server.pairingInfoRequests, 2);
});

test("rejects malformed pairing metadata including non-32-byte live run IDs and returns to idle", async () => {
  const cases = [
    { v: 1, runId: encodeBytes(new Uint8Array(16)), serverPublicKey: encodeBytes(validPublicKey()) },
    { v: 1, runId: encodeBytes(new Uint8Array(31)), serverPublicKey: encodeBytes(validPublicKey()) },
    { v: 1, runId: encodeBytes(new Uint8Array(33)), serverPublicKey: encodeBytes(validPublicKey()) },
    { v: 2, runId: encodeBytes(new Uint8Array(32)), serverPublicKey: encodeBytes(validPublicKey()) },
    { v: 1, runId: "AA=", serverPublicKey: encodeBytes(validPublicKey()) },
    { v: 1, runId: encodeBytes(new Uint8Array(32)), serverPublicKey: encodeBytes(validPublicKey(64)) },
    { v: 1, runId: encodeBytes(new Uint8Array(32)), serverPublicKey: encodeBytes(validPublicKey()), extra: true },
  ];

  for (const metadata of cases) {
    let disconnects = 0;
    const { client, server } = fixture(() => { disconnects += 1; });
    server.infoResponse = response(200, metadata);

    await assert.rejects(client.pair("123456"), {
      name: "LanApiError",
      code: "PROTOCOL",
      message: "手机返回了无效响应",
      disconnect: false,
    });
    assert.equal(client.status, "idle");
    assert.equal(client.snapshot, null);
    assert.equal(server.pairingSubmits.length, 0);
    assert.equal(disconnects, 0);
  }
});

test("wipes partially produced pairing bytes when later schema or key validation fails", async () => {
  {
    const { client, crypto, server } = fixture();
    const decoded = [];
    const originalDecode = crypto.decodeBase64Url;
    crypto.decodeBase64Url = (value) => {
      const bytes = originalDecode(value);
      decoded.push(bytes);
      return bytes;
    };
    server.infoResponse = response(200, {
      v: 1,
      runId: encodeBytes(new Uint8Array(32).fill(1)),
      serverPublicKey: encodeBytes(validPublicKey(64)),
    });

    await assert.rejects(client.pair("123456"), { code: "PROTOCOL" });
    assert.equal(decoded.length, 2);
    for (const bytes of decoded) assert.ok(bytes.every((byte) => byte === 0));
  }

  {
    const { client, crypto } = fixture();
    const handshakeKey = new Uint8Array(32).fill(9);
    crypto.ephemeralBytes.push(handshakeKey);
    crypto.deriveSessionKeys = async () => ({
      handshakeKey,
      clientToServerKey: "invalid",
      serverToClientKey: new Uint8Array(32).fill(8),
    });

    await assert.rejects(client.pair("123456"), { code: "PROTOCOL", disconnect: true });
    assert.ok(handshakeKey.every((byte) => byte === 0));
  }
});

test("registers every composite crypto sibling before exact validation and wipes all byte arrays", async () => {
  const cases = [
    {
      configure(crypto) {
        const publicKey = validPublicKey();
        crypto.ephemeralBytes.push(publicKey);
        crypto.generateClientKeyPair = () => ({ privateKey: "invalid", publicKey });
      },
      expectedStage: "idle",
    },
    {
      configure(crypto) {
        const privateKey = new Uint8Array(31).fill(1);
        const publicKey = validPublicKey();
        crypto.ephemeralBytes.push(privateKey, publicKey);
        crypto.generateClientKeyPair = () => ({ privateKey, publicKey });
        crypto.deriveSharedSecret = async () => {
          assert.fail("invalid client key length must be rejected before ECDH");
        };
      },
      expectedStage: "idle",
    },
    {
      configure(crypto) {
        const ciphertext = new Uint8Array(22).fill(2);
        crypto.ephemeralBytes.push(ciphertext);
        crypto.encryptPairingCode = async () => ({ nonce: "invalid", ciphertext });
      },
      expectedStage: "idle",
    },
    {
      configure(crypto) {
        const nonce = new Uint8Array(12).fill(3);
        const ciphertext = new Uint8Array(21).fill(4);
        crypto.ephemeralBytes.push(nonce, ciphertext);
        crypto.encryptPairingCode = async () => ({ nonce, ciphertext });
      },
      expectedStage: "idle",
    },
    {
      configure(crypto) {
        const handshakeKey = new Uint8Array(32).fill(5);
        const serverToClientKey = new Uint8Array(32).fill(6);
        crypto.ephemeralBytes.push(handshakeKey, serverToClientKey);
        crypto.deriveSessionKeys = async () => ({
          handshakeKey,
          clientToServerKey: "invalid",
          serverToClientKey,
        });
      },
      expectedStage: "disconnected",
    },
    {
      configure(crypto) {
        const clientToServerKey = new Uint8Array(32).fill(7);
        const serverToClientKey = new Uint8Array(32).fill(8);
        crypto.ephemeralBytes.push(clientToServerKey, serverToClientKey);
        crypto.deriveSessionKeys = async () => ({
          handshakeKey: "invalid",
          clientToServerKey,
          serverToClientKey,
        });
      },
      expectedStage: "disconnected",
    },
  ];

  for (const { configure, expectedStage } of cases) {
    const { client, crypto } = fixture();
    configure(crypto);
    await assert.rejects(client.pair("123456"), { code: "PROTOCOL" });
    assert.equal(client.status, expectedStage);
    for (const bytes of crypto.ephemeralBytes) {
      assert.ok(bytes.every((byte) => byte === 0), "every returned sibling must be wiped");
    }
  }
});

test("maps pairing 401 and 429 to exact non-sensitive messages and permits retry", async () => {
  for (const [status, body, code, message] of [
    [401, "UNAUTHORIZED: attempts=4", "UNAUTHORIZED", "访问码错误或已失效"],
    [429, "RATE_LIMITED: retry=500", "RATE_LIMITED", "操作过快，请稍后重试"],
  ]) {
    const { client, server } = fixture();
    server.submitResponse = response(status, body, "text/plain");

    await assert.rejects(client.pair("123456"), {
      name: "LanApiError",
      code,
      message,
      disconnect: false,
    });
    assert.equal(client.status, "idle");
    server.submitResponse = null;
    assert.deepEqual(await client.pair("123456"), snapshot(0));
  }
});

test("serializes mutations, assigns counters inside the queue, and snapshots after each success", async () => {
  const { client, server } = await pairedFixture();
  const gate = deferred();
  server.blockNextVault = gate;

  const first = client.mutate({ op: "category.create", name: "工作" });
  const second = client.mutate({ op: "tag.create", name: "常用" });
  await waitUntil(() => server.operations.length === 2);
  assert.deepEqual(server.operations, ["snapshot", "category.create"]);
  gate.resolve();
  const [firstSnapshot, secondSnapshot] = await Promise.all([first, second]);

  assert.equal(server.maxConcurrentVaultRequests, 1);
  assert.deepEqual(server.operations, [
    "snapshot", "category.create", "snapshot", "tag.create", "snapshot",
  ]);
  assert.deepEqual(server.counters, [1, 2, 3, 4, 5]);
  assert.equal(firstSnapshot.revision, 1);
  assert.equal(secondSnapshot.revision, 2);
  assert.equal(client.snapshot.revision, 2);
});

test("serializes concurrent refreshes with counters 1, 2, 3", async () => {
  const { client, server } = fixture();
  const pairing = client.pair("123456");
  await pairing;

  await Promise.all([client.refreshSnapshot(), client.refreshSnapshot()]);

  assert.deepEqual(server.operations, ["snapshot", "snapshot", "snapshot"]);
  assert.deepEqual(server.counters, [1, 2, 3]);
  assert.equal(server.maxConcurrentVaultRequests, 1);
});

test("maps every encrypted business error and does not auto-refresh or poison the queue", async () => {
  const { client, server } = await pairedFixture();
  const cases = [
    ["VALIDATION", "输入内容不符合要求"],
    ["NOT_FOUND", "请求的内容已不存在"],
    ["STALE_VERSION", "记录已变化，请刷新后重试"],
    ["BAD_REQUEST", "操作失败，请稍后重试"],
    ["INTERNAL", "操作失败，请稍后重试"],
  ];

  for (const [code, message] of cases) {
    const before = server.operations.length;
    server.nextBusinessError = code;
    await assert.rejects(client.mutate({ op: "category.create", name: code }), {
      name: "LanApiError",
      code,
      message,
      disconnect: false,
    });
    assert.equal(server.operations.length, before + 1, `${code} must not trigger snapshot`);
    assert.equal(client.status, "connected");
  }

  assert.deepEqual(await client.refreshSnapshot(), snapshot(0));
});

test("disconnects immediately for vault outer 401 responses regardless of body", async () => {
  for (const body of ["DISCONNECTED", "UNAUTHORIZED", "server detail must not leak"]) {
    const reasons = [];
    const { client, server, crypto } = await pairedFixture((reason) => reasons.push(reason));
    server.nextOuter = response(401, body, "text/plain");

    await assert.rejects(client.refreshSnapshot(), {
      name: "LanApiError",
      code: "DISCONNECTED",
      message: "与手机连接已断开，请在手机重新开启 PC 访问",
      disconnect: true,
    });
    assert.equal(client.status, "disconnected");
    assert.equal(client.snapshot, null);
    assert.deepEqual(reasons, ["DISCONNECTED"]);
    assert.equal(crypto.sessions[0].destroyed, true);
    for (const key of crypto.sessions[0].ownedKeys) assert.ok(key.every((byte) => byte === 0));
  }
});

test("disconnects on network and abort failures without exposing transport details", async () => {
  for (const error of [new TypeError("192.168.1.2 refused secret route"), abortError()]) {
    const reasons = [];
    const { client, server } = await pairedFixture((reason) => reasons.push(reason));
    server.nextNetworkError = error;

    await assert.rejects(client.refreshSnapshot(), (failure) => {
      assert.ok(failure instanceof LanApiError);
      assert.equal(failure.code, "DISCONNECTED");
      assert.equal(failure.disconnect, true);
      assert.doesNotMatch(failure.message, /192\.168|secret|Abort/i);
      return true;
    });
    assert.equal(client.status, "disconnected");
    assert.deepEqual(reasons, ["DISCONNECTED"]);
  }
});

test("treats response body rejection as a disconnecting transport failure at every endpoint", async () => {
  {
    const { client, server } = fixture();
    server.infoResponse = rejectingBodyResponse(new TypeError("body socket failed"));
    await assert.rejects(client.pair("123456"), {
      name: "LanApiError", code: "DISCONNECTED", disconnect: true,
    });
    assert.equal(client.status, "disconnected");
  }

  {
    const { client, server } = fixture();
    server.submitResponse = rejectingBodyResponse(abortError());
    await assert.rejects(client.pair("123456"), {
      name: "LanApiError", code: "DISCONNECTED", disconnect: true,
    });
    assert.equal(client.status, "disconnected");
  }

  {
    const { client, server } = await pairedFixture();
    server.nextOuter = rejectingBodyResponse(new TypeError("truncated body"));
    await assert.rejects(client.refreshSnapshot(), {
      name: "LanApiError", code: "DISCONNECTED", disconnect: true,
    });
    assert.equal(client.status, "disconnected");
  }
});

test("disconnects on decrypt failure and replayed response counters", async () => {
  for (const envelope of [
    {
      v: 1,
      sessionId: "session-1",
      counter: 2,
      ciphertext: encodeBytes(encoder.encode("DECRYPT_FAILURE")),
    },
    {
      v: 1,
      sessionId: "session-1",
      counter: 1,
      ciphertext: encodeBytes(jsonBytes({ ok: true, snapshot: snapshot(0) })),
    },
  ]) {
    const { client, server } = await pairedFixture();
    server.nextEnvelope = envelope;

    await assert.rejects(client.refreshSnapshot(), {
      name: "LanApiError",
      code: "DISCONNECTED",
      disconnect: true,
    });
    assert.equal(client.status, "disconnected");
  }
});

test("treats malformed connected envelopes and decrypted payloads as disconnecting protocol failures", async () => {
  const cases = [
    { envelope: { v: 1, sessionId: "session-1", counter: 2, ciphertext: "AA=", extra: true } },
    { plaintext: { ok: true, snapshot: snapshot(0), extra: true } },
    { plaintext: { ok: true, snapshot: { ...snapshot(0), serverOnly: "unexpected" } } },
    { plaintext: { ok: false, error: "SERVER_STACK:password" } },
  ];
  for (const value of cases) {
    const { client, server } = await pairedFixture();
    if (value.envelope) server.nextEnvelope = value.envelope;
    if (value.plaintext) server.nextPlaintext = value.plaintext;

    await assert.rejects(client.refreshSnapshot(), (error) => {
      assert.ok(error instanceof LanApiError);
      assert.equal(error.code, "PROTOCOL");
      assert.equal(error.message, "手机返回了无效响应");
      assert.equal(error.disconnect, true);
      assert.doesNotMatch(error.message, /password|STACK/);
      return true;
    });
    assert.equal(client.status, "disconnected");
  }
});

test("malformed authenticated pairing replies and pairing decrypt failures cross the disconnect boundary", async () => {
  for (const reply of [
    { v: 1, nonce: encodeBytes(new Uint8Array(12)), ciphertext: "AA=", extra: true },
    {
      v: 1,
      nonce: encodeBytes(new Uint8Array(12)),
      ciphertext: encodeBytes(encoder.encode("not-json")),
    },
  ]) {
    let disconnects = 0;
    const { client, server } = fixture(() => { disconnects += 1; });
    server.submitResponse = response(200, reply);

    await assert.rejects(client.pair("123456"), {
      name: "LanApiError",
      code: "PROTOCOL",
      disconnect: true,
    });
    assert.equal(client.status, "disconnected");
    assert.equal(disconnects, 1);
  }
});

test("disconnect is idempotent, clears state, invokes its callback once, and rejects future work", async () => {
  const reasons = [];
  const { client, crypto } = await pairedFixture((reason) => reasons.push(reason));

  client.disconnect("PAGEHIDE");
  client.disconnect("SECOND_REASON");

  assert.equal(client.status, "disconnected");
  assert.equal(client.snapshot, null);
  assert.deepEqual(reasons, ["PAGEHIDE"]);
  assert.equal(crypto.sessions[0].destroyed, true);
  await assert.rejects(client.refreshSnapshot(), {
    name: "LanApiError",
    code: "DISCONNECTED",
    disconnect: true,
  });
  await assert.rejects(client.mutate({ op: "tag.create", name: "later" }), {
    name: "LanApiError",
    code: "DISCONNECTED",
    disconnect: true,
  });
  await assert.rejects(client.pair("123456"), {
    name: "LanApiError",
    code: "DISCONNECTED",
    disconnect: true,
  });
});

test("throwing disconnect callbacks cannot replace network errors or prevent active and queued rejection", async () => {
  let callbackCalls = 0;
  const { client, crypto, server } = await pairedFixture(() => {
    callbackCalls += 1;
    throw new Error("callback failure");
  });
  const originalDestroyBytes = crypto.destroyBytes;
  crypto.destroyBytes = (...values) => {
    originalDestroyBytes(...values);
    throw new Error("temporary byte cleanup failure");
  };
  server.nextNetworkError = new TypeError("network failed");

  const active = client.refreshSnapshot();
  const queued = client.mutate({ op: "tag.create", name: "queued" });

  await assert.rejects(active, {
    name: "LanApiError", code: "DISCONNECTED", disconnect: true,
  });
  await assert.rejects(queued, {
    name: "LanApiError", code: "DISCONNECTED", disconnect: true,
  });
  assert.equal(client.status, "disconnected");
  assert.equal(client.snapshot, null);
  assert.equal(callbackCalls, 1);
  assert.equal(crypto.sessions[0].destroyed, true);
  for (const key of crypto.sessions[0].ownedKeys) assert.ok(key.every((byte) => byte === 0));
  assert.doesNotThrow(() => client.disconnect("SECOND"));
  assert.equal(callbackCalls, 1);
});

test("disconnect attempts every cleanup step even when injected cleanup throws", async () => {
  let callbackCalls = 0;
  const { client, crypto } = await pairedFixture(() => { callbackCalls += 1; });
  const session = crypto.sessions[0];
  const originalDestroy = session.destroy.bind(session);
  session.destroy = () => {
    originalDestroy();
    throw new Error("session cleanup failed");
  };
  const originalDestroyBytes = crypto.destroyBytes;
  let byteCleanupCalls = 0;
  crypto.destroyBytes = (...values) => {
    byteCleanupCalls += 1;
    originalDestroyBytes(...values);
    throw new Error("byte cleanup failed");
  };

  assert.doesNotThrow(() => client.disconnect("TEST"));
  assert.equal(client.status, "disconnected");
  assert.equal(client.snapshot, null);
  assert.equal(session.destroyed, true);
  assert.equal(byteCleanupCalls, 1);
  assert.equal(callbackCalls, 1);
  await assert.rejects(client.refreshSnapshot(), { code: "DISCONNECTED" });
});

test("disconnect during pairing cannot install a session after in-flight session derivation resumes", async () => {
  const reasons = [];
  const { client, crypto, server } = fixture((reason) => reasons.push(reason));
  const gate = deferred();
  const derivedKeys = {
    handshakeKey: new Uint8Array(32).fill(3),
    clientToServerKey: new Uint8Array(32).fill(4),
    serverToClientKey: new Uint8Array(32).fill(5),
  };
  crypto.ephemeralBytes.push(...Object.values(derivedKeys));
  crypto.deriveSessionKeys = async () => gate.promise;
  const pairing = client.pair("123456");
  await waitUntil(() => server.pairingSubmits.length === 1);

  client.disconnect("PAGEHIDE");
  gate.resolve(derivedKeys);

  await assert.rejects(pairing, { code: "DISCONNECTED", disconnect: true });
  assert.equal(client.status, "disconnected");
  assert.equal(crypto.sessions.length, 0);
  assert.equal(server.pairingSubmits.length, 1);
  assert.deepEqual(reasons, ["PAGEHIDE"]);
  for (const bytes of Object.values(derivedKeys)) assert.ok(bytes.every((byte) => byte === 0));
});

test("disconnect aborts active work and rejects already queued work without sending it", async () => {
  const reasons = [];
  const { client, server } = await pairedFixture((reason) => reasons.push(reason));
  const gate = deferred();
  server.blockNextVault = gate;
  const active = client.refreshSnapshot();
  const queued = client.mutate({ op: "tag.create", name: "must-not-send" });
  await waitUntil(() => server.operations.length === 2);

  client.disconnect("NETWORK_CHANGED");

  await assert.rejects(active, { name: "LanApiError", code: "DISCONNECTED" });
  await assert.rejects(queued, { name: "LanApiError", code: "DISCONNECTED" });
  assert.deepEqual(server.operations, ["snapshot", "snapshot"]);
  assert.deepEqual(server.counters, [1, 2]);
  assert.deepEqual(reasons, ["NETWORK_CHANGED"]);
  gate.resolve();
});

test("disconnect while decrypt is pending rejects refresh and never repopulates the snapshot", async () => {
  const { client, crypto, server } = await pairedFixture();
  server.revision = 9;
  const session = crypto.sessions[0];
  const originalDecrypt = session.decryptResponse.bind(session);
  const entered = deferred();
  const release = deferred();
  session.decryptResponse = async (options) => {
    const plaintext = await originalDecrypt(options);
    entered.resolve();
    await release.promise;
    return plaintext;
  };

  const active = client.refreshSnapshot();
  await entered.promise;
  client.disconnect("PAGEHIDE");
  release.resolve();

  await assert.rejects(active, {
    name: "LanApiError",
    code: "DISCONNECTED",
    message: "与手机连接已断开，请在手机重新开启 PC 访问",
    disconnect: true,
  });
  assert.equal(client.snapshot, null);
});

test("disconnect during mutate post-refresh decrypt rejects without restoring its snapshot", async () => {
  const { client, crypto } = await pairedFixture();
  const session = crypto.sessions[0];
  const originalDecrypt = session.decryptResponse.bind(session);
  const entered = deferred();
  const release = deferred();
  let calls = 0;
  session.decryptResponse = async (options) => {
    const plaintext = await originalDecrypt(options);
    calls += 1;
    if (calls === 2) {
      entered.resolve();
      await release.promise;
    }
    return plaintext;
  };

  const active = client.mutate({ op: "tag.create", name: "race" });
  await entered.promise;
  client.disconnect("PAGEHIDE");
  release.resolve();

  await assert.rejects(active, { code: "DISCONNECTED", disconnect: true });
  assert.equal(client.snapshot, null);
});
