import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import * as lanCrypto from "../app/src/main/assets/web/lan-crypto.mjs";

const {
  LanClientCryptoSession,
  decodeBase64Url,
  decryptPairingReply,
  deriveSharedSecret,
  deriveSessionKeys,
  destroyBytes,
  encodeBase64Url,
  encryptPairingCode,
  generateClientKeyPair,
  importPrivateScalar,
  importPublicSec1,
} = lanCrypto;

const vector = JSON.parse(
  await readFile(new URL("../protocol/lan-crypto-v1-test-vectors.json", import.meta.url), "utf8"),
);

const decode = (value) => Uint8Array.from(Buffer.from(value, "base64url"));

test("derives the Java-compatible shared secret and direction keys", async () => {
  const clientPrivate = await importPrivateScalar(decode(vector.clientPrivate), decode(vector.clientPublic));
  const serverPublic = await importPublicSec1(decode(vector.serverPublic));
  const sharedSecret = await deriveSharedSecret(clientPrivate, serverPublic);
  const keys = await deriveSessionKeys(sharedSecret, decode(vector.runId));

  assert.deepEqual(sharedSecret, decode(vector.sharedSecret));
  assert.deepEqual(keys.handshakeKey, decode(vector.handshakeKey));
  assert.deepEqual(keys.clientToServerKey, decode(vector.clientToServerKey));
  assert.deepEqual(keys.serverToClientKey, decode(vector.serverToClientKey));
});

test("accepts the production 32-byte runId for pairing and session keys", async () => {
  const runId = decode("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8");
  const keys = await deriveSessionKeys(decode(vector.sharedSecret), runId);

  assert.deepEqual(keys.handshakeKey, decode("SqgusziNIVJynpGJN6F-gRV_wieUECkwhM-qYCMWG68"));
  assert.deepEqual(keys.clientToServerKey, decode("CYop7IyzCZSHkzLDUwGIU-Di56R2QenI-7tdvejFnvs"));
  assert.deepEqual(keys.serverToClientKey, decode("VmKa7kWGMSuhEMJjinOG37z-OXWMQET9_fu9cydErR0"));

  const encrypted = await encryptPairingCode({
    sharedSecret: decode(vector.sharedSecret),
    runId,
    serverPublic: decode(vector.serverPublic),
    clientPublic: decode(vector.clientPublic),
    nonce: decode(vector.pairingNonce),
    accessCode: vector.pairingCode,
  });
  assert.deepEqual(encrypted.ciphertext, decode("jgqQ2ZNPBPq7iGafZ1psrRC9lYqA3g"));
});

test("encrypts a pairing code that Java can decrypt", async () => {
  const encrypted = await encryptPairingCode({
    sharedSecret: decode(vector.sharedSecret),
    runId: decode(vector.runId),
    serverPublic: decode(vector.serverPublic),
    clientPublic: decode(vector.clientPublic),
    nonce: decode(vector.pairingNonce),
    accessCode: vector.pairingCode,
  });

  assert.deepEqual(encrypted.nonce, decode(vector.pairingNonce));
  assert.deepEqual(encrypted.ciphertext, decode(vector.pairingCiphertext));
});

test("produces the Java-compatible encrypted request", async () => {
  const keys = await deriveSessionKeys(decode(vector.sharedSecret), decode(vector.runId));
  const session = new LanClientCryptoSession({
    sessionId: vector.sessionId,
    clientToServerKey: keys.clientToServerKey,
    serverToClientKey: keys.serverToClientKey,
  });
  const envelope = await session.encryptRequest({
    method: vector.requestMethod,
    path: vector.requestPath,
    plaintext: decode(vector.requestPlaintext),
  });

  assert.equal(envelope.counter, vector.requestCounter);
  assert.deepEqual(envelope.ciphertext, decode(vector.requestCiphertext));
});

test("client session allocates counters and rejects replayed responses", async () => {
  const keys = await deriveSessionKeys(decode(vector.sharedSecret), decode(vector.runId));
  const session = new LanClientCryptoSession({
    sessionId: vector.sessionId,
    clientToServerKey: keys.clientToServerKey,
    // Reuse the known-answer request key so the fixture can stand in for a response.
    serverToClientKey: keys.clientToServerKey,
  });
  const request = await session.encryptRequest({
    method: vector.requestMethod,
    path: vector.requestPath,
    plaintext: decode(vector.requestPlaintext),
  });
  const response = {
    counter: request.counter,
    ciphertext: decode(vector.requestCiphertext),
  };

  assert.equal(request.counter, 1);
  const decrypt = () => session.decryptResponse({
      method: vector.requestMethod,
      path: vector.requestPath,
      envelope: response,
    });
  const concurrentResults = await Promise.allSettled([decrypt(), decrypt()]);

  assert.equal(concurrentResults.filter((result) => result.status === "fulfilled").length, 1);
  assert.equal(concurrentResults.filter((result) => result.status === "rejected").length, 1);
  assert.deepEqual(concurrentResults.find((result) => result.status === "fulfilled").value, decode(vector.requestPlaintext));
  assert.match(
    concurrentResults.find((result) => result.status === "rejected").reason.message,
    /response counter/,
  );
});

test("decrypts a Java-compatible pairing reply", async () => {
  const plaintext = await decryptPairingReply({
    sharedSecret: decode(vector.sharedSecret),
    runId: decode(vector.runId),
    serverPublic: decode(vector.serverPublic),
    clientPublic: decode(vector.clientPublic),
    nonce: decode("ICEiIyQlJicoKSor"),
    ciphertext: decode("-q-CcsPYClmZc2l_1fpHZr7ryur0ei1KwfdRj_K6UvOWFr2HSvg4HEShwSyxALQ"),
  });

  assert.equal(plaintext, JSON.stringify({ sessionId: vector.sessionId }));
});

test("rejects tampered ciphertext", async () => {
  const keys = await deriveSessionKeys(decode(vector.sharedSecret), decode(vector.runId));
  const session = new LanClientCryptoSession({
    sessionId: vector.sessionId,
    clientToServerKey: keys.clientToServerKey,
    // Reuse the known-answer request key so the fixture can stand in for a response.
    serverToClientKey: keys.clientToServerKey,
  });
  await session.encryptRequest({
    method: vector.requestMethod,
    path: vector.requestPath,
    plaintext: decode(vector.requestPlaintext),
  });
  const tampered = decode(vector.requestCiphertext);
  tampered[0] ^= 1;

  await assert.rejects(session.decryptResponse({
    method: vector.requestMethod,
    path: vector.requestPath,
    envelope: { counter: vector.requestCounter, ciphertext: tampered },
  }));
});

test("rejects invalid P-256 SEC1 points and byte lengths", async () => {
  const offCurve = new Uint8Array(65);
  offCurve[0] = 0x04;

  await assert.rejects(importPublicSec1(new Uint8Array(64)), /65-byte uncompressed SEC1 point/);
  await assert.rejects(importPublicSec1(offCurve));
  await assert.rejects(
    importPrivateScalar(new Uint8Array(31), decode(vector.clientPublic)),
    /private scalar must be 32 bytes/,
  );
  await assert.rejects(
    deriveSessionKeys(new Uint8Array(31), decode(vector.runId)),
    /sharedSecret must contain 32 bytes/,
  );
  await assert.rejects(
    deriveSessionKeys(decode(vector.sharedSecret), new Uint8Array(0)),
    /runId must not be empty/,
  );
});

test("strictly encodes and decodes unpadded base64url", () => {
  const publicKey = decode(vector.clientPublic);

  assert.equal(encodeBase64Url(publicKey), vector.clientPublic);
  assert.deepEqual(decodeBase64Url(vector.clientPublic), publicKey);
  for (const invalid of ["AA=", "AA+", "AA/", "A A", "A"]) {
    assert.throws(() => decodeBase64Url(invalid), /base64url/);
  }
});

test("generated client key pairs agree without exposing caller-owned arrays", async () => {
  const client = generateClientKeyPair();
  const server = generateClientKeyPair();
  const clientPrivateInput = client.privateKey.slice();
  const clientPublicInput = client.publicKey.slice();
  const serverPublicInput = server.publicKey.slice();
  const clientPrivate = await importPrivateScalar(clientPrivateInput, clientPublicInput);
  const serverPublic = await importPublicSec1(serverPublicInput);
  clientPrivateInput.fill(0);
  clientPublicInput.fill(0);
  serverPublicInput.fill(0);

  const clientShared = await deriveSharedSecret(clientPrivate, serverPublic);
  const serverShared = await deriveSharedSecret(server.privateKey, client.publicKey);

  assert.equal(client.privateKey.length, 32);
  assert.equal(client.publicKey.length, 65);
  assert.equal(client.publicKey[0], 0x04);
  assert.deepEqual(clientShared, serverShared);
});

test("rejects a private scalar paired with a different public key", async () => {
  const first = generateClientKeyPair();
  const second = generateClientKeyPair();
  try {
    await assert.rejects(
      importPrivateScalar(first.privateKey, second.publicKey),
      {
        name: "TypeError",
        message: "P-256 private scalar does not match public key",
      },
    );
  } finally {
    destroyBytes(first.privateKey, second.privateKey);
  }
});

test("destroy wipes owned bytes and rejects future session operations", async () => {
  const clientToServerKey = decode(vector.clientToServerKey);
  const serverToClientKey = decode(vector.serverToClientKey);
  const session = new LanClientCryptoSession({
    sessionId: vector.sessionId,
    clientToServerKey,
    serverToClientKey,
  });
  const temporary = Uint8Array.of(1, 2, 3);

  await session.encryptRequest({
    method: vector.requestMethod,
    path: vector.requestPath,
    plaintext: decode(vector.requestPlaintext),
  });
  const queuedResponse = session.decryptResponse({
    method: vector.requestMethod,
    path: vector.requestPath,
    envelope: { counter: 1, ciphertext: decode(vector.requestCiphertext) },
  });

  destroyBytes(temporary);
  session.destroy();
  session.destroy();

  assert.deepEqual(temporary, new Uint8Array(3));
  assert.deepEqual(clientToServerKey, decode(vector.clientToServerKey));
  assert.deepEqual(serverToClientKey, decode(vector.serverToClientKey));
  await assert.rejects(
    queuedResponse,
    { message: "LAN crypto session is destroyed" },
  );
  await assert.rejects(
    session.encryptRequest({
      method: vector.requestMethod,
      path: vector.requestPath,
      plaintext: decode(vector.requestPlaintext),
    }),
    { message: "LAN crypto session is destroyed" },
  );
  await assert.rejects(
    session.decryptResponse({
      method: vector.requestMethod,
      path: vector.requestPath,
      envelope: { counter: 1, ciphertext: decode(vector.requestCiphertext) },
    }),
    { message: "LAN crypto session is destroyed" },
  );
});

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
