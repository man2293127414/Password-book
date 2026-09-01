import { gcm } from "@noble/ciphers/aes.js";
import { p256 } from "@noble/curves/nist.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

const HANDSHAKE_INFO = encoder.encode("PVL-LAN-HANDSHAKE-V1");
const CLIENT_TO_SERVER_INFO = encoder.encode("PVL-LAN-C2S-V1");
const SERVER_TO_CLIENT_INFO = encoder.encode("PVL-LAN-S2C-V1");
const DESTROYED_MESSAGE = "LAN crypto session is destroyed";

function asBytes(value, name = "value") {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  throw new TypeError(`${name} must be a byte array`);
}

function concat(...values) {
  const parts = values.map((value) => asBytes(value));
  const result = new Uint8Array(parts.reduce((length, value) => length + value.length, 0));
  let offset = 0;
  for (const value of parts) {
    result.set(value, offset);
    offset += value.length;
  }
  return result;
}

function validateLength(value, length, message, name) {
  const bytes = asBytes(value, name);
  if (bytes.length !== length) throw new TypeError(message);
  return bytes;
}

function equalBytes(left, right) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

function validateSharedSecret(sharedSecret) {
  return validateLength(
    sharedSecret,
    32,
    "sharedSecret must contain 32 bytes",
    "sharedSecret",
  );
}

function validateRunId(runId) {
  const bytes = asBytes(runId, "runId");
  if (bytes.length === 0) throw new TypeError("runId must not be empty");
  return bytes;
}

function validatePublicSec1(publicKey) {
  const bytes = asBytes(publicKey, "P-256 public key");
  if (bytes.length !== 65 || bytes[0] !== 0x04) {
    throw new TypeError("P-256 public key must be a 65-byte uncompressed SEC1 point");
  }
  try {
    if (p256.Point.fromBytes(bytes).is0()) throw new Error("point at infinity");
  } catch {
    throw new TypeError("P-256 public key must be a valid SEC1 point");
  }
  return bytes;
}

function validatePrivateScalar(privateScalar) {
  const scalar = validateLength(
    privateScalar,
    32,
    "P-256 private scalar must be 32 bytes",
    "P-256 private scalar",
  );
  if (!p256.utils.isValidSecretKey(scalar)) {
    throw new TypeError("P-256 private scalar is invalid");
  }
  return scalar;
}

function validateAesKey(rawKey) {
  return validateLength(rawKey, 32, "AES-256 key must be 32 bytes", "AES-256 key");
}

function validateCounter(counter) {
  if (!Number.isSafeInteger(counter) || counter < 0) {
    throw new TypeError("counter must be a non-negative safe integer");
  }
}

function validateSessionId(sessionId) {
  if (typeof sessionId !== "string" || sessionId.length === 0) {
    throw new TypeError("sessionId must not be empty");
  }
}

function validateMessageMetadata(sessionId, method, path) {
  validateSessionId(sessionId);
  if (typeof method !== "string" || method.length === 0) {
    throw new TypeError("method must not be empty");
  }
  if (typeof path !== "string" || path.length === 0) {
    throw new TypeError("path must not be empty");
  }
}

function messageNonce(counter) {
  validateCounter(counter);
  const nonce = new Uint8Array(12);
  new DataView(nonce.buffer).setBigUint64(4, BigInt(counter), false);
  return nonce;
}

function messageAad(method, path, sessionId, counter) {
  validateCounter(counter);
  validateMessageMetadata(sessionId, method, path);
  return encoder.encode(`${method}\n${path}\n${sessionId}\n${counter}`);
}

function randomBytes(length) {
  const random = globalThis.crypto?.getRandomValues;
  if (typeof random !== "function") {
    throw new Error("Secure random byte generation is unavailable");
  }
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

function deriveHkdf(sharedSecret, runId, info) {
  return hkdf(sha256, validateSharedSecret(sharedSecret), validateRunId(runId), info, 32);
}

export function encodeBase64Url(value) {
  const bytes = asBytes(value, "base64url input");
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export function decodeBase64Url(value) {
  if (
    typeof value !== "string"
    || !/^[A-Za-z0-9_-]*$/.test(value)
    || value.length % 4 === 1
  ) {
    throw new TypeError("Invalid unpadded base64url value");
  }
  try {
    const padding = "=".repeat((4 - (value.length % 4)) % 4);
    const binary = atob(value.replaceAll("-", "+").replaceAll("_", "/") + padding);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    if (encodeBase64Url(bytes) !== value) {
      throw new TypeError("Invalid unpadded base64url value");
    }
    return bytes;
  } catch (error) {
    if (error instanceof TypeError && /base64url/.test(error.message)) throw error;
    throw new TypeError("Invalid unpadded base64url value");
  }
}

export function generateClientKeyPair() {
  const seed = randomBytes(p256.lengths.seed);
  let privateKey;
  try {
    privateKey = p256.utils.randomSecretKey(seed);
    return {
      privateKey,
      publicKey: p256.getPublicKey(privateKey, false),
    };
  } catch (error) {
    destroyBytes(privateKey);
    throw error;
  } finally {
    destroyBytes(seed);
  }
}

export async function importPublicSec1(publicKey) {
  return validatePublicSec1(publicKey).slice();
}

export async function importPrivateScalar(privateScalar, publicKey) {
  const scalar = validatePrivateScalar(privateScalar);
  const publicSec1 = validatePublicSec1(publicKey);
  let derivedPublic;
  try {
    derivedPublic = p256.getPublicKey(scalar, false);
    if (!equalBytes(derivedPublic, publicSec1)) {
      throw new TypeError("P-256 private scalar does not match public key");
    }
    return scalar.slice();
  } finally {
    destroyBytes(derivedPublic);
  }
}

export async function deriveSharedSecret(privateKey, publicKey) {
  const privateScalar = validatePrivateScalar(privateKey);
  const publicSec1 = validatePublicSec1(publicKey);
  let sharedPoint;
  try {
    sharedPoint = p256.getSharedSecret(privateScalar, publicSec1, false);
    return sharedPoint.slice(1, 33);
  } finally {
    destroyBytes(sharedPoint);
  }
}

export async function deriveSessionKeys(sharedSecret, runId) {
  let handshakeKey;
  let clientToServerKey;
  let serverToClientKey;
  try {
    handshakeKey = deriveHkdf(sharedSecret, runId, HANDSHAKE_INFO);
    clientToServerKey = deriveHkdf(sharedSecret, runId, CLIENT_TO_SERVER_INFO);
    serverToClientKey = deriveHkdf(sharedSecret, runId, SERVER_TO_CLIENT_INFO);
    return { handshakeKey, clientToServerKey, serverToClientKey };
  } catch (error) {
    destroyBytes(handshakeKey, clientToServerKey, serverToClientKey);
    throw error;
  }
}

export async function encryptPairingCode({
  sharedSecret,
  runId,
  serverPublic,
  clientPublic,
  nonce,
  accessCode,
}) {
  if (!/^\d{6}$/.test(accessCode)) throw new TypeError("accessCode must contain six digits");
  const pairingNonce = nonce === undefined
    ? randomBytes(12)
    : validateLength(nonce, 12, "pairing nonce must contain 12 bytes", "pairing nonce").slice();
  const validatedRunId = validateRunId(runId);
  const validatedServerPublic = validatePublicSec1(serverPublic);
  const validatedClientPublic = validatePublicSec1(clientPublic);
  let handshakeKey;
  let plaintext;
  try {
    handshakeKey = deriveHkdf(sharedSecret, validatedRunId, HANDSHAKE_INFO);
    const pairingAad = concat(validatedRunId, validatedServerPublic, validatedClientPublic);
    plaintext = encoder.encode(accessCode);
    const ciphertext = gcm(handshakeKey, pairingNonce, pairingAad).encrypt(plaintext);
    return { nonce: pairingNonce.slice(), ciphertext };
  } finally {
    destroyBytes(handshakeKey, plaintext);
  }
}

export async function decryptPairingReply({
  sharedSecret,
  runId,
  serverPublic,
  clientPublic,
  nonce,
  ciphertext,
}) {
  const pairingNonce = validateLength(
    nonce,
    12,
    "pairing nonce must contain 12 bytes",
    "pairing nonce",
  );
  const encrypted = asBytes(ciphertext, "pairing ciphertext");
  if (encrypted.length < 16) {
    throw new TypeError("pairing ciphertext must contain an authentication tag");
  }
  const validatedRunId = validateRunId(runId);
  const validatedServerPublic = validatePublicSec1(serverPublic);
  const validatedClientPublic = validatePublicSec1(clientPublic);
  let handshakeKey;
  let plaintext;
  try {
    handshakeKey = deriveHkdf(sharedSecret, validatedRunId, HANDSHAKE_INFO);
    const pairingAad = concat(validatedRunId, validatedServerPublic, validatedClientPublic);
    plaintext = gcm(handshakeKey, pairingNonce, pairingAad).decrypt(encrypted);
    return decoder.decode(plaintext);
  } finally {
    destroyBytes(handshakeKey, plaintext);
  }
}

function encryptMessage({ key, sessionId, counter, method, path, plaintext }) {
  const aesKey = validateAesKey(key);
  const nonce = messageNonce(counter);
  const aad = messageAad(method, path, sessionId, counter);
  let plaintextCopy;
  try {
    plaintextCopy = asBytes(plaintext, "plaintext").slice();
    return { counter, ciphertext: gcm(aesKey, nonce, aad).encrypt(plaintextCopy) };
  } finally {
    destroyBytes(plaintextCopy);
  }
}

function decryptMessage({ key, sessionId, counter, method, path, ciphertext }) {
  const aesKey = validateAesKey(key);
  const encrypted = asBytes(ciphertext, "ciphertext");
  if (encrypted.length < 16) {
    throw new TypeError("ciphertext must contain an authentication tag");
  }
  const nonce = messageNonce(counter);
  const aad = messageAad(method, path, sessionId, counter);
  let plaintext;
  try {
    plaintext = gcm(aesKey, nonce, aad).decrypt(encrypted);
    return plaintext.slice();
  } finally {
    destroyBytes(plaintext);
  }
}

function encryptClientRequest(options) {
  return encryptMessage(options);
}

function decryptServerResponse(options) {
  return decryptMessage(options);
}

export function destroyBytes(...values) {
  for (const value of values) {
    if (value instanceof Uint8Array) value.fill(0);
  }
}

export class LanClientCryptoSession {
  #sessionId;
  #clientToServerKey;
  #serverToClientKey;
  #nextRequestCounter = 1;
  #lastResponseCounter = 0;
  #responseQueue = Promise.resolve();
  #destroyed = false;

  constructor({ sessionId, clientToServerKey, serverToClientKey }) {
    validateSessionId(sessionId);
    this.#sessionId = sessionId;
    this.#clientToServerKey = validateLength(
      clientToServerKey,
      32,
      "LAN session keys must contain 32 bytes",
      "client-to-server key",
    ).slice();
    this.#serverToClientKey = validateLength(
      serverToClientKey,
      32,
      "LAN session keys must contain 32 bytes",
      "server-to-client key",
    ).slice();
  }

  #assertActive() {
    if (this.#destroyed) throw new Error(DESTROYED_MESSAGE);
  }

  async encryptRequest({ method, path, plaintext }) {
    this.#assertActive();
    if (this.#nextRequestCounter > Number.MAX_SAFE_INTEGER) {
      throw new RangeError("request counter exhausted");
    }
    const counter = this.#nextRequestCounter;
    this.#nextRequestCounter += 1;
    return encryptClientRequest({
      key: this.#clientToServerKey,
      sessionId: this.#sessionId,
      counter,
      method,
      path,
      plaintext,
    });
  }

  decryptResponse({ method, path, envelope }) {
    try {
      this.#assertActive();
    } catch (error) {
      return Promise.reject(error);
    }
    const operation = this.#responseQueue.then(() => {
      this.#assertActive();
      const counter = envelope?.counter;
      validateCounter(counter);
      if (counter <= this.#lastResponseCounter || counter >= this.#nextRequestCounter) {
        throw new Error("response counter is replayed or was not requested");
      }
      const plaintext = decryptServerResponse({
        key: this.#serverToClientKey,
        sessionId: this.#sessionId,
        counter,
        method,
        path,
        ciphertext: envelope.ciphertext,
      });
      this.#lastResponseCounter = counter;
      return plaintext;
    });
    this.#responseQueue = operation.then(() => undefined, () => undefined);
    return operation;
  }

  destroy() {
    if (this.#destroyed) return;
    this.#destroyed = true;
    destroyBytes(this.#clientToServerKey, this.#serverToClientKey);
    this.#responseQueue = Promise.resolve();
  }
}
