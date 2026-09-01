# LAN Access Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let one trusted PC browser temporarily manage the phone vault over the current Wi-Fi or phone hotspot without sending secrets as unauthenticated plaintext.

**Architecture:** A dependency-free core manages the six-digit access code, five-attempt limit, single session, monotonic message counters, and 30-minute inactivity timeout. Pairing uses ephemeral P-256 ECDH and AES-GCM to carry the access code; subsequent request/response bodies use an HKDF-derived session key. An Android foreground service later exposes static assets and encrypted API envelopes through one embedded HTTP server.

**Tech Stack:** Java 8/JCA P-256 ECDH, HKDF-HMAC-SHA256, AES-256-GCM, SecureRandom; browser WebCrypto; Android foreground service. Embedded HTTP server dependency requires separate user approval before addition.

**Spec:** `docs/superpowers/specs/2026-08-27-offline-password-vault-design.md`

## Global Constraints

- LAN service starts only after an explicit phone action and stops on phone action, 30-minute valid-operation inactivity, network change, or service termination.
- One run has one random six-digit code and at most one authenticated PC session.
- Five wrong access-code attempts invalidate the run.
- Successful pairing invalidates the access code immediately.
- Unauthenticated endpoints expose no vault count, record name, category, tag, or other vault metadata.
- Every data request is authenticated and encrypted; request and response counters are strictly monotonic to reject replay.
- The first version assumes a trusted personal LAN and protects against passive capture and unauthorized clients; an active attacker able to replace the served page or public key is outside the first-version threat model.
- No access code, session key, token, account, password, or notes may be logged.
- One PC session only; no long-term trusted device.

---

### Task 1: Access Code and Session State Machine

**Files:**
- Create: `app/src/test/java/com/passwordvault/local/core/LanSessionManagerTest.java`
- Create: `app/src/main/java/com/passwordvault/local/core/lan/LanClock.java`
- Create: `app/src/main/java/com/passwordvault/local/core/lan/LanRandom.java`
- Create: `app/src/main/java/com/passwordvault/local/core/lan/LanSessionState.java`
- Create: `app/src/main/java/com/passwordvault/local/core/lan/PairingResult.java`
- Create: `app/src/main/java/com/passwordvault/local/core/lan/LanSessionManager.java`

**Interfaces:**
- Produces: `LanSessionManager.start(): LanSessionState`.
- Produces: `LanSessionManager.submitAccessCode(String): PairingResult`.
- Produces: `LanSessionManager.recordValidOperation(String sessionId, long requestCounter): void`.
- Produces: `LanSessionManager.stop()` and `LanSessionManager.checkTimeout()`.

- [x] Write tests for six-digit generation, five failures, one-time success, second-client rejection, replay rejection, valid-operation timeout refresh, invalid-operation no-refresh, 30-minute timeout, explicit stop, and restart invalidation.
- [x] Run the core test script and confirm RED because LAN session types are missing.
- [x] Implement the synchronized state machine without networking or Android classes.
- [x] Run the core test script and confirm GREEN.
- [x] Commit with `git commit -m "feat: add LAN session state machine"`.

### Task 2: Browser-Interoperable Pairing and Message Crypto

**Files:**
- Create: `app/src/test/java/com/passwordvault/local/core/LanCryptoTest.java`
- Create: `app/src/main/java/com/passwordvault/local/core/lan/LanCrypto.java`
- Create: `app/src/main/java/com/passwordvault/local/core/lan/LanKeyAgreement.java`
- Create: `app/src/main/java/com/passwordvault/local/core/lan/LanEnvelope.java`
- Create: `protocol/lan-crypto-v1-test-vectors.json`.
- Create: `web-tests/lan-crypto.test.mjs`.

**Interfaces:**
- P-256 public keys use uncompressed SEC1 form.
- Pairing code is encrypted under an ECDH/HKDF handshake key with transcript-bound AAD.
- Session traffic uses separate client-to-server and server-to-client AES-GCM keys and 64-bit counters.

- [x] Write Java known-answer and tamper/replay tests.
- [x] Implement JCA ECDH, HKDF, key separation, nonce construction, and AES-GCM envelopes.
- [x] Write browser WebCrypto code against the same committed vectors and run Node tests.
- [x] Commit with `git commit -m "feat: add encrypted LAN protocol"`.

### Task 3: Embedded HTTP Feasibility and Dependency Gate

**Dependency decision:** Before production implementation, obtain explicit user approval for the selected embedded HTTP server dependency and exact version. Do not implement an ad-hoc general-purpose HTTP parser for password data.

- [ ] Build a minimal Android feasibility branch that serves bundled `index.html`, binds only while foreground service is active, and stops cleanly.
- [ ] Verify access over same Wi-Fi and phone hotspot on one physical device.
- [ ] Verify network switch and notification stop revoke the service.
- [ ] Record the selected dependency/version and commit only after user approval.

### Task 4: Encrypted Vault API and Foreground Service

**Files:**
- Create Android server, route, foreground-service, notification, and address resolver classes under `app/src/main/java/com/passwordvault/local/lan/`.
- Create Android integration tests under `app/src/androidTest/java/com/passwordvault/local/lan/`.

- [ ] Expose unauthenticated static assets and pairing-info/pairing-submit routes only.
- [ ] Expose all vault/category/tag operations through encrypted authenticated POST envelopes.
- [ ] Map validation, missing entity, stale version, unauthorized, and disconnected states to stable API error codes without sensitive logs.
- [ ] Add notification stop action, 30-minute timeout, network callback shutdown, and one-session enforcement.
- [ ] Run GitHub emulator tests and physical Wi-Fi/hotspot acceptance checks.
- [ ] Commit with `git commit -m "feat: add Android LAN vault service"`.
