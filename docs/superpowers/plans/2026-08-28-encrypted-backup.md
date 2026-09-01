# Encrypted Backup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a phone-only, password-protected backup format that previews counts before an atomic full-vault replacement.

**Architecture:** A versioned binary envelope carries PBKDF2 parameters, salt, password verifier, AES-GCM nonce, and authenticated ciphertext. The ciphertext is the existing deterministic `VaultBinaryCodec` payload. Preview decrypts and validates without writing; confirmation replaces the current `VaultStore` exactly once.

**Tech Stack:** Java 8; `PBKDF2WithHmacSHA256` at 600,000 iterations; AES-256-GCM; HMAC-SHA256 password verifier; existing dependency-free vault core.

**Spec:** `docs/superpowers/specs/2026-08-27-offline-password-vault-design.md`

## Global Constraints

- Backup is available only on the phone, never in the PC Web client.
- Export always contains all credentials, categories, and tags.
- The backup password is separate from the device-bound Keystore key.
- Import is full replacement only; no merge or duplicate resolution.
- Password failure, structural corruption, authentication failure, and unsupported format must not write current data.
- Import preview exposes only credential/category/tag counts and retains the validated snapshot in memory until confirmation or cancellation.
- Successful import must be able to notify the Android integration layer to stop the active PC session.
- No CSV, Excel, plaintext JSON, or new production dependency.

---

### Task 1: Versioned Backup Envelope and Password Crypto

**Files:**
- Create: `app/src/test/java/com/passwordvault/local/core/BackupCryptoTest.java`
- Create: `app/src/main/java/com/passwordvault/local/core/backup/BackupException.java`
- Create: `app/src/main/java/com/passwordvault/local/core/backup/WrongBackupPasswordException.java`
- Create: `app/src/main/java/com/passwordvault/local/core/backup/CorruptBackupException.java`
- Create: `app/src/main/java/com/passwordvault/local/core/backup/UnsupportedBackupVersionException.java`
- Create: `app/src/main/java/com/passwordvault/local/core/backup/BackupEnvelope.java`
- Create: `app/src/main/java/com/passwordvault/local/core/backup/BackupEnvelopeCodec.java`
- Create: `app/src/main/java/com/passwordvault/local/core/backup/BackupCrypto.java`

**Interfaces:**
- Produces: `BackupCrypto.encrypt(byte[] plaintext, char[] password): byte[]`.
- Produces: `BackupCrypto.decrypt(byte[] backup, char[] password): byte[]`.
- `BackupEnvelopeCodec` accepts only format version `1`, KDF id `1`, 600,000 iterations, 16-byte salt, 16-byte verifier, 12-byte nonce, and at most 64 MiB ciphertext.

- [x] Write tests proving round-trip, no plaintext leakage, wrong-password classification, ciphertext corruption classification, unsupported-version rejection, and truncated-envelope rejection.
- [x] Run `powershell -ExecutionPolicy Bypass -File scripts/test-core.ps1` and confirm compilation fails because backup types are missing.
- [x] Implement the envelope, PBKDF2 key split, verifier check, AES-GCM encryption, and zeroing of temporary password/key/plaintext buffers.
- [x] Run the core test script and confirm every suite passes.
- [x] Commit with `git commit -m "feat: add encrypted backup format"`.

### Task 2: Preview and Atomic Full Replacement

**Files:**
- Create: `app/src/test/java/com/passwordvault/local/core/BackupServiceTest.java`
- Create: `app/src/main/java/com/passwordvault/local/core/backup/ImportPreview.java`
- Create: `app/src/main/java/com/passwordvault/local/core/backup/BackupService.java`
- Modify: `app/src/main/java/com/passwordvault/local/core/repository/VaultService.java`

**Interfaces:**
- Produces: `BackupService.exportAll(VaultSnapshot, char[]): byte[]`.
- Produces: `BackupService.previewImport(byte[], char[]): ImportPreview`.
- Produces: `BackupService.applyImport(ImportPreview): void`.
- Produces: `VaultService.replaceAll(VaultSnapshot): void`, used only by validated backup import.

- [x] Write tests proving exact export/import, count preview, no write before confirmation, one replacement on confirmation, stale/cancelled preview rejection, and no write after any decode/decrypt error.
- [x] Run the core test script and confirm RED because `BackupService` is missing.
- [x] Implement preview tokens bound to one `BackupService` instance and one-time application.
- [x] Run the core test script and confirm GREEN.
- [x] Commit with `git commit -m "feat: add atomic backup import"`.

### Task 3: Android Document Picker Integration

**Files:**
- Create: `app/src/main/java/com/passwordvault/local/backup/AndroidBackupFiles.java`
- Create: `app/src/main/java/com/passwordvault/local/ui/BackupController.java`
- Create: Android backup layouts and strings under `app/src/main/res/`.
- Create: `app/src/androidTest/java/com/passwordvault/local/BackupFlowTest.java`

**Interfaces:**
- Consumes: `BackupService` and Android Storage Access Framework URIs.
- Produces: export password/confirmation flow, import password/preview/full-replacement confirmation flow, and successful-import callback for stopping LAN access.

- [ ] Write Android tests for password confirmation, cancelled file selection, preview counts, overwrite confirmation, failed import preservation, and successful import callback.
- [ ] Run `./gradlew connectedDebugAndroidTest` in GitHub Actions/emulator and confirm RED.
- [ ] Implement Storage Access Framework reads/writes without requesting broad storage permission.
- [ ] Run Android tests and lint; confirm GREEN.
- [ ] Commit with `git commit -m "feat: add phone backup flow"`.
