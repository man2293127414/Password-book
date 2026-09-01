# Android Vault Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the dependency-free Android vault core and the first usable phone UI slice for local credential CRUD, categories, tags, search, filtering, password masking, and device-encrypted persistence.

**Architecture:** Domain rules are plain Java 8 so they can be tested before the Android toolchain is installed. Android-specific persistence stores one AES-256-GCM encrypted `VaultSnapshot` blob in a private SQLite database, using a non-exportable Android Keystore key. The UI uses one platform `Activity` and XML layouts in the first phase, avoiding new production dependencies.

**Tech Stack:** Java 8 domain code; Android SDK 37 with `minSdk 28` and `targetSdk 37`; Android Gradle Plugin 9.2.0; Gradle 9.4.1; Android framework Views, SQLite, Keystore, and JCA only; no third-party production dependency.

**Spec:** `docs/superpowers/specs/2026-08-27-offline-password-vault-design.md`

## Global Constraints

- The phone is the only persistent source of truth.
- The first version has no in-app unlock screen, recovery code, cloud sync, autofill, TOTP, password generator, recycle bin, or plaintext import/export.
- Credential fields are name, account, password, URL, one optional category, multiple optional tags, notes, timestamps, and an internal version.
- Name and password are required; category and tag references must exist.
- Category and tag names are trimmed, non-empty, case-insensitively unique.
- Deleting a category uncategorizes credentials; deleting a tag removes only that association.
- Search covers name, account, URL, category name, and tag names, never password or notes.
- Multiple selected tags use AND matching; default sort is name, case-insensitive.
- Password placeholders are always exactly `••••••••`; only the selected record may be revealed, and reveal state resets on navigation or backgrounding.
- Android Auto Backup must exclude the database, Keystore metadata, and sensitive files.
- No third-party production dependency may be added without explicit user approval.

## File Structure

- `scripts/test-core.ps1`: compiles and runs plain-Java core tests with the installed JDK 8.
- `app/src/main/java/com/passwordvault/local/core/model/`: immutable domain models and drafts.
- `app/src/main/java/com/passwordvault/local/core/validation/`: credential and taxonomy validation.
- `app/src/main/java/com/passwordvault/local/core/query/`: search, category filter, tag-AND filter, and name sorting.
- `app/src/main/java/com/passwordvault/local/core/repository/`: repository contract and domain errors.
- `app/src/main/java/com/passwordvault/local/core/codec/`: deterministic binary snapshot codec.
- `app/src/main/java/com/passwordvault/local/storage/`: Android SQLite and Keystore adapters.
- `app/src/main/java/com/passwordvault/local/ui/`: platform-View activity, list, editor, detail, and taxonomy screens.
- `app/src/test/java/com/passwordvault/local/core/`: dependency-free executable core test suites.
- `app/src/androidTest/java/com/passwordvault/local/`: Android persistence and UI behavior tests.

---

### Task 1: Domain Models and Validation

**Files:**
- Create: `scripts/test-core.ps1`
- Create: `app/src/test/java/com/passwordvault/local/core/CoreTestMain.java`
- Create: `app/src/test/java/com/passwordvault/local/core/VaultValidatorTest.java`
- Create: `app/src/main/java/com/passwordvault/local/core/model/Credential.java`
- Create: `app/src/main/java/com/passwordvault/local/core/model/CredentialDraft.java`
- Create: `app/src/main/java/com/passwordvault/local/core/model/Category.java`
- Create: `app/src/main/java/com/passwordvault/local/core/model/Tag.java`
- Create: `app/src/main/java/com/passwordvault/local/core/model/VaultSnapshot.java`
- Create: `app/src/main/java/com/passwordvault/local/core/validation/ValidationException.java`
- Create: `app/src/main/java/com/passwordvault/local/core/validation/VaultValidator.java`

**Interfaces:**
- Produces: `VaultValidator.validateCredential(CredentialDraft, VaultSnapshot): CredentialDraft`
- Produces: `VaultValidator.normalizeTaxonomyName(String, Collection<String>): String`
- Produces immutable `Credential`, `Category`, `Tag`, and `VaultSnapshot` types used by all later tasks.

- [x] **Step 1: Write failing validation tests**

```java
expectValidation("名称不能为空", () -> validator.validateCredential(draft(" ", "secret"), empty));
expectValidation("密码不能为空", () -> validator.validateCredential(draft("GitHub", ""), empty));
assertEquals("GitHub", validator.validateCredential(draft("  GitHub  ", "secret"), empty).getName());
expectValidation("分类不存在", () -> validator.validateCredential(draftWithCategory("missing"), empty));
expectValidation("标签不存在", () -> validator.validateCredential(draftWithTags("missing"), empty));
assertEquals("工作", validator.normalizeTaxonomyName("  工作  ", Arrays.asList("生活")));
expectValidation("名称已存在", () -> validator.normalizeTaxonomyName("工作", Arrays.asList("工作")));
expectValidation("名称已存在", () -> validator.normalizeTaxonomyName("WORK", Arrays.asList("work")));
```

- [x] **Step 2: Run the test and verify RED**

Run: `powershell -ExecutionPolicy Bypass -File scripts/test-core.ps1`

Expected: compilation fails because `VaultValidator` and the model types do not exist.

- [x] **Step 3: Implement immutable models and minimal validation**

Implement exact normalization and reference checks; preserve password and notes verbatim, trim name/account/URL, copy tag IDs into an unmodifiable insertion-ordered set, and defensively copy all snapshot collections.

- [x] **Step 4: Run the test and verify GREEN**

Run: `powershell -ExecutionPolicy Bypass -File scripts/test-core.ps1`

Expected: `PASS VaultValidatorTest` and exit code `0`.

- [x] **Step 5: Commit**

```bash
git add scripts app/src/main/java/com/passwordvault/local/core app/src/test/java/com/passwordvault/local/core docs/superpowers/plans/2026-08-27-android-vault-core.md
git commit -m "feat: add vault domain validation"
```

### Task 2: Search and Filtering

**Files:**
- Create: `app/src/test/java/com/passwordvault/local/core/VaultQueryTest.java`
- Create: `app/src/main/java/com/passwordvault/local/core/query/VaultFilter.java`
- Create: `app/src/main/java/com/passwordvault/local/core/query/VaultQuery.java`
- Modify: `app/src/test/java/com/passwordvault/local/core/CoreTestMain.java`

**Interfaces:**
- Consumes: `Credential`, `Category`, `Tag`, and `VaultSnapshot` from Task 1.
- Produces: `VaultQuery.apply(VaultSnapshot, VaultFilter): List<Credential>`.

- [x] **Step 1: Write failing query tests**

```java
assertIds(query.apply(snapshot, new VaultFilter("git", null, emptySet())), "c1");
assertIds(query.apply(snapshot, new VaultFilter("工作", null, emptySet())), "c1", "c2");
assertIds(query.apply(snapshot, new VaultFilter("重要", null, emptySet())), "c1");
assertIds(query.apply(snapshot, new VaultFilter("secret", null, emptySet())));
assertIds(query.apply(snapshot, new VaultFilter("", "work", setOf("important", "shared"))), "c1");
assertIds(query.apply(snapshot, new VaultFilter("", null, emptySet())), "c2", "c1", "c3");
```

- [x] **Step 2: Run the test and verify RED**

Run: `powershell -ExecutionPolicy Bypass -File scripts/test-core.ps1`

Expected: compilation fails because `VaultQuery` and `VaultFilter` do not exist.

- [x] **Step 3: Implement search and filter rules**

Normalize search with `Locale.ROOT`; match name, account, URL, resolved category name, and resolved tag names; exclude password and notes; require every selected tag; return an unmodifiable name-sorted result.

- [x] **Step 4: Run the test and verify GREEN**

Run: `powershell -ExecutionPolicy Bypass -File scripts/test-core.ps1`

Expected: all core suites print `PASS` and exit code `0`.

- [x] **Step 5: Commit**

```bash
git add app/src/main/java/com/passwordvault/local/core/query app/src/test/java/com/passwordvault/local/core
git commit -m "feat: add vault search and filtering"
```

### Task 3: Snapshot Mutations and Conflict Protection

**Files:**
- Create: `app/src/test/java/com/passwordvault/local/core/VaultServiceTest.java`
- Create: `app/src/main/java/com/passwordvault/local/core/repository/ConflictException.java`
- Create: `app/src/main/java/com/passwordvault/local/core/repository/NotFoundException.java`
- Create: `app/src/main/java/com/passwordvault/local/core/repository/VaultStore.java`
- Create: `app/src/main/java/com/passwordvault/local/core/repository/InMemoryVaultStore.java`
- Create: `app/src/main/java/com/passwordvault/local/core/repository/VaultService.java`
- Modify: `app/src/test/java/com/passwordvault/local/core/CoreTestMain.java`

**Interfaces:**
- Consumes: `VaultValidator` and immutable domain models.
- Produces: `VaultService.createCredential`, `updateCredential(id, expectedVersion, draft)`, `deleteCredential`, category/tag create/rename/delete, and `clearAll`.
- Produces: `VaultStore.read(): VaultSnapshot` and `VaultStore.replace(VaultSnapshot): void`.

- [x] **Step 1: Write failing mutation tests**

Cover ID/timestamp assignment, version increments, stale-version rejection, delete-category uncategorization, delete-tag disassociation, permanent credential deletion, and clear-all producing an empty snapshot with a higher revision.

- [x] **Step 2: Run and verify RED**

Run: `powershell -ExecutionPolicy Bypass -File scripts/test-core.ps1`

Expected: compilation fails because `VaultService` does not exist.

- [x] **Step 3: Implement mutations with copy-on-write snapshots**

Use injected `Supplier<String>` for IDs and `LongSupplier` for time. Validate every write before calling `VaultStore.replace`; never mutate a collection returned by an existing snapshot.

- [x] **Step 4: Run and verify GREEN**

Run: `powershell -ExecutionPolicy Bypass -File scripts/test-core.ps1`

Expected: all core suites print `PASS` and exit code `0`.

- [x] **Step 5: Commit**

```bash
git add app/src/main/java/com/passwordvault/local/core/repository app/src/test/java/com/passwordvault/local/core
git commit -m "feat: add vault mutation service"
```

### Task 4: Encrypted Android Persistence

**Files:**
- Reuse: Android project configuration and the workflow-pinned Gradle installation.
- Reuse: `app/src/main/java/com/passwordvault/local/core/codec/VaultBinaryCodec.java`
- Reuse: `app/src/main/java/com/passwordvault/local/core/crypto/AesGcmCipher.java`
- Create: `app/src/main/java/com/passwordvault/local/storage/DeviceKeyProvider.java`
- Create: `app/src/main/java/com/passwordvault/local/storage/VaultDatabase.java`
- Create: `app/src/main/java/com/passwordvault/local/storage/EncryptedVaultStore.java`
- Create: `app/src/main/res/xml/backup_rules.xml`
- Create: `app/src/main/res/xml/data_extraction_rules.xml`
- Create: instrumented tests under `app/src/androidTest/java/com/passwordvault/local/storage/`.

**Interfaces:**
- Consumes: `VaultStore` and `VaultSnapshot`.
- Produces: `EncryptedVaultStore(Context)` implementing `VaultStore`.

- [ ] **Step 1: Install/authorize Android Studio, JDK 17+, Android SDK 37, and platform tools**

Verify: `java -version`, `adb --version`, and `sdkmanager --list_installed` show a compatible toolchain.

- [x] **Step 2: Write failing codec and instrumented storage tests**

Assert a snapshot round-trips exactly, the database file does not contain a known password byte sequence, tampered ciphertext is rejected, and replacing a snapshot is atomic.

- [ ] **Step 3: Run and verify RED**

Run: `.\gradlew.bat testDebugUnitTest connectedDebugAndroidTest`

Expected: tests fail because codec and encrypted store are missing.

Status: tests were written before the Android storage types. Local execution is unavailable because
this machine does not have JDK 17 or an Android SDK; the cloud workflow now compiles the test APK.

- [x] **Step 4: Implement binary codec, Keystore AES-256-GCM, and one-row SQLite store**

Use key alias `password_vault_device_key_v1`, a fresh 12-byte nonce per write, 128-bit GCM tag, AAD `PVL-DEVICE-V1`, and a table containing only `singleton_id`, `nonce`, and `ciphertext`. Set `android:allowBackup="false"` and explicit exclusion rules.

- [ ] **Step 5: Run and verify GREEN**

Run: `.\gradlew.bat testDebugUnitTest connectedDebugAndroidTest lintDebug`

Expected: all tests pass and lint reports no errors.

Status: all platform-independent core and browser crypto tests pass locally. Android test APK
compilation, lint, and device execution remain pending on the cloud/Android toolchain.

- [x] **Step 6: Commit**

```bash
git add app gradle gradlew gradlew.bat settings.gradle.kts build.gradle.kts gradle.properties
git commit -m "feat: persist vault with device encryption"
```

### Task 5: First Usable Phone UI

**Files:**
- Create: `app/src/main/java/com/passwordvault/local/MainActivity.java`
- Create: `app/src/main/java/com/passwordvault/local/ui/VaultListController.java`
- Create: `app/src/main/java/com/passwordvault/local/ui/CredentialEditorController.java`
- Create: `app/src/main/java/com/passwordvault/local/ui/TaxonomyController.java`
- Create: XML layouts, strings, colors, dimensions, shapes, and icons under `app/src/main/res/`.
- Create: `app/src/androidTest/java/com/passwordvault/local/VaultUiTest.java`

**Interfaces:**
- Consumes: `VaultService`, `VaultQuery`, and `EncryptedVaultStore`.
- Produces: phone list, detail, add/edit, category/tag management, search/filter, copy, delete confirmation, and clear-all screens.

- [x] **Step 1: Write failing UI tests**

Assert fixed password masking, reveal limited to one record, re-hide on `onStop`, add/edit validation, account/password copy, category/tag management, AND tag filtering, permanent delete confirmation, and clear-all double confirmation.

- [ ] **Step 2: Run and verify RED**

Run: `.\gradlew.bat connectedDebugAndroidTest`

Expected: UI tests fail because the screens do not exist.

Status: Android-free controller tests were observed failing before the UI controllers existed. The
instrumented smoke test is compiled by the cloud workflow; device execution remains pending.

- [x] **Step 3: Implement the approved concise visual style with platform Views**

Use white cards on `#F5F7FA`, primary blue `#2563EB`, success green `#16A34A`, 12dp corners, 16dp page spacing, fixed `••••••••`, and system fonts. Mark copied password clips sensitive on API 33+.

- [ ] **Step 4: Run and verify GREEN**

Run: `.\gradlew.bat connectedDebugAndroidTest lintDebug`

Expected: UI suites pass and lint reports no errors.

Status: controller suites pass on both local runners. Android compilation, lint, and instrumentation
execution remain pending on the cloud/physical Android toolchain.

- [x] **Step 5: Commit**

```bash
git add app/src/main
git commit -m "feat: add phone vault interface"
```

## Phase Completion Check

- [ ] Run `powershell -ExecutionPolicy Bypass -File scripts/test-core.ps1`.
- [ ] Run `.\gradlew.bat testDebugUnitTest connectedDebugAndroidTest lintDebug` after the Android toolchain is available.
- [ ] Confirm every password is masked by default and backgrounding clears reveal state.
- [ ] Confirm the on-disk database contains no known credential plaintext.
- [ ] Confirm no dependency exists outside Android framework, AGP, and the Java/Kotlin standard build toolchain.
