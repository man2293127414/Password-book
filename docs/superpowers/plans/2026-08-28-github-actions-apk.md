# GitHub Actions APK Delivery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a tested, consistently signed Android APK in GitHub Actions for direct installation on the user's phone.

**Architecture:** A manually triggered workflow checks out the private repository, installs JDK 17 and Gradle 9.4.1, restores the signing keystore from encrypted repository secrets, runs all available tests and lint, builds a signed release APK, verifies its signature, and uploads only the APK as an Actions Artifact. No signing material is committed or printed.

**Tech Stack:** GitHub Actions; `actions/checkout@v7`; `actions/setup-java@v6`; `actions/setup-node@v7`; `gradle/actions/setup-gradle@v6`; `actions/upload-artifact@v7`; Temurin JDK 17; Node.js 24; Gradle 9.4.1; Android Gradle Plugin 9.2.0; Android SDK 37.

**Spec:** `docs/superpowers/specs/2026-08-27-offline-password-vault-design.md`

## Global Constraints

- Workflow trigger is `workflow_dispatch` only.
- Repository permission is `contents: read`.
- Tests and lint must pass before APK assembly.
- Release signing uses `ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, and `ANDROID_KEY_PASSWORD` GitHub Secrets.
- The keystore is reconstructed only under `$RUNNER_TEMP` and deleted by runner teardown.
- Secret values must never be echoed or included in artifacts.
- The workflow uploads one installable signed APK and no database, logs containing secrets, keystore, or intermediate signing files.
- The same signing key must be preserved for all future APK versions so upgrades do not require uninstalling the app.

---

### Task 1: Cross-Platform Build and Core Test Entry Point

**Files:**
- Create: `settings.gradle.kts`, root `build.gradle.kts`, `gradle.properties`, and `app/build.gradle.kts`.
- Create: `scripts/test-core.sh` matching `scripts/test-core.ps1` behavior on Linux.
- Modify: `.gitignore` for Android local/build/signing outputs.

- [x] Add a shell test script that compiles all dependency-free core sources and runs `CoreTestMain` with JDK 17.
- [x] Run the script through a POSIX shell and confirm the same suites pass as PowerShell; repeat on GitHub Ubuntu/JDK 17 in Task 3.
- [x] Pin Gradle `9.4.1` through the official `gradle/actions/setup-gradle@v6` action; do not commit a partial wrapper when the wrapper JAR cannot be verified locally.
- [x] Commit the Android Gradle project together with the signing workflow in one cohesive build-stage commit.

### Task 2: Stable Release Signing

**Files:**
- Modify: `app/build.gradle.kts`.
- Create: `scripts/prepare-signing.sh`.
- Create: `scripts/verify-apk.sh`.

- [x] Add a test mode using a temporary generated keystore and prove `prepare-signing.sh` writes only beneath the requested temporary directory.
- [x] Configure Gradle release signing exclusively through environment variables and the temporary keystore path.
- [x] Make configuration fail with a clear non-secret error if any required signing input is absent.
- [x] Add APK verification with `apksigner verify --verbose --print-certs`; execute it against the first cloud-built APK in Task 4.
- [x] Commit secure release signing together with the workflow so no unsigned release path is introduced.

### Task 3: Manual GitHub Actions APK Workflow

**Files:**
- Create: `.github/workflows/build-apk.yml`.

- [x] Add `workflow_dispatch`, `permissions: contents: read`, `ubuntu-latest`, official Action versions, JDK 17, and Gradle 9.4.1.
- [x] Run `scripts/test-core.sh`, browser WebCrypto tests, `gradle lintDebug`, signed `gradle assembleRelease`, and `scripts/verify-apk.sh` in that order. Do not run an empty JUnit task because core tests use their own executable harness.
- [x] Upload `app/build/outputs/apk/release/app-release.apk` as artifact `password-vault-apk`, failing if the path is absent.
- [x] Validate workflow structure and pinned Action inputs by review; GitHub performs the authoritative YAML/build validation in Task 4.

### Task 4: First Remote Build and Download Verification

**External setup:**
- Create or select a private GitHub repository.
- Push the completed implementation branch after user authorization.
- Generate one long-lived Android signing keystore and give the user a secure offline copy.
- Configure the four repository secrets without exposing their values in chat or logs.

- [ ] Manually run `Build signed APK` from GitHub Actions.
- [ ] Confirm every test/lint/build/signature step is green.
- [ ] Download `password-vault-apk` and verify its SHA-256 locally.
- [ ] Give the user the GitHub Artifact download location and SHA-256.
- [ ] After real-device installation, capture issues as failing regression tests before fixes.
