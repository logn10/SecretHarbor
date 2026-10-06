# Contributing to SecretHarbor

Thank you for your interest in contributing to **SecretHarbor**! SecretHarbor is an open-source, host-level security boundary for AI coding agents and developer environments.

## Development Prerequisites

* **Go:** Version 1.22 or higher
* **Make:** GNU Make
* **OS:** macOS (Apple Silicon / Intel) or Linux (x86_64 / arm64)
* **Git:** Standard git toolchain

## Development Workflow

### 1. Clone the Repository
```bash
git clone https://github.com/logn10/SecretHarbor.git
cd secretharbor
```

### 2. Build from Source
Compile both `shb` and `secretharbor` binaries:
```bash
make build
```
Binaries will be placed in `./bin/shb` and `./bin/secretharbor`.

### 3. Generate Man Pages
Documentation and Unix manual pages are generated deterministically:
```bash
make man
```
Ensure that `git diff man/man1` produces no unexpected diffs after modifying command metadata.

### 4. Run the Test Suite
```bash
go test -v -race ./...
```
Or for updater and documentation tests:
```bash
go test -v ./internal/updater/... ./internal/docs/...
```

### 5. Run the Adversarial Security Doctor
```bash
./bin/shb doctor
```
Verifies that all 14 adversarial attack vectors remain blocked by the security boundary.

## Code Standards and Guidelines

* **Formatting:** All Go code must be formatted using `go fmt` and follow standard Go idioms.
* **Architecture:** The security boundary must remain enforced *below the agent*. Avoid user-space path checks that can be raced (TOCTOU). Prefer kernel-level primitives.
* **Zero Telemetry:** Never add network calls that report user telemetry, usage data, or credentials.
* **Deterministic Builds:** Tooling must respect `SOURCE_DATE_EPOCH` and produce reproducible output.
* **Error Handling:** Avoid raw stack traces or unexplained panics. Network and update checks must fail gracefully with human-friendly diagnostics.

## Submitting Pull Requests

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/my-feature
   ```
2. Write clean, focused commits with clear messages.
3. Include tests covering new functionality or bug fixes.
4. Ensure `make man` and `go test ./...` pass cleanly.
5. Open a Pull Request on GitHub targeting `main`.

## Releasing

Releases are published from Git tags and require no manual artifact uploads:

1. Ensure `main` is green (CI) and the working tree is clean.
2. Create and push a SemVer tag:
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```
3. The `SecretHarbor Release` workflow runs GoReleaser on macOS and publishes, for each platform:
   - `secretharbor_<version>_<os>_<arch>.tar.gz` (Windows: `.zip`) containing `shb`, `secretharbor`, README, LICENSE, and man pages,
   - `checksums.txt` (SHA-256),
   - `manifest.json` (version, artifact URLs, hashes, and Ed25519 signatures when `RELEASE_SIGNING_KEY` is configured),
   - `install.sh` and `install.ps1` for the one-line installers.
4. The installer and `shb update` resolve releases from GitHub:
   - `https://github.com/logn10/SecretHarbor/releases/latest/download/install.sh`
   - `shb update` fetches `manifest.json` from the same release.

Optional secrets:
- `RELEASE_SIGNING_KEY` — hex-encoded Ed25519 private key used to sign artifacts. Without it, `manifest.json` is published without signatures and `shb update` refuses the update (fail closed). The corresponding public key must be set in `internal/updater/verifier.go`.
- `APPLE_CERTIFICATE_BASE64`, `APPLE_CERTIFICATE_PASSWORD`, `KEYCHAIN_PASSWORD` — optional Developer ID signing for macOS binaries.

## Code of Conduct

All contributors and maintainers are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md).
