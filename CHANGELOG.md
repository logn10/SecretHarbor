# Changelog

All notable changes to SecretHarbor will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-10-06

### Added
* **Ed25519 Cryptographic Verification:** Integrated Ed25519 signature verification into `shb update` and release manifest pipeline, distinguishing SHA-256 checksum validation from cryptographic authenticity checks.
* **Zip-Slip & Decompression Bomb Defenses:** Protected release archive extraction against path traversal attempts (`../`) and unbounded extraction exhaustion (256 MB safety limit).
* **Package Manager Distributions:** Canonical formulas for Homebrew (`Formula/shb.rb`, `Formula/secretharbor.rb`) and WinGet (`packaging/winget/SecretHarbor.SecretHarbor.yaml`).
* **Complete Manual Pages:** Generated Unix man pages for all subcommands including `shb-version(1)` and `shb-help(1)`.
* **Repository Hygiene & Security Policies:** Added `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `LICENSE` (Apache-2.0), and comprehensive `.gitignore`.

### Changed
* **Canonical Installers:** Refactored `scripts/install.sh` and `scripts/install.ps1` to match GoReleaser archive naming conventions, verify SHA-256 hashes against `checksums.txt`, and eliminate insecure local binary fallbacks.
* **Deterministic Builds:** Pinned documentation generation dates with `SOURCE_DATE_EPOCH` support and sorted map iteration orders in `internal/docs/man.go`.
* **Go 1.22 Toolchain Compatibility:** Standardized `go.mod` on Go 1.22 with direct dependencies for `golang.org/x/sys` and `gopkg.in/yaml.v3`.
* **Version Unification:** Unified release version to `0.4.0` across updater, packaging, and CLI runtime.

### Fixed
* **Version Injection:** Changed `cli.Version` from constant to variable to permit `-ldflags` version injection during automated builds.
* **Update Network Failures:** Gracefully handled DNS and network resolution failures in `shb update --check` with human-readable error messages.
* **Downgrade Protection:** Enforced strict downgrade prevention in `shb update` unless explicitly requested via `--version`.
* **PowerShell Syntax:** Fixed `${Version:-latest}` variable syntax in `scripts/install.ps1`.
