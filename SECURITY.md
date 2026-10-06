# Security Policy

SecretHarbor is a host-level security boundary designed to protect credentials and sensitive system capabilities from entering untrusted AI agent context. We take the security of SecretHarbor and our users' machines with the utmost seriousness.

## Supported Versions

| Version | Supported | Status |
|---|---|---|
| `0.4.x` | :white_check_mark: | Active production release branch |
| `< 0.4.0` | :x: | End of Life / Unsupported |

## Threat Model and Security Guarantees

SecretHarbor enforces security boundaries **below the agent** using OS kernel primitives:
* **macOS:** Apple Seatbelt (`sandbox-exec`, `libsandbox`) kernel profiles.
* **Linux:** Linux Namespaces (`CLONE_NEWUSER`, `CLONE_NEWNS`, `CLONE_NEWIPC`) and Landlock LSM where supported.
* **Windows:** Process isolation, job object boundaries, and environment sanitization.

### Security Invariants
1. **Agent Lockout:** AI agents cannot disable their own security boundary, edit project policies, or trigger self-updates.
2. **Fail-Closed Guarantee:** If kernel security boundaries cannot be initialized, SecretHarbor refuses to launch the agent process.
3. **Zero-Telemetry Principle:** SecretHarbor never transmits source code, file paths, credentials, or audit logs off your machine.
4. **Cryptographic Release Verification:** All releases and self-updates are cryptographically verified using SHA-256 checksums and Ed25519 digital signatures.

## Reporting a Vulnerability

If you discover a security vulnerability or potential sandbox bypass in SecretHarbor:

> **Please DO NOT file a public GitHub issue.**

Instead, report the vulnerability through coordinated disclosure:
1. **Email:** Send details to [security@secretharbor.dev](mailto:security@secretharbor.dev).
2. **GitHub Security Advisories:** Submit a private vulnerability report via [GitHub Security Advisory](https://github.com/secretharbor/secretharbor/security/advisories/new).

### What to Include in Your Report
To help us triage and resolve the issue quickly, please include:
* Operating system name, version, and architecture (`uname -a`).
* SecretHarbor version (`shb version`).
* Description of the vulnerability or sandbox escape vector.
* Minimal reproducible proof-of-concept (PoC) script or test case.
* Any impact analysis or potential exploit scenario.

## Response Timeline
* **Initial Acknowledgement:** Within 48 hours of receipt.
* **Triage & Assessment:** Within 5 business days.
* **Patch & Disclosure:** Coordinated release with CVE assignment where appropriate.
