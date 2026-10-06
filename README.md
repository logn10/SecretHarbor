# SecretHarbor

> **Host-level security boundary for AI coding agents and agentic development environments.**  
> *"Do not lock the file. Lock the agent's capability to access the file."*

[![CI](https://github.com/secretharbor/secretharbor/actions/workflows/ci.yml/badge.svg)](https://github.com/secretharbor/secretharbor/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/secretharbor/secretharbor?include_prereleases)](https://github.com/secretharbor/secretharbor/releases)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/security-policy-green.svg)](SECURITY.md)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg?logo=go)](go.mod)
[![Platform Support](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey)](#platform-support-matrix)

---

## What is SecretHarbor?

AI coding agents (Claude Code, Codex, Cursor, Google Antigravity, OpenCode, Amazon Kiro, Ollama, Gemini CLI, Aider, Cline) need read/write access to your workspace to write tests, run builds, and refactor code. However, giving an AI agent unrestricted access to your project exposes:
* Real database credentials, API keys, and `.env` files
* SSH keys (`~/.ssh`) and cloud tokens (`~/.aws`, `~/.config/gcloud`, `~/.azure`)
* Host-level Docker daemon sockets (`/var/run/docker.sock`)
* Local IPC endpoints and unconfined network egress

**SecretHarbor (`shb`)** is a host-level operating system boundary enforced **below the agent**. It intercepts capability requests at the OS kernel layer (Apple Seatbelt on macOS, unprivileged user namespaces, mount isolation, and Landlock on Linux), virtualizing sensitive files with format-preserving synthetic fakes while preserving seamless development for both the human developer and the AI agent.

```text
Host Operating System (Human Developer)
│
├── Real .env (Real API Keys, Database Passwords)
├── Real SSH Keys & Cloud Credentials
│
└── ══════════════════════════════════════════════════════════
    [ SecretHarbor Security Boundary (Kernel Enforced) ]
    ══════════════════════════════════════════════════════
      │
      ├── AI Agent Process (Antigravity, Claude Code, Cursor, OpenCode, Codex, etc.)
      │     ├── Sees Synthetic Format-Preserving Fake Secrets
      │     ├── Outbound Network Policy (Allowed by default, explicit deny supported)
      │     ├── Capability-Gated Docker Daemon Interception
      │     └── Close-on-Exec Sanitized File Descriptors
      │
      └── Sandboxed Child Tasks (bash, pytest, bun test, npm, compiler)
```

---

## Zero-Telemetry & Privacy Guarantee

SecretHarbor is built on a strict **Zero-Telemetry Principle**:
1. **100% Local Execution:** SecretHarbor never transmits your source code, file names, environment variables, credentials, or audit logs to any external server or telemetry service.
2. **Local Encrypted Vault:** Credentials managed via `shb secret` are stored exclusively on your local machine in an AES-256-GCM encrypted vault (`~/.secretharbor/vault.enc`).
3. **Local Audit Logs:** Operational logs are written strictly to your local machine (`~/.secretharbor/audit.log`) with automatic redaction of sensitive values and size-capped rotation limits.
4. **No Tracking or Analytics:** The CLI contains zero analytics trackers, tracking beacons, or telemetry instrumentation.

---

## Platform Support Matrix

| Platform | Tier | Sandboxing Driver | Isolation Primitives | Operational Requirements |
|---|---|---|---|---|
| **macOS (Apple Silicon & Intel)** | **Tier 1 (Production Ready)** | Apple Seatbelt (`sandbox-exec`, `libsandbox`) | Kernel Seatbelt profiles, shadow workspace virtualization, Close-on-Exec FDs, Unix domain socket interception | Supported natively on macOS 12+ |
| **Linux (x86_64 & aarch64)** | **Tier 1 (Production Ready)** | Linux Namespaces & Landlock LSM | Mount namespace filesystem virtualization (`CLONE_NEWUSER`, `CLONE_NEWNS`, `CLONE_NEWIPC`), `PR_SET_DUMPABLE=0`, Close-on-Exec FDs, network proxying | Requires unprivileged user namespaces (`kernel.unprivileged_userns_clone = 1` and `user.max_user_namespaces > 0`). If unprivileged namespaces are disabled, SecretHarbor reports `LIMITED` posture rather than false security claims |
| **Windows (x86_64)** | **Tier 2 (Developer Preview)** | Environment Sanitization & Process Isolation | Process environment sanitization, process group job isolation, restricted tokens | Windows 10/11 x64 |

---

## Security Posture Reporting (`shb status`)

SecretHarbor strictly distinguishes **configuration intent** from **actual active kernel enforcement**:
* A valid `secretharbor.yaml` configuration alone does not constitute "STRONG" security.
* `shb status` interrogates runtime kernel primitives, namespace availability, and process confinement boundaries to report the **true active posture**:
  - `Kernel Enforcement`: active / inactive
  - `Filesystem Isolation`: kernel-enforced (`fake` shadow virtualization) / not enforced / unconfined
  - `Network Isolation`: allow / restricted / deny
  - `Docker Capability`: approval-gated / disabled / allow
  - `Inherited FD Protection`: active (close-on-exec sanitized)
  - `Unsandboxed Escape`: denied
* When a required kernel capability (e.g., Linux user namespaces or Landlock) is unavailable, SecretHarbor reports `LIMITED` or `UNCONFINED` along with diagnostic remediation commands (`sudo sysctl -w kernel.unprivileged_userns_clone=1`), never silently downgrading claims.

---

## Quickstart

### 1. Installation

#### A. One-Line POSIX Installer (macOS & Linux)
```bash
curl -fsSL https://secretharbor.dev/install.sh | sh
```
* Fully POSIX compliant (`/bin/sh`).
* Automatically verifies SHA-256 checksums from `checksums.txt` and validates against signed release metadata.
* Installs `shb`, `secretharbor` binary alias, and Unix manual pages to `man1/`.

#### B. One-Line PowerShell Installer (Windows)
```powershell
irm https://secretharbor.dev/install.ps1 | iex
```
* Verifies SHA-256 hash against `checksums.txt` via `Get-FileHash`.
* Installs to `$env:LOCALAPPDATA\Programs\SecretHarbor` and updates user `PATH`.

#### C. Homebrew (macOS & Linux)
```bash
brew tap secretharbor/tap
brew install secretharbor
```

#### D. WinGet (Windows)
WinGet packaging is generated from published release artifacts. Until the first
signed release is published, install on Windows from the release archive or build
from source.

#### E. From Source (Go 1.22+)
```bash
git clone https://github.com/secretharbor/secretharbor.git
cd secretharbor
make build
make man
sudo make install
```

### 2. Initialize SecretHarbor

Navigate to any project repository and run:
```bash
shb init
```
SecretHarbor automatically:
- Detects installed AI agents (`claude`, `codex`, `gemini`, `cursor`, `antigravity`, `opencode`, `kiro`, `ollama`, `vscode`, etc.)
- Installs transparent launcher shims (`~/.secretharbor/shims`)
- Configures your shell profile `PATH` (`~/.zshrc` or `~/.bashrc`)
- Generates a minimal, preset-driven `secretharbor.yaml` policy file

*(Tip: Run `shb init --force` at any time to upgrade an existing project's config to the latest default template).*

### 3. Run Agents Seamlessly

#### A. CLI Agents (Terminal)
Launch your CLI agents normally in any terminal window:
```bash
claude
# or
codex
# or
ollama run codellama
```
The shell shims intercept execution and launch the process inside the SecretHarbor sandbox.

#### B. Desktop GUI Applications (Antigravity, OpenCode, VS Code, Cursor)
On macOS, applications launched from the **Dock, Spotlight, or Finder** are spawned directly by `launchd` and bypass your shell's `$PATH`. To run desktop apps sandboxed:

**Option 1: Launch Sandboxed in Background (`-d` / `--detach`)**:
```bash
shb run -d antigravity-app
shb run -d opencode-app
shb run -d vscode-app
shb run -d cursor-app
```
*(The `-d` flag detaches the application, freeing your terminal immediately. Stop it anytime with `shb stop <app>`)*.

**Option 2: Adopt Already-Running Desktop Apps (`shb adopt`)**:
If you launched an app from the Dock, run:
```bash
shb adopt
```
SecretHarbor terminates the unconfined process tree and relaunches it inside the sandbox boundary.

---

## Key Capabilities

### 1. Transparent Secret Virtualization
Agents often crash if `.env` is simply hidden or blocked with `EPERM`. SecretHarbor generates **format-preserving synthetic credentials**:
* `STRIPE_SECRET_KEY` $\to$ `sk_test_secretharbor_fake_...` (valid checksum format)
* `OPENAI_API_KEY` $\to$ `sk-proj-secretharbor-fake-...`
* `ANTHROPIC_API_KEY` $\to$ `sk-ant-api03-secretharbor-fake-...`
* `AWS_ACCESS_KEY_ID` $\to$ `AKIAFAKEHARBOR...`
* `DATABASE_URL` $\to$ `postgresql://secretharbor_user:fake_password@localhost:5432/fake_db?sslmode=disable`
* `GITHUB_TOKEN` $\to$ `ghp_secretharbor_fake_...`

#### Credential Coverage
SecretHarbor automatically discovers, isolates, and virtualizes:
- **Environment files:** `.env`, `.env.local`, `.env.development`, `.env.test`, `.env.staging` (`.env.production` and `secrets/**` are denied by default)
- **Cloud tokens:** AWS (`~/.aws/credentials`), GCP (`~/.config/gcloud`), Azure (`~/.azure`)
- **Keys & Certificates:** SSH private keys (`~/.ssh/id_*`), TLS private keys (`*.pem`, `*.key`)
- **Database connection strings:** PostgreSQL, MySQL, Redis, MongoDB URIs
- **Custom variables:** User-defined secret patterns via `secretharbor.yaml`

#### Shadow Workspace Virtualization (macOS) & Mount Virtualization (Linux)
In default protection mode (`mode: fake`), **your real secret files are never modified**. The agent runs inside a per-session virtualized view:

1. **Shadow Workspace (macOS):** Before launch, SecretHarbor creates an ephemeral mirror of the project under the system temp directory. Non-secret files are hard-linked (so agent edits flow to the real project), secret files are replaced with format-preserving synthetic fakes, and control-plane files (`secretharbor.yaml`) are exposed read-only. The real `.env` on disk is untouched.
2. **Mount Virtualization (Linux):** Inside the agent's mount namespace, synthetic fakes are bind-mounted over the real secret paths. The host files are never changed, and only sandboxed processes see fakes.
3. **Auto-Inject:** Synthetic values from `.env` are also merged into the agent's process environment, so `process.env.<KEY>` is always defined.
4. **Humans and test runners keep real values:** Your editor, your shell, and `bun test` / `pytest` / `npm test` run outside the sandbox see the **real** `.env`, even while an agent session is active. Agents and their child processes see fakes.
5. **No crash-recovery needed:** Because the real files are never swapped, a `kill -9`, crash, or reboot cannot leave fakes on disk. Stale shadow workspaces are reclaimed automatically; `shb restore` remains available for legacy in-place swap sessions.
6. **Live editing:** Edit the real `.env` in VS Code, Cursor, or Vim at any time; run `shb env edit` to open the real file. A running agent session keeps its synthetic copy — restart the session to pick up new values. Agent-created and agent-edited non-secret files are synced back when the session ends.

### 2. Outbound Network Policy: Allowed by Default with Explicit Deny
SecretHarbor permits all outbound network calls by default, giving agent workflows native network speed without local proxy overhead:
```yaml
network:
  mode: allow
  # Optional: explicitly deny specific domains
  # deny:
  #   - telemetry.example.com
  #   - tracking.evil.com
```
When `network.deny` entries exist, SecretHarbor's forward proxy activates automatically and returns `403 Forbidden` for blocked domains and their subdomains.

For stricter policies, `network.mode: restricted` (domain allowlist) and `network.mode: deny` are **kernel-enforced on macOS**: Seatbelt blocks all non-loopback egress, so only the local forward proxy can reach the network and raw socket clients fail closed with `Operation not permitted`. On Linux, restricted mode is proxy-based and `shb status` reports it as such. `shb doctor` probes raw egress and reports `FAIL` if a restricted/deny policy is bypassable on the running platform.

### 3. Docker Capability Interception
Instead of completely denying Docker (which breaks developer workflows), SecretHarbor provides **capability-based interception**:
* In `standard` mode, SecretHarbor intercepts requests to `/var/run/docker.sock` via an ephemeral proxy socket (`DOCKER_HOST`).
* When the agent invokes `docker`, SecretHarbor suspends the agent (`SIGSTOP`) and prompts the human user via a native desktop modal or secondary CLI (`shb approve <id>`).
* Approved access is scoped to a temporary 10-minute lease.

### 4. Process Hierarchy & Whole-Tree Termination
Inspect running agents and their exact security boundary:
```bash
shb status
```
Output:
```text
Antigravity (PID 58342)
  │
  ══════════════════════════════════════════════════════
  [SecretHarbor Security Boundary - standard policy]
  ══════════════════════════════════════════════════════
    │
    ├── UI (Renderer, PID 58357)
    ├── Language Server / Agent Host (PID 58375)
    └── sandboxed task (PID 58491)
```
* **Instant `Ctrl+C` Termination:** Pressing `Ctrl+C` once sends whole-tree `SIGTERM`/`SIGKILL` signals to all child helpers (GPU, Renderer, crashpad, Node workers), exiting cleanly with status 130 without leaving orphaned processes.

### 5. Adversarial Security Doctor
Run SecretHarbor's built-in 18-vector live attack suite:
```bash
shb doctor
```
Simulates direct reads, symlink evasions, path traversals, interpreter reads (Python, Node.js), descriptor leaks, Docker socket access, container secret inspection, and policy file tampering.

### 6. Audit Logging & Redaction Limits
* Operational audit trail is stored locally at `~/.secretharbor/audit.log`.
* All secret values are automatically redacted before disk write (`[REDACTED]`).
* Log files are capped and rotated to prevent unbounded disk growth.

### 7. Cryptographic Release Verification
All self-updates and release artifacts are cryptographically signed:
* **Integrity:** SHA-256 hash verified against manifest checksums.
* **Authenticity:** Ed25519 digital signature verified against the official SecretHarbor release public key (`e8ad8a74ba9288a266a4cbe3a044b6482688ac37de8d39b9137d182e25978011`).
* **Transport:** All release downloads strictly require HTTPS.
* **Archive Protection:** Built-in defenses against decompression bombs (256 MB safety limit) and zip-slip directory traversals.

---

## Command Reference

| Command | Usage | Description |
|---|---|---|
| `shb init` | `shb init [--yes] [--force]` | Initialize host integration, shims, and project policy (`--force` overwrites) |
| `shb status` | `shb status` | Inspect live kernel protection status, active sessions, and process trees |
| `shb adopt` | `shb adopt [--yes]` | Discover and adopt unprotected running agents |
| `shb restart` | `shb restart [agent]` | Cleanly restart an agent inside a fresh sandbox |
| `shb run` | `shb run [-d] <agent> \| shb run -- <cmd>` | Execute an agent or arbitrary command (`-d` runs detached in background) |
| `shb stop` | `shb stop <agent\|session_id>` | Terminate an active sandboxed agent session and process tree |
| `shb sessions` | `shb sessions` | List active sandboxed sessions |
| `shb config` | `shb config [show\|get\|set\|check\|diff]` | Read-only effective policy viewer and updater |
| `shb policy` | `shb policy explain <resource>` | Explain why a resource or network domain is allowed, virtualized, or denied |
| `shb secret` | `shb secret [status\|test\|set\|delete]` | Manage local encrypted vault credentials |
| `shb env` | `shb env [edit]` | Edit the real `.env` in $EDITOR (agents keep synthetic values) |
| `shb restore` | `shb restore [path\|--all\|--orphans]` | Restore legacy in-place swap sessions (recovery only) |
| `shb trust` | `shb trust [list\|add\|remove]` | Manage trusted processes |
| `shb doctor` | `shb doctor` | Execute 18-vector live adversarial attack suite |
| `shb guard` | `shb guard [on\|off]` | Toggle protection boundary for the current project |
| `shb update` | `shb update [--check] [--version <v>] [--dry-run]` | Check for and install verified updates with Ed25519 signature checks |
| `shb version` | `shb version` | Show version, platform, kernel, and sandbox driver details |
| `shb help` | `shb help [command]` | Display comprehensive usage or command-specific reference manual |

---

## Security Invariants

* **Fail-Closed Guarantee:** If the OS security boundary fails to initialize, SecretHarbor refuses to start the agent. It will never silently fall back to unconfined execution.
* **Agent Lockout:** Sandboxed agents cannot execute `shb update`, `shb guard off`, or `shb config edit`. Administrative operations are strictly human-controlled.
* **No Retroactive Sandboxing:** An already-running agent process cannot be retroactively confined safely. Pre-existing processes are marked `UNPROTECTED` until restarted via `shb adopt` or `shb restart`.
* **Universal Untrusted Fallback:** Any command or unknown binary executed via `shb run` defaults to `Runtime: process, Integration: unknown` under full standard sandbox protections.

---

## License

SecretHarbor is open-source software licensed under the [Apache License, Version 2.0](LICENSE).
