# SecretHarbor — Production Development Specification v2

**Project name:** SecretHarbor  
**Primary domain:** secretharbor.dev  
**Purpose:** Host-level security boundary for AI agents and their tools, with secret virtualization and capability-controlled secret use.

## 1. Mission

Build **SecretHarbor**, a host-level security layer for AI coding agents and agentic development environments.

SecretHarbor must prevent an untrusted AI agent from obtaining protected credentials or weakening its own security policy, while preserving normal human access to the same secrets.

The core principle is:

> **Do not lock the file. Lock the agent's capability to access the file.**

The security boundary must be enforced below the agent, using OS/process-level security primitives. Agent instructions, prompts, skills, MCP policies, IDE extensions, or configuration files alone are not security boundaries.

---

# 2. Primary Security Goal

SecretHarbor protects secrets and security-sensitive local capabilities from entering AI-agent-controlled process context.

Protected resources include, but are not limited to:

- `.env`
- `.env.local`
- `.env.production`
- API keys
- database credentials
- cloud credentials
- SSH private keys
- TLS/private keys
- credential files
- authentication tokens
- password files
- secret environment variables
- privileged local IPC endpoints
- other user-configured sensitive paths

The product must be agent-agnostic.

It should eventually support agents such as:

- Claude Code
- Codex
- Gemini CLI
- Cursor agents
- VS Code agents
- Antigravity
- Claude Desktop / other desktop agent hosts
- arbitrary CLI-based agents

Agent-specific integrations are adapters and UX helpers. They must not be the underlying security boundary.

---

# 3. Non-Goals

SecretHarbor is NOT:

- a prompt-injection detector
- a system-prompt security mechanism
- merely a `.gitignore` replacement
- merely an IDE extension
- merely a secret scanner
- merely a vault
- merely a container wrapper
- a product that asks the AI agent to obey policy

SecretHarbor must enforce restrictions even when the agent is malicious, prompt-injected, or intentionally attempting to bypass restrictions.

---

# 4. Threat Model

Assume the AI agent is fully untrusted.

The agent may:

1. Execute arbitrary shell commands.
2. Execute Python, Node, Ruby, Go, Perl, etc.
3. Spawn child processes.
4. Spawn grandchildren and deeper process trees.
5. Invoke MCP servers.
6. Invoke arbitrary local tools.
7. Inspect environment variables.
8. Inspect process arguments.
9. Inspect accessible file descriptors.
10. Create symlinks.
11. Attempt path traversal.
12. Create hard links where the platform permits.
13. Rename files.
14. Copy files.
15. Archive files.
16. Pipe data through arbitrary programs.
17. Modify project files.
18. Modify shell startup files.
19. Modify PATH.
20. Modify its own configuration.
21. Modify SecretHarbor configuration.
22. Kill or interfere with SecretHarbor processes.
23. Launch another copy of itself.
24. Attempt to invoke an unsandboxed shell.
25. Attempt to use network access to exfiltrate secrets.
26. Intentionally misuse credentials exposed to child runtimes.
27. Exploit symlinks, alternate paths, mount points, namespace tricks, or equivalent filesystem mechanisms.
28. Attempt sandbox escape.
29. Access privileged local daemons through Unix sockets or equivalent IPC.
30. Exploit inherited file descriptors or already-open resources.
31. Inspect or attach to other local processes when platform controls permit.
32. Abuse local developer tooling such as Docker, SSH agent, cloud credential helpers, browser debugging interfaces, or credential-manager sockets.

The design must assume malicious behavior rather than cooperative behavior.

---

# 5. Security Invariants

These are mandatory product requirements.

## 5.1 Agent cannot weaken its own policy

An agent MUST NOT be able to:

- modify the active SecretHarbor policy
- disable SecretHarbor
- replace SecretHarbor binaries
- modify SecretHarbor's policy database
- restart SecretHarbor with weaker settings
- launch itself outside the enforced sandbox
- alter enforcement state
- grant itself capabilities
- modify credentials stored by SecretHarbor
- change security settings that affect its own sandbox

## 5.2 Human access remains normal

The human must be able to:

- read secrets
- edit secrets
- copy secrets
- delete secrets
- rename secrets
- import secrets
- export secrets when explicitly permitted
- use normal editors and terminals

SecretHarbor should not require the user to abandon normal filesystem workflows.

## 5.3 Protected files are protected from the agent, not globally

Do not globally lock `.env`.

A trusted human process and an untrusted agent process may interact with the same underlying resource under different capabilities.

## 5.4 Policy enforcement must be below the agent

Policy should flow:

    Human configuration
            |
            v
      Policy compiler
            |
            v
    OS-level enforcement
            |
            v
       Agent process
            |
       child processes
            |
       grandchildren

The agent is never the authority deciding whether it is allowed to access something.

## 5.5 Network and IPC restrictions are part of the security model

Filesystem protection alone is insufficient.

The agent must not be able to bypass filesystem controls by using:

- arbitrary network destinations
- privileged local sockets
- abstract Unix sockets
- inherited service endpoints
- credential-helper IPC

## 5.6 Security claims must match tested enforcement

SecretHarbor MUST NOT claim a universal "impossible to bypass" guarantee.

Security claims must be qualified by:

- operating system
- supported version
- enforcement mechanism
- privileges required
- documented threat model
- tested limitations

---

# 6. Secret Access Model

SecretHarbor has three primary secret visibility modes.

## allow

The agent receives the actual value.

Use sparingly.

```yaml
secrets:
  mode: allow
```

## fake

The agent receives a synthetic value instead of the real secret.

```yaml
secrets:
  mode: fake
```

Fake values should preserve useful structural properties where practical without being derived from the real secret.

## deny

The agent receives no value.

```yaml
secrets:
  mode: deny
```

Access should fail using platform-appropriate permission semantics where possible.

---

# 7. Separate "Read" From "Use"

This is a core architectural feature.

A secret should not necessarily have to be exposed to an agent merely because the agent needs to perform an operation requiring that secret.

Conceptual example:

```yaml
secrets:
  DATABASE_URL:
    read: fake
    use:
      enabled: true
      hosts:
        - db.internal
```

Desired security model:

    Agent
      |
      | requests authorized operation
      v
    SecretHarbor broker
      |
      | obtains real credential without exposing it
      v
    Approved destination

The agent should know only the fake/public representation.

This must be implemented through a controlled runtime/broker/proxy rather than putting the real credential into the agent environment.

---

# 8. Configuration Philosophy

The public configuration must be simple.

Do NOT require users to repeatedly specify:

```yaml
read: fake
write: deny
delete: deny
rename: deny
copy: deny
```

for every secret.

SecretHarbor should be opinionated.

The normal configuration should be approximately:

```yaml
version: 1

protection: standard
```

or:

```yaml
version: 1

secrets:
  mode: deny
```

Users should specify exceptions, not restate defaults.

Example:

```yaml
version: 1

protection: standard

secrets:
  mode: fake

exceptions:
  allow:
    - .env.example

  deny:
    - .env.production
    - secrets/**
```

---

# 9. Built-In Secret Detection

SecretHarbor should recognize common secret locations automatically.

Initial built-in patterns:

```text
.env
.env.*
*.pem
*.key
*.p12
*.pfx
credentials.json
credentials.yml
credentials.yaml
.aws/credentials
.aws/config
.ssh/*
.gnupg/*
```

Do not rely exclusively on filename detection.

Support explicit user rules as an override.

Future versions may add:

- content-based secret detection
- entropy detection
- provider-specific patterns
- secret scanner integration

Content scanning is supplementary and must not replace explicit policy.

---

# 10. Minimal Configuration

Recommended standard configuration:

```yaml
version: 1

protection: standard
```

Strict configuration:

```yaml
version: 1

protection: strict
```

Slightly customized:

```yaml
version: 1

protection: standard

secrets:
  mode: fake

exceptions:
  allow:
    - .env.example

  deny:
    - .env.production
    - secrets/**
```

Advanced configuration can exist, but it should not be necessary for ordinary users.

---

# 11. Environment Variable Isolation

Protect environment variables in addition to files.

The agent MUST NOT inherit real secrets simply because the human shell has them.

Bad:

```text
Human shell
  |
  +-- STRIPE_SECRET_KEY=REAL
  |
  +-- launches agent
          |
          +-- env
                |
                +-- REAL SECRET
```

Desired:

```text
Human shell
  |
  +-- REAL SECRET
  |
  +-- launches SecretHarbor
          |
          +-- agent
                |
                +-- STRIPE_SECRET_KEY=FAKE
```

SecretHarbor must sanitize inherited environment variables.

Example:

```yaml
environment:
  mode: sanitize

  allow:
    - HOME
    - PATH
    - SHELL
    - PWD
    - USER
    - LANG
    - TERM

  fake:
    - DATABASE_URL
    - STRIPE_SECRET_KEY
    - OPENAI_API_KEY

  deny:
    - AWS_SECRET_ACCESS_KEY
    - AWS_SESSION_TOKEN
    - SSH_AUTH_SOCK
    - DOCKER_HOST
```

The system should also identify variables that expose privileged local services, including but not limited to:

- `SSH_AUTH_SOCK`
- `DOCKER_HOST`
- `CONTAINER_HOST`
- `KUBECONFIG`
- credential-helper endpoints
- custom local broker/socket variables

Do not assume variable-name filtering is sufficient. Explicitly configured secret variables must always be handled.

---

# 12. Filesystem Security

Protected paths must be inaccessible according to policy even when the agent uses alternative mechanisms.

Security decisions MUST NOT rely on a userspace sequence such as:

    stat(path)
       |
       v
    inspect path
       |
       v
    allow/deny
       |
       v
    open(path)

That creates a Time-of-Check to Time-of-Use race.

Instead:

> Filesystem security MUST be enforced by an OS security mechanism at the actual filesystem operation.

Do not describe the security requirement as "userspace inode checking."

The requirement is:

> **Kernel-enforced filesystem hierarchy policy with no userspace TOCTOU dependency.**

The test suite must cover:

```bash
cat .env
head .env
tail .env
less .env
more .env
sed .env
grep .env
awk .env
strings .env
```

Interpreters:

```bash
python
node
ruby
perl
go
```

Archive/copy:

```bash
cp
mv
tar
zip
gzip
dd
```

Indirect access:

```text
symlinks
path traversal
relative paths
absolute paths
hard links
renames
mounts where applicable
alternate path representations
```

The agent must also be prevented from replacing a protected file with a malicious file and then obtaining the original content through another path.

---

# 13. Filesystem Namespace / TOCTOU Controls

SecretHarbor MUST address namespace manipulation explicitly.

In a protected directory hierarchy, the sandbox policy should restrict, as appropriate:

- creation of symlinks
- creation of hard links
- protected-file deletion
- protected-file replacement
- cross-directory rename
- reparenting of protected objects
- mutation of directories containing protected resources

For Linux implementations using Landlock, use the strongest available hierarchy and link/rename controls supported by the running kernel.

Do not build security correctness around pre-resolving a pathname in userspace.

Where the platform does not provide an equivalent atomic security primitive, document the limitation rather than pretending path checks are sufficient.

### macOS Filesystem Virtualization Semantics (Seatbelt vs. Linux Mount Namespaces)

On Linux, kernel mount namespaces (`CLONE_NEWNS`) permit mounting synthetic fake secret files directly over the host path within the agent's private namespace, ensuring both relative and absolute paths resolve to virtualized content.

On macOS, Apple Seatbelt (`sandbox-exec`, `libsandbox`) operates at the kernel authorization layer: it can permit or deny system calls, but cannot transparently rewrite or redirect path arguments in-kernel:

1. **In-Place Secret Swap & Auto-Inject Architecture**:
   SecretHarbor implements in-place secret swapping for native developer experience and seamless test runner compatibility (`bun test`, Node, Python):
   - **Vault Backup**: Before sandboxed launch, real secrets are backed up to `~/.secretharbor/vault/shadow_backups/<project_hash>/` (permission mode `0600`).
   - **In-Tree Synthetic Swap**: Format-preserving synthetic values are written directly in-place at the project path (`projectDir/.env`).
   - **Kernel Lockdown**: Apple Seatbelt denies `~/.secretharbor/vault` from sandboxed reads/writes, while permitting reads to the in-tree synthetic file so test runners and runtimes succeed without flags or errors.
   - **Auto-Inject**: Format-preserving synthetic environment variables are extracted and injected into `cmd.Env`, ensuring `process.env.<KEY>` is always defined across runtimes.
   - **Live Reconciliation**: Modifications made to `.env` in VS Code or editors during an active session are reconciled upon exit via a 3-way merge, ensuring newly added configuration keys are preserved and real secrets are restored without data loss.
   - **Fail-Safe Crash Recovery**: Write-Ahead Journaling (`active_swaps.json`), signal traps, pre-flight auto-cleanup, and `shb restore` protect against unexpected crashes, force quits, or system reboots.

---

# 14. File Mutation Rules

A protected secret policy should implicitly protect the protected namespace from agent mutation.

In standard/strict modes, the agent should not be able to:

- overwrite protected secrets
- delete protected secrets
- rename protected secrets
- move protected secrets
- create links to protected secrets
- replace protected paths
- alter protected parent directories in a way that bypasses controls

Human processes remain unrestricted.

SecretHarbor MUST prefer fail-closed behavior in strict mode.

---

# 15. Process Tree Security

Restrictions MUST propagate to agent-created children.

Example:

```text
Agent
 |
 +-- bash
      |
      +-- python
           |
           +-- node
                |
                +-- malicious process
```

Every descendant must remain within the SecretHarbor security boundary.

Do not assume the original agent executable is the only process of interest.

### Process Tree Termination & Signal Handling

Modern agents and Electron-based IDEs (Antigravity, Cursor, OpenCode, VS Code) spawn multi-tiered process hierarchies:
- Root application process
- GPU process helpers
- UI renderers
- Utility & crashpad handlers
- Language servers / Extension hosts

Terminating only the root process leaves orphaned background helpers consuming CPU and GPU resources.

SecretHarbor enforces **Whole-Tree Process Termination (`KillProcessTree`)**:
1. Traverses the process hierarchy recursively using parent-child relationship tracking (`pgrep -P`).
2. Dispatches `SIGCONT` + `SIGTERM` across the full tree to awaken and gracefully shut down all helper processes.
3. Escalates to `SIGKILL` if processes do not exit within the timeout window.
4. **Instant Terminal Interrupt (`Ctrl+C`)**: A single `SIGINT` from the human developer triggers tree termination immediately, exiting cleanly with status 130.

### GUI Application Terminal Decoupling
Passing terminal standard input (`os.Stdin`) to desktop GUI applications can cause Chromium/Electron helper processes to acquire the controlling terminal foreground process group (`TPGID`), which prevents the shell from capturing `Ctrl+C`. For all recognized GUI applications, standard input is decoupled (`/dev/null`), preserving 100% terminal control for the developer.

### Desktop GUI App Adoption Model
Because operating system sandbox boundaries (Seatbelt on macOS) must attach at process creation time (`execve`), GUI apps launched from the **Dock, Spotlight, or Finder** start unconfined via `launchd`. SecretHarbor flags these as `UNPROTECTED`. `shb adopt` safely identifies the entire process tree, stops the unconfined processes, and restarts them inside the sandbox boundary. Alternatively, apps can be launched directly in detached mode via `shb run -d <agent>-app`.

---

# 16. Process Introspection and Memory Isolation

Linux implementations SHOULD add defense-in-depth against process inspection.

Before or as part of agent launch, set:

```c
prctl(PR_SET_DUMPABLE, 0);
```

for relevant sandboxed processes.

Also evaluate controls for:

```text
ptrace
process_vm_readv
/proc/<pid>/mem
/proc/<pid>/environ
/proc/<pid>/maps
core dumps
debugger attachment
```

Important:

> `PR_SET_DUMPABLE=0` is defense-in-depth. It is not the sole process-isolation mechanism.

Do not claim that setting `PR_SET_DUMPABLE=0` universally makes all process information inaccessible.

The implementation must combine it with the platform's process, identity, namespace, and sandbox controls.

---

# 17. File Descriptor Security

SecretHarbor MUST explicitly control inherited file descriptors.

A filesystem policy cannot be assumed to retroactively invalidate an already-open descriptor to a sensitive resource.

Before launching the agent:

- close unexpected inherited descriptors
- use close-on-exec semantics
- explicitly whitelist broker descriptors
- never pass sensitive file descriptors into agent processes unless explicitly authorized
- prevent the agent from obtaining privileged broker descriptors

The launcher must verify its descriptor set during development and in `secretharbor doctor`.

Test scenario:

```text
Human process:
    fd 7 -> open(.env)

SecretHarbor:
    launches agent

Agent:
    attempts to read fd 7
```

Expected:

```text
DENIED
```

---

# 18. Unix Socket and Local IPC Security

Restricted agents MUST NOT automatically inherit access to privileged local IPC endpoints.

Treat local IPC as a capability class, not merely as ordinary filesystem access.

Examples:

```text
SSH agent
Docker daemon
Podman
container runtimes
cloud credential helpers
database sockets
desktop application IPC
browser debugging interfaces
credential-manager sockets
custom local daemons
```

Restricted mode MUST explicitly define policy for:

- Unix-domain sockets
- filesystem-backed Unix sockets
- Linux abstract Unix sockets
- equivalent local IPC mechanisms on other platforms

Example:

```yaml
network:
  mode: restricted

  unix_sockets:
    mode: deny

  abstract_sockets:
    mode: deny

  docker:
    mode: approval  # standard: approval, strict: deny, custom: allow
    allowed_containers: []
```

### Docker Capability Brokering Model

Docker access represents a major potential host escape vector because possessing access to `/var/run/docker.sock` grants root-equivalent control over the host. However, blanket denial breaks common developer workflows. SecretHarbor handles Docker via **capability-based interception**:

1. **Preset Defaults:**
   - `standard` preset: `ipc.docker.mode: approval`. Docker daemon sockets are denied at the OS boundary, and SecretHarbor binds an ephemeral Unix domain proxy socket exposed via `DOCKER_HOST`.
   - `strict` preset: `ipc.docker.mode: deny`. Docker daemon sockets are hard blocked; `DOCKER_HOST`, `CONTAINER_HOST`, `DOCKER_CONTEXT`, `DOCKER_CERT_PATH`, and `DOCKER_TLS_VERIFY` are purged.
   - `allow`: explicitly configured by human for fully trusted environments.
2. **Capability-Based Interception (Not Command Matching):**
   Interception triggers at the connection layer when the agent's Docker client connects to the proxy socket, not via shell string matching (`docker compose up`).
3. **Out-of-Band Human Approval:**
   When an intercepted connection arrives, SecretHarbor suspends the agent process tree (`SIGSTOP`), dispatches an out-of-band approval notification/dialog to the human, and only proxies traffic if human approval is granted. Denial immediately terminates the connection without granting access.
4. **Environment Sanitization:**
   Raw unconfined container variables (`DOCKER_HOST`, `CONTAINER_HOST`, `DOCKER_CONTEXT`, `DOCKER_CERT_PATH`, `DOCKER_TLS_VERIFY`) and container credential files (`~/.docker/config.json`, `/run/secrets`) are denied by default.

The implementation must prevent the agent from using local IPC as a backdoor around Internet network restrictions.

---

# 19. Network Policy

SecretHarbor supports three primary network egress modes:

### Standard Preset: `allow` by default with Explicit Deny
In the `standard` protection preset, outbound network access is allowed by default:

```yaml
network:
  mode: allow
  # Optional explicit denylist
  deny:
    - telemetry.example.com
    - tracking.evil.com
```

- When `network.mode == allow` and `len(network.deny) == 0` (and no secret injection rules apply), `ProxyRequired` is `false`. The agent connects directly to the Internet with native network performance and zero proxy latency.
- When explicit `network.deny` domains are configured, SecretHarbor automatically starts the forward proxy and returns `403 Forbidden` for HTTP requests and HTTPS `CONNECT` tunnels matching denied domains or their subdomains (`*.evil.com`).

### Restricted Mode (Domain Allowlist)
When network access must be locked down to trusted platforms:

```yaml
network:
  mode: restricted
  allow:
    - github.com
    - registry.npmjs.org
    - proxy.golang.org
    - pypi.org
    - api.openai.com
    - api.anthropic.com
    - generativelanguage.googleapis.com
```

Requests to any destination outside the allowlist return `403 Forbidden`.

### Strict Mode: Full Network Denial
Strict mode defaults to complete outbound network isolation:

```yaml
network:
  mode: deny
```

### Local IPC & Electron Loopback (`NO_PROXY`)
For Electron and Chromium-based desktop environments (VS Code, Cursor, OpenCode, Antigravity), internal communication between the UI renderer and local language servers relies on loopback (`127.0.0.1`, `localhost`). Whenever the forward proxy is active, SecretHarbor sets:
```text
NO_PROXY=localhost,127.0.0.1,::1
no_proxy=localhost,127.0.0.1,::1
```
This ensures internal app RPC is never routed through the proxy, preventing internal connection failures while maintaining strict external egress boundaries.

---

# 20. Secret Broker / Runtime Injection

For advanced `use` functionality, implement a broker.

Conceptually:

```text
Agent
 |
 | fake credential / logical secret identifier
 v
SecretHarbor broker
 |
 | real credential inserted at controlled boundary
 v
Approved destination
```

Requirements:

1. Real secret must not be returned to the agent.
2. Real secret must not be printed to agent stdout/stderr.
3. Real secret must not be written to agent-readable files.
4. Real secret must not be placed in the agent environment.
5. Logs must redact secret values.
6. Network destinations must be allowlisted.
7. Access should be time-limited where practical.
8. Access should be auditable.
9. Broker requests must be authenticated and capability-scoped.
10. The agent cannot modify broker policy.

---

# 21. Human Approval

The agent may request a capability but cannot grant itself the capability.

Example:

```text
Agent requests:

DATABASE_URL
Purpose: run integration tests
Destination: db.internal
Duration: 10 minutes

[ Deny ] [ Allow ]
```

If approved, access should be:

- scoped
- temporary
- auditable
- non-persistent by default

Human approval must be performed through a trusted control plane.

The agent cannot approve its own request.

---

# 22. Policy Protection

The active SecretHarbor configuration must live outside the agent's authority.

Possible architecture:

```text
~/.secretharbor/
    policy.yaml
    compiled/
    state/
    vault/
```

The agent must not be able to modify these resources.

Do not rely solely on ordinary filesystem permissions when the agent runs as the same user.

The OS-level sandbox must prevent the agent from modifying SecretHarbor control-plane resources.

The SecretHarbor executable/binary must also be protected from modification.

A policy change should require creation of a new human-authorized enforcement state.

---

# 23. Policy Compilation

Do not evaluate YAML as the primary runtime security mechanism.

Recommended architecture:

```text
policy.yaml
    |
    v
Policy Parser
    |
    v
Normalized Policy
    |
    v
Policy Compiler
    |
    +--> filesystem rules
    +--> network rules
    +--> environment rules
    +--> process rules
    +--> IPC rules
    +--> secret broker rules
    |
    v
OS Enforcement
```

A running sandbox should use compiled enforcement state.

Modifying `policy.yaml` must not weaken the already-running sandbox.

---

# 24. Platform Strategy

SecretHarbor should use native OS security primitives where possible.

## Linux

Evaluate and use, as appropriate:

- Landlock
- namespaces
- seccomp
- cgroups
- mount namespaces
- network namespaces
- privileged/unprivileged broker separation
- process credential controls
- `prctl(PR_SET_DUMPABLE, 0)`

Landlock is especially relevant for unprivileged filesystem restrictions.

The implementation must account for kernel-version differences.

Important Landlock concerns include:

- rule support varying by kernel version
- inherited restrictions
- already-open file descriptors
- link/rename/reference restrictions
- directory hierarchy semantics

When a required Landlock feature is unavailable, SecretHarbor MUST NOT silently downgrade to a weaker and equivalent-looking claim.

Instead, expose the actual posture.

Example:

```text
Filesystem isolation: STRONG
Rename/link isolation: STRONG
Network isolation: LIMITED
Reason: required kernel feature unavailable
```

## macOS

Production enforcement SHOULD use Apple-supported system security mechanisms.

Primary architecture:

- System Extensions where persistent privileged security components are required
- Endpoint Security for security-event authorization/monitoring where appropriate
- Network Extension for network policy where appropriate

`Sandbox` / Seatbelt mechanisms may be used where appropriate, but MUST NOT be the sole basis of the product's universal macOS security claim.

`DYLD_INSERT_LIBRARIES` / dynamic-loader interposition MUST NOT be treated as the primary security boundary.

Reason:

- loader interposition is process-specific
- it can be unavailable or restricted
- it is not equivalent to OS authorization
- it should be considered defense-in-depth or compatibility tooling, not the universal enforcement layer

The macOS implementation must account for:

- code signing
- entitlements
- System Extension installation
- user authorization
- non-root operation
- application sandboxing
- desktop application architecture

## Windows

Evaluate:

- AppContainer
- restricted tokens
- job objects
- filesystem ACL mechanisms
- Windows Filtering Platform
- process mitigation policies
- user-mode / service-based enforcement

Windows support may initially be experimental, but the policy abstraction should remain platform-independent.

---

# 25. Security Posture Reporting

SecretHarbor must distinguish configuration from actual enforcement.

Example:

```text
SecretHarbor status

Protection: standard
Platform: Linux
Kernel enforcement: active
Filesystem isolation: strong
Network isolation: strong
IPC isolation: strong
Environment sanitization: active
Inherited FD protection: active
Secret virtualization: active
Broker: disabled
Unsandboxed escape: denied

Overall posture: STRONG
```

Do not report "strong" solely because a YAML file is valid.

Status should be based on the active enforcement state.

---

# 26. Fake Secret Generation

Fake values must be:

1. structurally useful where practical
2. obviously synthetic
3. compatible with expected parsers where possible
4. impossible to confuse with the production credential
5. free of real secret content
6. generated locally
7. excluded from telemetry
8. never derived reversibly from the real value

Recommended strategy:

```text
Known provider format
        |
        v
Provider-specific safe fake

Known generic type
        |
        v
Type-specific synthetic fake

Unknown secret
        |
        v
Stable synthetic placeholder
```

Example:

```text
STRIPE_SECRET_KEY
-> sk_test_secretharbor_fake_...

JWT_SECRET
-> synthetic random secret of configured type/size

DATABASE_URL
-> valid fake connection string

UNKNOWN_KEY
-> secretharbor_fake_<stable identifier>
```

Do not blindly preserve exact secret length for every unknown value.

Instead, use type-aware heuristics.

Optional configuration:

```yaml
fake:
  strategy: auto
  known_formats: provider
  unknown: synthetic
  deterministic: true
```

Deterministic fake values may be useful for development reproducibility, but MUST NOT be derived from the real secret.

---

# 27. Secret Materialization Rules

Never replace a human-owned real secret on disk with a fake value unless the product explicitly chooses a virtualization model that preserves the human workflow.

Preferred architecture:

- real secret remains in a trusted store or human-readable location according to product mode
- agent sees a fake/denied view through the sandbox or virtualization layer
- human editor access remains separate

If a virtualization implementation changes what appears on disk, the difference between:

- stored secret
- human presentation
- agent presentation
- application/runtime presentation

must be explicit and testable.

---

# 28. Desktop / IDE Architecture

A VS Code or IDE extension is a **control-plane/UX component**, not the security boundary.

The extension can provide:

- status
- configuration editing
- secret management UI
- approval dialogs
- audit display
- agent detection
- launch controls

But actual protection must occur at the process/OS level.

A compromised extension must not automatically bypass the core SecretHarbor security model.

For desktop agent applications, prefer isolating the agent execution process rather than sandboxing the entire human-facing application where possible.

For architectures where agent and human UI are inseparable, document the resulting trust trade-off explicitly.

---

# 29. MCP Security

MCP servers launched by the agent are untrusted by default.

They must inherit the agent's security boundary.

Do not create an exception merely because a process is labeled an MCP server.

Example:

```text
Agent
 |
 +-- MCP server
       |
       +-- filesystem
       +-- shell
       +-- network
```

The entire process tree remains restricted.

Explicitly trusted MCP servers may be supported later as a human-controlled capability.

---

# 30. Desktop Agent Capability Boundary

For desktop agents, do not assume the GUI process is the agent.

Model the architecture explicitly.

Possible architecture:

```text
Trusted human UI
      |
      +------ control plane
      |
      +------ sandbox launcher
                  |
                  v
             agent process
                  |
             child processes
```

If the agent lives inside the same process as the human UI and cannot be separately isolated, the integration must not claim the same security level as a separately sandboxed process.

---

# 31. Unsandboxed Execution

Strong mode must default to:

```yaml
sandbox:
  escape: deny
```

If an agent requests execution outside the sandbox:

```text
Agent requests unsandboxed execution.

Command:
rm -rf ...

[ Deny ] [ Allow once ]
```

Any human-approved escape should be:

- explicit
- visible
- temporary
- audited

The agent itself must never be able to approve the escape.

An "allow once" escape must create an auditable event and must not permanently change project policy.

---

# 32. Local Privileged Capability Sanitization

SecretHarbor should identify and sanitize references to capabilities that can indirectly reach secrets.

Initial examples:

```text
SSH_AUTH_SOCK
DOCKER_HOST
CONTAINER_HOST
KUBECONFIG
cloud credential helper endpoints
browser debugging endpoints
custom agent/helper sockets
```

Do not treat the presence of a string such as `DOCKER_HOST` as itself malicious.

The security rule is:

> **Agent processes receive only local-service capabilities explicitly required and explicitly allowlisted.**

---

# 33. IPC Security

If the agent communicates with an SecretHarbor broker:

- use authenticated local IPC
- authenticate the calling process where the platform permits
- do not expose a globally writable Unix socket
- prevent arbitrary local processes from impersonating the agent
- enforce capability scope server-side
- never trust a request merely because it arrived through the expected socket
- isolate privileged broker endpoints from ordinary agent filesystem access
- rotate/expire temporary capability handles where practical

---

# 34. Policy Semantics

Recommended conceptual model:

```text
PROTECTION
    |
    +-- secrets
    |     +-- fake
    |     +-- deny
    |     +-- allow
    |
    +-- environment
    |
    +-- filesystem
    |
    +-- network
    |
    +-- IPC
    |
    +-- process
    |
    +-- runtime use
```

Avoid exposing OS-specific concepts in the basic configuration.

Users configure intent.

SecretHarbor translates intent into platform-specific enforcement.

---

# 35. Security Presets

Provide simple presets.

## permissive

Protect obvious/high-risk secrets while minimizing disruption.

## standard

Recommended default:

- secret files -> fake
- secret mutation -> denied
- sensitive environment variables -> sanitized/fake
- network -> restricted
- local privileged IPC -> restricted
- SecretHarbor control plane -> protected
- unsandboxed agent execution -> denied by default

## strict

- secret files -> deny
- secret environment variables -> deny
- network -> deny unless explicitly allowed
- privileged local IPC -> deny
- no unsandboxed execution
- no agent-controlled policy changes
- strongest available platform controls enabled

Example:

```yaml
version: 1

protection: standard
```

This should be sufficient for most users.

---

# 36. CLI Model & Session Lifecycle

SecretHarbor provides two first-class, interchangeable binaries:
- **`shb`** (primary concise command)
- **`secretharbor`** (full name alias)

### Full CLI Surface Model

```bash
shb init                    # Initialize host integration, detect agents, install shims, setup project policy
shb adopt [--yes]           # Discover unprotected running agents and cleanly restart them under SecretHarbor
shb restart [agent]         # Cleanly restart an agent session inside a fresh SecretHarbor sandbox
shb run claude              # Explicitly start guarded agent session (debug / manual fallback)
shb run -- <cmd...>         # Run arbitrary agent command in sandbox
shb status                  # Display persistent host integration, active sandboxes, and running processes
shb sessions                # List active SecretHarbor-managed agent sessions
shb stop [id]               # Terminate an agent session (clean process tree termination, preserves policy)
shb doctor                  # Run live adversarial security verification test suite

shb guard on                # Enable SecretHarbor sandbox and secret protections
shb guard off               # Explicitly disable protection for this project (requires human confirmation)

shb config [show]           # Display effective configuration (read-only, zero secret exposure)
shb config --json           # Machine-readable effective policy JSON
shb config source           # Trace origin and provenance of each active rule
shb config check            # Validate syntax, consistency, and rule conflicts
shb config edit             # Human-only policy editor ($EDITOR) with diff verification (agent lockout)
shb config diff             # Show active customizations relative to standard preset

shb policy check            # Validate active policy file
shb policy explain <res>    # Debug why a file, env var, or domain was faked, denied, or allowed

shb secret list             # List registered secret keys without values
shb secret status <KEY>     # Inspect secret virtualization status and broker capabilities
shb secret test <KEY>       # Validate vault retrieval, synthetic fake generator, and broker rules
shb secret set <KEY> <VAL>  # Store a credential in local AES-256-GCM encrypted vault
shb secret delete <KEY>     # Remove a credential from local vault

shb trust list              # List explicitly trusted processes, tools, or MCP servers
shb trust add <name>        # Grant trusted status to a tool or process
shb trust remove <name>     # Revoke trusted status

shb pending                 # List pending human capability escalation requests
shb approve <id>            # Approve capability escalation
shb deny <id>               # Deny capability escalation
shb logs [limit]            # View redacted audit log events

shb update                  # Check for and install newer SecretHarbor version
shb update --check          # Check for newer versions without installing
shb update --version <ver>  # Pin or install an explicit version
shb update --dry-run        # Simulate download and verification without installing

shb version [--json]        # Detailed system audit output (kernel, sandbox driver, active policy)
shb help [cmd]              # Dynamic, centralized documentation per command
```

### Invisible Host-Level Security Layer Architecture

SecretHarbor does not require users to run `shb run claude` as the primary UX. Instead, `shb init` establishes an invisible host security layer:

```text
shb init
   ↓
Detect supported agents/apps (Claude, Codex, Gemini CLI, Cursor, VS Code, Aider, Cline)
   ↓
Install transparent launcher shims (~/.secretharbor/shims) & configure shell PATH
   ↓
Future agent launches are automatically guarded
```

1. **One-Time Setup Across Reboots:** `shb init` is run once per machine / project. Launcher shims and shell profiles persist across system reboots without requiring re-initialization.
2. **Transparent Shims:** When the user or an IDE runs `claude`, the shim interceptor (`~/.secretharbor/shims/claude`) executes `shb run claude -- "$@"`. Inside the sandbox, `SECRETHARBOR_SANDBOX=1` prevents infinite recursion and executes the underlying real binary directly.
3. **No Retroactive In-Flight Sandboxing Invariant:**
   SecretHarbor MUST NOT claim an already-running agent is protected unless the applicable OS security boundary was established before it started. Pre-existing processes are explicitly marked as `UNPROTECTED`.
4. **Agent Adoption (`shb adopt`):**
   Discovers unprotected running agents, explains the retroactive sandboxing constraint, terminates the process cleanly (`SIGTERM` -> `SIGKILL`), and restarts it inside a fresh SecretHarbor sandbox.
5. **Clean Session Restart (`shb restart [agent]`):**
   Cleanly terminates existing sessions or unprotected processes and restarts them inside a freshly initialized sandbox.
6. **Desktop Application Architecture (Cursor & VS Code):**
   The human editor UI itself is not an AI agent; the editor spawns sub-processes for terminal sessions, agent tool execution, and MCP servers. Because transparent launcher shims are configured in the user's shell profile, all agent tools and terminal tasks executed by Cursor/VS Code run inside SecretHarbor's sandbox boundary, leaving the human editor UI fully responsive and unhindered.
7. **Strict Fail-Closed Invariant:**
   If the security boundary fails to initialize (e.g. invalid policy, proxy error, unsupported OS driver), SecretHarbor MUST fail closed rather than silently launching the agent unprotected. It outputs:
   ```text
   SecretHarbor enforcement unavailable.
   <agent> cannot be started safely.
   Reason: <error>
   Run: shb status / shb doctor
   ```
8. **Decoupled Agent Model (`AgentRuntime` and `AgentIntegration`):**
   SecretHarbor decouples **Agent Identity** from its **Execution Context**:
   - `AgentRuntime`: `process` (native host process), `container` (Docker/Podman container), `remote` (SSH/remote devbox), `embedded` (library inside host application).
   - `AgentIntegration`: `cli` (terminal execution), `desktop` (standalone desktop app), `ide` (IDE host like Cursor/VS Code), `extension` (IDE extension host sub-agent), `server` (background daemon), `unknown` (generic command execution).
   - **Universal Untrusted Fallback Invariant:** Any unknown binary or arbitrary command executed via `shb run` defaults to `Runtime: process, Integration: unknown` and is subjected to full sandbox confinement (never bypasses security).
9. **Process Hierarchy & Boundary Visualization:**
   `shb status`, `shb adopt`, and `shb restart` inspect system process tables by traversing parent PIDs (`PPID`) to build the full upstream parentage and downstream task hierarchy. SecretHarbor visualizes the process tree and renders an explicit boundary line:
   ```text
   Cursor (PID 1200)
     │
     Extension Host (PID 1240)
       │
       ══════════════════════════════════════════════════════
       [SecretHarbor Security Boundary - standard policy]
       ══════════════════════════════════════════════════════
         │
         └── claude (PID 1350)  PROTECTED
               │
               └── bash (PID 1360)
   ```
   For unprotected processes, SecretHarbor displays the absence of the security boundary:
   ```text
   Terminal (PID 900)
     │
     └── claude (PID 1100)  UNPROTECTED (started before SecretHarbor)
   ```

### Secure Self-Updating Architecture (`shb update`)
Because SecretHarbor is itself the security boundary, self-updating is security-sensitive:
- **Agent Lockout:** An AI agent running inside `shb run` cannot trigger a self-update (`SECRETHARBOR_SANDBOX=1`). Sandboxed update attempts immediately abort with:
  ```text
  Permission denied: SecretHarbor self-update is human-controlled.
  Sandboxed agents and processes cannot modify the security boundary binary.
  ```
- **Integrity Verification:** The updater downloads release manifests and artifacts over authenticated HTTPS, computing and verifying SHA-256 checksums and digital release signatures before touching files.
- **Atomic Replacement Strategy:** The updater stages downloads in the same directory (`filepath.Dir(execPath)`), creates a `<binary>.old` backup, and performs an atomic rename.
- **Automated Health Check & Rollback:** The new executable is tested with `--version`. If the health check fails, SecretHarbor instantly rolls back to `<binary>.old`.

### Official Multi-Platform Installation Channels
SecretHarbor supports 4 official distribution and installation paths:
1. **One-Line POSIX Installer (macOS & Linux):**
   ```bash
   curl -fsSL https://secretharbor.dev/install.sh | sh
   ```
   - `/bin/sh` POSIX compliant, small, auditable.
   - Detects OS (`darwin`, `linux`) and architecture (`amd64`, `arm64`).
   - Downloads signed release manifest, verifies SHA256 checksums.
   - Installs `secretharbor` and `shb` symlink/binary atomically.
   - Installs Unix man pages to `man1/`.
2. **One-Line PowerShell Installer (Windows):**
   ```powershell
   irm https://secretharbor.dev/install.ps1 | iex
   ```
   - Detects architecture, downloads verified zip archive.
   - Verifies SHA256 via `Get-FileHash`.
   - Installs to `$env:LOCALAPPDATA\Programs\SecretHarbor` and updates user `PATH`.
3. **Package Managers:**
   - **Homebrew (macOS / Linux):** `brew install secretharbor` (via `packaging/homebrew/secretharbor.rb`).
   - **WinGet (Windows):** `winget install SecretHarbor.SecretHarbor` (via `packaging/winget/SecretHarbor.SecretHarbor.yaml`).
4. **Direct Binary Downloads & Source Builds:**
   - Signed binaries for `linux-amd64`, `linux-arm64`, `darwin-amd64`, `darwin-arm64`, `windows-amd64`, `windows-arm64`.
   - Source compilation via `make build` and `make install`.

### Critical Security Boundary: `shb stop` vs `shb guard off`

A strict architectural and security distinction is enforced between stopping a process and weakening security policy:

> **`shb stop` terminates an active agent session.** It terminates the agent process tree cleanly (`SIGTERM` -> `SIGKILL` on process group) and reclaims ephemeral sandbox/virtualizer/proxy state. **`shb stop` must NEVER weaken, alter, or disable SecretHarbor's security policy.**

> **`shb guard off` disables protection for the current project.** Because disabling protection is high-risk, it requires explicit, interactive human confirmation:
> ```text
> SecretHarbor protection will be disabled for this project.
> 
> The next agent session may have unrestricted access to:
>   .env
>   credentials
>   SSH keys
>   local services
>   network
> 
> Continue? [y/N]
> ```

### Effective Configuration Inspection (`shb config`)
`shb config` and `shb config show` are strictly read-only and guarantee zero secret exposure:
- Raw secret values are never printed; secret entries render as `fake`, `deny`, `allow`, or `stripped`.
- `--json` outputs machine-readable JSON representing the compiled enforcement plan.
- `shb config source` details the exact provenance for every active rule (preset, project YAML, or built-in).
- `shb config edit` is human-only: sandboxed agents attempting `shb config edit` are blocked with an immediate permission denied error before accessing `$EDITOR`.

### Policy Debugging (`shb policy explain <resource>`)
Provides instant clarity for developers debugging agent behavior:
- `shb policy explain .env`: shows matched secret pattern, agent read (`FAKE`), agent write (`DENY`), agent delete (`DENY`), human access (`ALLOW`), and rule source.
- `shb policy explain DATABASE_URL`: shows sensitive environment variable pattern match and synthetic format-preserving replacement.
- `shb policy explain --network api.stripe.com`: reveals whether the egress endpoint is allowed, blocked, or intercepted by the capability broker.

### Unix Manual Pages & Documentation
Single-source-of-truth specification registry generates compliant troff/roff manual pages:
- `man/man1/shb.1`: Main manual page with synopsis, security model, and command directory.
- `man/man1/secretharbor.1`: Alias pointing to `shb.1`.
- `man/man1/shb-<cmd>.1`: Command-specific manual pages (`shb-init.1`, `shb-adopt.1`, `shb-restart.1`, `shb-run.1`, `shb-status.1`, `shb-sessions.1`, `shb-stop.1`, `shb-config.1`, `shb-policy.1`, `shb-secret.1`, `shb-trust.1`, `shb-doctor.1`, `shb-guard.1`, `shb-update.1`).
- Integrated into build workflow via `make man` and `make install-man`.

### Multi-Session Management (`shb sessions` & `shb stop <id>`)

When agents run concurrently across projects, `shb sessions` lists active instances:

```text
SecretHarbor Sessions

ID       Agent      Project     Status
a81f     Claude     my-app      RUNNING
b22c     Codex      api         RUNNING
```

- `shb stop a81f`: terminates session `a81f` specifically.
- `shb stop`: automatically targets the session running in the current working directory, or prompts if multiple sessions exist.

---

# 37. `secretharbor doctor`

This is a required security feature.

It must verify actual enforcement rather than merely validating configuration.

Test categories:

### Filesystem

```text
Direct secret read
Python secret read
Node secret read
Symlink bypass
Path traversal
Copy bypass
Rename bypass
Archive bypass
Hard-link bypass
Protected-directory mutation
```

### Environment

```text
Real secret environment exposure
Credential-helper environment exposure
SSH_AUTH_SOCK exposure
DOCKER_HOST exposure
```

### Process

```text
Child-process access
Grandchild-process access
MCP process access
ptrace attempt
process memory inspection
core dump behavior
```

### File descriptors

```text
Inherited sensitive FD access
Unexpected FD inheritance
Broker FD exposure
```

### IPC

```text
Unix socket access
Linux abstract socket access
Docker socket access
SSH agent socket access
Known privileged local service endpoints
```

### Network

```text
Allowed host access
Denied host access
Raw outbound connection
DNS policy
Localhost access
Network exfiltration attempt
```

### Control plane

```text
Policy modification
Policy deletion
SecretHarbor binary modification
Broker shutdown
Sandbox disable attempt
Launching second unsandboxed agent
```

### Escape attempts

```text
Namespace escape
Sandbox escape
Privilege escalation attempt
```

Output:

```text
PASS = attack was prevented
FAIL = attack succeeded
NOT TESTED = test unavailable
LIMITED = partially enforced; see reason
```

Never report PASS merely because configuration looks correct.

---

# 38. Logging and Auditing

SecretHarbor should record security events.

Example:

```json
{
  "timestamp": "2026-09-11T10:00:00Z",
  "agent": "claude",
  "operation": "read",
  "resource": ".env",
  "result": "fake"
}
```

Denied access:

```json
{
  "timestamp": "2026-09-11T10:01:00Z",
  "agent": "claude",
  "operation": "read",
  "resource": ".env.production",
  "result": "denied"
}
```

Never log:

- real secret values
- full Authorization headers
- private keys
- credential contents
- sensitive environment values

Redaction must happen before logging.

The audit system itself must be protected from agent tampering.

---

# 39. Secret Storage

If SecretHarbor stores real secrets itself, use a platform-appropriate secure store.

Preferred mechanisms:

- macOS Keychain
- Windows Credential Manager / DPAPI-backed storage
- Linux Secret Service / keyring where available

Do not store plaintext credentials in:

```text
~/.secretharbor/secrets.json
```

If encrypted local storage is required:

- use modern authenticated encryption
- separate encryption keys from ciphertext where practical
- protect key material using OS facilities
- avoid exposing decryption keys to the agent process

---

# 40. Agent Adapters

Agent adapters should be thin.

Example:

```text
adapters/
    claude/
    codex/
    gemini/
    cursor/
    vscode/
    generic/
```

An adapter may:

- detect the agent
- identify its executable
- identify child-process launch behavior
- configure launch arguments
- integrate with agent-specific UI
- provide status information

An adapter must NOT be trusted as the security boundary.

The generic launcher must remain functional for unknown agents.

---

# 41. Generic Agent Support

Users should be able to run arbitrary agents:

```bash
secretharbor run -- ./my-agent
```

or:

```bash
secretharbor run -- npm run my-agent
```

Everything launched beneath that process inherits the SecretHarbor boundary.

---

# 42. Human UI

A future UI may show:

```text
SecretHarbor

Project: my-app
Protection: Standard

Secrets
--------------------------------
.env                 FAKE
.env.local           DENY
.env.production      DENY
.env.example         ALLOW

IPC
--------------------------------
SSH agent            DENY
Docker socket        DENY

Network
--------------------------------
github.com           ALLOW
npmjs.org             ALLOW

[Edit]
[Import]
[Audit]
[Settings]
```

The UI is a trusted human control surface.

It should never expose real secret values to the agent process.

---

# 43. Policy Change Semantics

Policy changes must not silently mutate the security state of an already-running agent.

Recommended model:

```text
policy.yaml
    |
    v
human saves change
    |
    v
policy validation
    |
    v
new compiled policy
    |
    v
new agent session required
```

For temporary human-approved capabilities, use a scoped runtime capability mechanism rather than rewriting the permanent project policy.

This prevents the agent from turning an approved temporary action into permanent access.

---

# 44. Development Priorities

## Phase 1 — Linux Security Core

Build first:

1. Linux support
2. `secretharbor run`
3. process-tree sandboxing
4. filesystem policy
5. protected secret paths
6. environment sanitization
7. SecretHarbor self-protection
8. `fake` and `deny`
9. Unix/privileged IPC blocking where supported
10. inherited FD control
11. `PR_SET_DUMPABLE=0` defense-in-depth
12. `secretharbor doctor`
13. adversarial tests

Do NOT start with IDE integrations.

## Phase 2 — Usability

Add:

1. `secretharbor init`
2. standard presets
3. policy validation
4. audit logs
5. human-friendly status
6. secret detection
7. better fake generation

## Phase 3 — Runtime Secret Use

Add:

1. secret broker
2. host allowlists
3. temporary capabilities
4. human approval
5. audit trail
6. credential substitution/proxy

## Phase 4 — macOS

Build around:

1. System Extension architecture where required
2. Endpoint Security
3. Network Extension where required
4. user authorization/install flow
5. process-level agent isolation
6. desktop-agent integration

Do not make dynamic-loader interposition the primary security mechanism.

## Phase 5 — Windows

Evaluate and implement the strongest supported native process/filesystem/network isolation.

## Phase 6 — Desktop/IDE Integrations

Add:

1. VS Code
2. desktop agent integrations
3. agent adapters
4. trusted human secret UI

---

# 45. Testing Requirements

Tests must be adversarial.

## Direct access

```bash
cat
head
tail
less
```

## Interpreters

```bash
python
node
ruby
perl
```

## Shell tricks

```text
$(...)
`...`
pipes
redirection
process substitution
subshells
```

## Filesystem tricks

```text
symlink
hard link
rename
copy
archive
relative path
absolute path
../ traversal
protected parent-directory mutation
```

## Process tricks

```text
child process
grandchild process
shell spawned from interpreter
MCP server
npm script
make
task runner
```

## Environment

```bash
env
printenv
/proc/*/environ where applicable
process argument inspection
credential-helper discovery
```

## Memory / process inspection

```text
ptrace
process_vm_readv
/proc/<pid>/mem
/proc/<pid>/maps
core dump attempts
debugger attachment
```

## File descriptors

```text
inherited open descriptor
broker descriptor exposure
unexpected descriptor inheritance
```

## IPC

```text
Unix socket
abstract Unix socket
Docker socket
SSH agent socket
custom privileged socket
```

## Network

Attempt to send a known test secret to a controlled test endpoint.

Tests must include:

```text
Internet
localhost
private network ranges
DNS
allowed destination
denied destination
```

## Control-plane attacks

Attempt to:

```text
modify policy
delete policy
replace binary
kill broker
restart broker
launch a second agent outside the sandbox
change PATH
change configuration
disable enforcement
```

Every attack must either:

- be blocked, or
- be explicitly identified as an accepted platform limitation.

---

# 46. Security Acceptance Criteria

The MVP is not considered secure until all of the following are true for the supported platform and documented configuration:

- Agent cannot read protected real secret files.
- Agent receives fake values where `fake` is configured.
- Agent cannot modify protected secret files.
- Agent cannot modify SecretHarbor policy.
- Agent cannot replace SecretHarbor binaries.
- Child processes inherit restrictions.
- MCP processes inherit restrictions.
- Real secret environment variables are not inherited.
- Privileged local IPC references are removed or explicitly restricted.
- Network restrictions are enforced.
- Protected secrets cannot be reached through trivial symlink/path tricks.
- Agent cannot use an inherited sensitive file descriptor to bypass policy.
- SecretHarbor's broker cannot be impersonated by arbitrary local processes.
- `secretharbor doctor` can verify the above.
- Human processes can still edit/delete/copy secrets normally.
- Security logs do not contain real secrets.
- Temporary capabilities expire correctly.
- A policy change cannot silently weaken an already-running sandbox.

---

# 47. Accepted Limitations Must Be Explicit

If a platform primitive cannot guarantee a particular property, do not silently claim protection.

Document:

```text
SUPPORTED
PARTIALLY SUPPORTED
NOT SUPPORTED
```

per platform and feature.

Every security-sensitive feature should identify:

- enforcement primitive
- required privileges
- minimum OS/kernel version
- known bypasses outside the threat model
- failure behavior
- test coverage

Never use marketing language such as "impossible to bypass" unless the underlying platform and threat model truly justify it.

---

# 48. Repository Structure

Suggested structure:

```text
secretharbor/
├── cmd/
│   └── secretharbor/
├── internal/
│   ├── policy/
│   ├── compiler/
│   ├── sandbox/
│   │   ├── linux/
│   │   ├── darwin/
│   │   └── windows/
│   ├── secrets/
│   ├── environment/
│   ├── network/
│   ├── ipc/
│   ├── broker/
│   ├── process/
│   ├── fd/
│   ├── audit/
│   └── agents/
├── tests/
│   ├── adversarial/
│   ├── filesystem/
│   ├── environment/
│   ├── network/
│   ├── ipc/
│   ├── process/
│   ├── fd/
│   └── control-plane/
├── docs/
└── examples/
```

Keep platform-specific enforcement behind a common interface.

---

# 49. Core Interfaces

Conceptual interfaces:

```text
Policy
  |
  +-- Parse()
  +-- Validate()
  +-- Normalize()
  +-- Compile()
```

```text
Sandbox
  |
  +-- Prepare()
  +-- Launch(command)
  +-- ApplyFilesystemPolicy()
  +-- ApplyNetworkPolicy()
  +-- ApplyEnvironmentPolicy()
  +-- ApplyIPCPolicy()
  +-- ApplyProcessPolicy()
  +-- ApplyFDPolicy()
```

```text
SecretProvider
  |
  +-- GetMetadata()
  +-- GetFakeValue()
  +-- AuthorizeUse()
  +-- ExecuteWithSecret()
```

```text
AuditLogger
  |
  +-- LogAccess()
  +-- LogDenied()
  +-- LogApproval()
  +-- LogSecurityEvent()
```

These represent architectural boundaries, not mandatory language-specific APIs.

---

# 50. Example Complete Configurations

## Basic

```yaml
version: 1

protection: standard
```

## Strict

```yaml
version: 1

protection: strict
```

## Customized

```yaml
version: 1

protection: standard

secrets:
  mode: fake

exceptions:
  allow:
    - .env.example

  deny:
    - .env.production
    - .aws/credentials
    - .ssh/*

network:
  allow:
    - github.com
    - registry.npmjs.org
```

## Advanced

```yaml
version: 1

protection: custom

secrets:
  mode: fake

exceptions:
  deny:
    - .env.production
    - .aws/credentials
    - .ssh/*

environment:
  mode: sanitize

network:
  mode: restricted

  allow:
    - github.com
    - registry.npmjs.org

ipc:
  unix_sockets:
    mode: deny

  abstract_sockets:
    mode: deny

runtime:
  allow:
    - api.openai.com

rules:
  - secret: DATABASE_URL
    read: fake
    use:
      enabled: true
      hosts:
        - db.internal

  - secret: STRIPE_SECRET_KEY
    read: fake
    use:
      enabled: true
      hosts:
        - api.stripe.com

sandbox:
  escape: deny
```

---

# 51. Architecture

Reference architecture:

```text
                         HUMAN
                           |
                           v
                  +------------------+
                  | SecretHarbor UI /   |
                  | CLI / Control    |
                  | Plane            |
                  +---------+--------+
                            |
                      policy compile
                            |
                            v
                  +------------------+
                  | SecretHarbor        |
                  | Enforcement      |
                  +---------+--------+
                            |
           +----------------+----------------+
           |                |                |
           v                v                v
      Filesystem         Process          Network
       boundary          boundary         boundary
           |                |                |
           +----------------+----------------+
                            |
                            v
                     UNTRUSTED AGENT
                            |
          +-----------------+------------------+
          |                 |                  |
          v                 v                  v
        Shell              MCP            subprocesses
          |                 |                  |
          +-----------------+------------------+
                            |
                            v
                     Secret Broker
                            |
                    approved capability
                            |
                            v
                    Real secret use
```

---

# 52. Control Plane vs Data Plane

Keep these separate.

## Control plane

Trusted human-controlled components:

- policy
- secret store
- broker authorization
- approvals
- audit
- status
- UI

## Data plane

Untrusted agent-controlled components:

- agent
- shell
- MCP
- subprocesses
- project tooling

The control plane must never trust data-plane instructions about its own permissions.

---

# 53. Capability Security Principle

SecretHarbor should think in terms of capabilities, not just files.

A capability may be:

```text
read this file
write this directory
connect to this host
connect to this Unix socket
use this credential
invoke this local service
execute this binary
```

The agent receives only capabilities explicitly granted by policy.

This allows future functionality without redesigning the core model.

---

# 54. Product Principle

The product should ultimately feel simple:

```bash
secretharbor init
secretharbor run claude
```

The developer should not need to understand:

- Landlock
- Seatbelt
- namespaces
- seccomp
- AppContainer
- network namespaces
- System Extensions
- Endpoint Security
- file-descriptor inheritance

SecretHarbor should translate simple security intent into platform-level enforcement.

---

# 55. Final Product Definition

SecretHarbor is:

> **A security layer between AI agents and the developer's machine.**

Its most important capabilities are:

1. **Secret virtualization**
   - real secret for humans
   - fake or no secret for agents

2. **OS-level agent isolation**
   - filesystem
   - process tree
   - environment
   - network
   - IPC
   - file descriptors

3. **Policy protection**
   - agent cannot weaken its own restrictions

4. **Capability-based secret use**
   - agent can perform approved operations without receiving the underlying credential

5. **Human control**
   - humans can freely manage their own secrets

6. **Agent-agnostic architecture**
   - Claude/Codex/Gemini/Cursor/etc. are integrations, not the security boundary

7. **Adversarial verification**
   - `secretharbor doctor` proves the active security boundary rather than merely reporting configuration

8. **Platform-aware security claims**
   - each operating system reports exactly what is enforced

The central invariant is:

> **The agent controls its work, but never controls its security boundary.**
