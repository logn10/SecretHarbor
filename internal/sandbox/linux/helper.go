package linux

// SandboxHelperArg is the hidden CLI subcommand used to apply kernel restrictions
// in the child process between fork and exec.
const SandboxHelperArg = "__shb_linux_sandbox"

// SandboxHelperEnv carries the serialized enforcement spec to the helper.
const SandboxHelperEnv = "SHB_SANDBOX_SPEC"
