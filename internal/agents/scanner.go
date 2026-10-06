package agents

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/secretharbor/secretharbor/internal/session"
)

// ProcessNode represents a single process in the system process tree.
type ProcessNode struct {
	PID         int            `json:"pid"`
	PPID        int            `json:"ppid"`
	Command     string         `json:"command"`
	DisplayName string         `json:"display_name"`
	Parent      *ProcessNode   `json:"-"`
	Children    []*ProcessNode `json:"children,omitempty"`
}

// ProcessHierarchy holds the process hierarchy and security boundary position.
type ProcessHierarchy struct {
	Ancestors    []*ProcessNode `json:"ancestors"`
	AgentNode    *ProcessNode   `json:"agent_node"`
	Descendants  []*ProcessNode `json:"descendants"`
	Protected    bool           `json:"protected"`
	PolicyPreset string         `json:"policy_preset"`
}

// RenderTree returns an ASCII tree visualizing parent applications, the SecretHarbor
// boundary demarcation, and child tasks.
func (h *ProcessHierarchy) RenderTree(indent string) string {
	if h == nil || h.AgentNode == nil {
		return ""
	}
	var b strings.Builder

	currIndent := indent
	for _, anc := range h.Ancestors {
		if anc == nil {
			continue
		}
		b.WriteString(fmt.Sprintf("%s%s\n", currIndent, anc.DisplayName))
		b.WriteString(fmt.Sprintf("%s  │\n", currIndent))
		currIndent += "  "
	}

	agentName := h.AgentNode.DisplayName
	if agentName == "" {
		agentName = fmt.Sprintf("Process %d", h.AgentNode.PID)
	}

	if h.Protected {
		b.WriteString(fmt.Sprintf("%s══════════════════════════════════════════════════════\n", currIndent))
		preset := h.PolicyPreset
		if preset == "" {
			preset = "standard"
		}
		b.WriteString(fmt.Sprintf("%s[SecretHarbor Security Boundary - %s policy]\n", currIndent, preset))
		b.WriteString(fmt.Sprintf("%s══════════════════════════════════════════════════════\n", currIndent))
		b.WriteString(fmt.Sprintf("%s  │\n", currIndent))
		b.WriteString(fmt.Sprintf("%s  └── %s  \033[32mPROTECTED\033[0m\n", currIndent, agentName))
		currIndent += "  "
	} else {
		b.WriteString(fmt.Sprintf("%s└── %s  \033[33mUNPROTECTED\033[0m (started before SecretHarbor)\n", currIndent, agentName))
	}

	childIndent := currIndent + "    "
	for _, child := range h.Descendants {
		if child == nil {
			continue
		}
		b.WriteString(fmt.Sprintf("%s│\n", childIndent))
		b.WriteString(fmt.Sprintf("%s└── %s\n", childIndent, child.DisplayName))
	}

	return b.String()
}

// RunningAgentProcess represents a detected agent process running on the host.
type RunningAgentProcess struct {
	AgentID     string            `json:"agent_id"`
	DisplayName string            `json:"display_name"`
	PID         int               `json:"pid"`
	PPID        int               `json:"ppid"`
	Command     string            `json:"command"`
	Args        []string          `json:"args,omitempty"`
	Protected   bool              `json:"protected"`
	SessionID   string            `json:"session_id,omitempty"`
	Hierarchy   *ProcessHierarchy `json:"hierarchy,omitempty"`
}

// QueryProcessOutputForTest allows test suites to inject simulated process tables.
var QueryProcessOutputForTest func() ([]byte, error)

func queryProcessOutput() ([]byte, error) {
	if QueryProcessOutputForTest != nil {
		return QueryProcessOutputForTest()
	}
	cmd := exec.Command("ps", "-eo", "pid,ppid,command")
	out, err := cmd.Output()
	if err != nil {
		cmd = exec.Command("ps", "-eo", "pid,command")
		out, err = cmd.Output()
	}
	return out, err
}

// FormatProcessDisplayName formats a raw command line into a readable display name.
func FormatProcessDisplayName(cmdLine string, pid int) string {
	lower := strings.ToLower(cmdLine)
	if strings.Contains(lower, "antigravity.app") || strings.Contains(lower, "antigravity") {
		if strings.Contains(lower, "renderer") {
			return fmt.Sprintf("UI (Renderer, PID %d)", pid)
		}
		if strings.Contains(lower, "language_server") {
			return fmt.Sprintf("Language Server / Agent Host (PID %d)", pid)
		}
		return fmt.Sprintf("Antigravity (PID %d)", pid)
	}
	if strings.Contains(lower, "kiro.app") || strings.Contains(lower, "kiro") {
		if strings.Contains(lower, "extensionhost") {
			return fmt.Sprintf("Extension Host (PID %d)", pid)
		}
		if strings.Contains(lower, "renderer") {
			return fmt.Sprintf("UI (Renderer, PID %d)", pid)
		}
		return fmt.Sprintf("Kiro (PID %d)", pid)
	}
	if strings.Contains(lower, "opencode.app") || strings.Contains(lower, "opencode") {
		if strings.Contains(lower, "renderer") {
			return fmt.Sprintf("UI (Renderer, PID %d)", pid)
		}
		return fmt.Sprintf("OpenCode (PID %d)", pid)
	}
	if strings.Contains(lower, "windsurf.app") || strings.Contains(lower, "windsurf") {
		if strings.Contains(lower, "renderer") {
			return fmt.Sprintf("UI (Renderer, PID %d)", pid)
		}
		return fmt.Sprintf("Windsurf (PID %d)", pid)
	}
	if strings.Contains(lower, "zed.app") || strings.Contains(lower, "/zed") || strings.HasPrefix(lower, "zed ") {
		return fmt.Sprintf("Zed (PID %d)", pid)
	}
	if strings.Contains(lower, "github copilot") || strings.Contains(lower, "copilot") {
		return fmt.Sprintf("GitHub Copilot (PID %d)", pid)
	}
	if strings.Contains(lower, "ollama.app") || strings.Contains(lower, "/ollama") || strings.HasPrefix(lower, "ollama ") {
		if strings.Contains(lower, "serve") {
			return fmt.Sprintf("Ollama Server (PID %d)", pid)
		}
		return fmt.Sprintf("Ollama (PID %d)", pid)
	}
	if strings.Contains(lower, "openhands") || strings.Contains(lower, "all-hands") {
		return fmt.Sprintf("OpenHands (PID %d)", pid)
	}
	if strings.Contains(lower, "claude.app") && !strings.Contains(lower, "claude-code") {
		return fmt.Sprintf("Claude Desktop (PID %d)", pid)
	}
	if strings.Contains(lower, "cursor.app") && strings.Contains(lower, "renderer") {
		return fmt.Sprintf("UI (Renderer, PID %d)", pid)
	}
	if strings.Contains(lower, "cursor.app") || strings.Contains(lower, "cursor") {
		if strings.Contains(lower, "extensionhost") {
			return fmt.Sprintf("Extension Host (PID %d)", pid)
		}
		return fmt.Sprintf("Cursor (PID %d)", pid)
	}
	if strings.Contains(lower, "visual studio code") || strings.Contains(lower, "/code") || strings.HasPrefix(lower, "code ") {
		if strings.Contains(lower, "extensionhost") {
			return fmt.Sprintf("Extension Host (PID %d)", pid)
		}
		return fmt.Sprintf("VS Code (PID %d)", pid)
	}
	if strings.Contains(lower, "extensionhost") {
		return fmt.Sprintf("Extension Host (PID %d)", pid)
	}
	if strings.Contains(lower, "iterm") {
		return fmt.Sprintf("iTerm2 (PID %d)", pid)
	}
	if strings.Contains(lower, "terminal.app") {
		return fmt.Sprintf("Terminal (PID %d)", pid)
	}
	fields := strings.Fields(cmdLine)
	if len(fields) > 0 {
		base := filepath.Base(fields[0])
		return fmt.Sprintf("%s (PID %d)", base, pid)
	}
	return fmt.Sprintf("Process %d", pid)
}

// ScanRunningProcesses discovers all active processes on the host that match known agent signatures
// and determines whether they are inside an active SecretHarbor sandbox.
func ScanRunningProcesses() ([]*RunningAgentProcess, error) {
	var running []*RunningAgentProcess

	// 1. Fetch active SecretHarbor sessions
	activeSessions, _ := session.List()
	protectedPIDMap := make(map[int]*session.Session)
	for _, sess := range activeSessions {
		protectedPIDMap[sess.PID] = sess
	}

	// 2. Query system processes via ps
	out, err := queryProcessOutput()
	if err != nil {
		// If ps cannot be executed (e.g. sandboxed test runner or constrained container), return running gracefully
		return running, nil
	}

	myPID := os.Getpid()
	scanner := bufio.NewScanner(bytes.NewReader(out))
	allNodes := make(map[int]*ProcessNode)
	var rawRows []struct {
		pid     int
		ppid    int
		cmdLine string
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "PID") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		pid, err := strconv.Atoi(fields[0])
		if err != nil || pid == myPID || pid == 0 {
			continue
		}

		ppid := 0
		cmdStartIdx := 1
		if len(fields) >= 3 {
			if parsedPPID, err := strconv.Atoi(fields[1]); err == nil {
				ppid = parsedPPID
				cmdStartIdx = 2
			}
		}

		cmdLine := strings.Join(fields[cmdStartIdx:], " ")
		if strings.Contains(cmdLine, "ps -eo") || strings.HasPrefix(cmdLine, "grep ") ||
			strings.Contains(cmdLine, "<defunct>") || strings.Contains(cmdLine, "(zombie)") ||
			strings.HasPrefix(cmdLine, "/System/") || strings.HasPrefix(cmdLine, "/usr/libexec/") {
			continue
		}

		node := &ProcessNode{
			PID:         pid,
			PPID:        ppid,
			Command:     cmdLine,
			DisplayName: FormatProcessDisplayName(cmdLine, pid),
		}
		allNodes[pid] = node
		rawRows = append(rawRows, struct {
			pid     int
			ppid    int
			cmdLine string
		}{pid, ppid, cmdLine})
	}

	// Link tree parent/children with cycle prevention
	for _, node := range allNodes {
		if node.PPID <= 0 || node.PPID == node.PID {
			continue
		}
		if parent, exists := allNodes[node.PPID]; exists {
			// Check for cycle before linking
			cycle := false
			for p := parent; p != nil; p = p.Parent {
				if p.PID == node.PID {
					cycle = true
					break
				}
			}
			if !cycle {
				node.Parent = parent
				parent.Children = append(parent.Children, node)
			}
		}
	}

	// Find agents and build hierarchy
	for _, row := range rawRows {
		for _, spec := range SupportedAgentsRegistry {
			if matchesAgentCommand(row.cmdLine, spec.ID) {
				sess, isProtected := protectedPIDMap[row.pid]
				sessID := ""
				if isProtected && sess != nil {
					sessID = sess.ID
				}

				agentNode := allNodes[row.pid]
				if agentNode == nil {
					continue
				}

				// Resolve ancestors (up to 5 levels)
				var ancestors []*ProcessNode
				visited := make(map[int]bool)
				curr := agentNode.Parent
				for curr != nil && !visited[curr.PID] && curr.PID > 1 && len(ancestors) < 5 {
					visited[curr.PID] = true
					ancestors = append([]*ProcessNode{curr}, ancestors...)
					curr = curr.Parent
				}

				hierarchy := &ProcessHierarchy{
					Ancestors:    ancestors,
					AgentNode:    agentNode,
					Descendants:  agentNode.Children,
					Protected:    isProtected,
					PolicyPreset: "standard",
				}

				exe, args := ExtractExecutableAndArgs(row.cmdLine)
				running = append(running, &RunningAgentProcess{
					AgentID:     spec.ID,
					DisplayName: spec.DisplayName,
					PID:         row.pid,
					PPID:        row.ppid,
					Command:     row.cmdLine,
					Args:        append([]string{exe}, args...),
					Protected:   isProtected,
					SessionID:   sessID,
					Hierarchy:   hierarchy,
				})
				break
			}
		}
	}

	return running, nil
}

// commandTokens extracts normalized executable basenames, bundle names, and word tokens from a command line.
func commandTokens(cmdLine string) (bases []string, bundles []string, tokens []string) {
	fields := strings.Fields(cmdLine)
	runners := map[string]bool{
		"node": true, "nodejs": true, "python": true, "python3": true, "py": true,
		"bun": true, "deno": true, "poetry": true, "uv": true, "npx": true, "sh": true, "bash": true,
	}

	for i, f := range fields {
		fLower := strings.ToLower(f)
		tokens = append(tokens, fLower)

		base := strings.ToLower(filepath.Base(f))
		baseNoExt := strings.TrimSuffix(base, ".exe")

		// First token is always a candidate executable
		if i == 0 {
			bases = append(bases, baseNoExt)
		} else if i > 0 && len(fields) > 0 && runners[strings.TrimSuffix(strings.ToLower(filepath.Base(fields[0])), ".exe")] {
			// If run through an interpreter/runner, script or target binary is also candidate
			if !strings.HasPrefix(f, "-") {
				bases = append(bases, baseNoExt)
			}
		}

		// Check app bundle
		if idx := strings.Index(fLower, ".app"); idx != -1 {
			bundlePath := ExtractAppBundle(f)
			if bundlePath != "" {
				bundleBase := strings.ToLower(filepath.Base(bundlePath))
				bundles = append(bundles, bundleBase)
			}
		}
	}
	return bases, bundles, tokens
}

// matchesAgentCommand inspects a process command line string for agent signatures.
// Uses exact binary/executable names and word-bounded tokens to prevent false positives (BUG-036).
func matchesAgentCommand(cmdLine string, agentID string) bool {
	lower := strings.ToLower(cmdLine)
	bases, bundles, tokens := commandTokens(cmdLine)

	hasBase := func(targets ...string) bool {
		for _, b := range bases {
			for _, t := range targets {
				if b == t {
					return true
				}
			}
		}
		return false
	}

	hasBundle := func(targets ...string) bool {
		for _, b := range bundles {
			for _, t := range targets {
				if b == t {
					return true
				}
			}
		}
		return false
	}

	hasTokenMatch := func(target string) bool {
		for _, tok := range tokens {
			if tok == target {
				return true
			}
		}
		return false
	}

	switch agentID {
	case "claude":
		if strings.Contains(lower, "google") || strings.Contains(lower, "chrome") {
			return false
		}
		if hasBase("claude", "claude-code") || hasBundle("claude.app") {
			return true
		}
		for _, tok := range tokens {
			if strings.Contains(tok, "@anthropic-ai/claude-code") {
				return true
			}
		}

	case "codex":
		if strings.Contains(lower, "codecs") {
			return false
		}
		return hasBase("codex")

	case "gemini":
		if strings.Contains(lower, "gemini-browser") {
			return false
		}
		return hasBase("gemini")

	case "cursor":
		return hasBase("cursor", "cursor-server") || hasBundle("cursor.app")

	case "aider":
		return hasBase("aider")

	case "cline":
		return hasBase("cline")

	case "antigravity":
		return hasBase("antigravity", "agy", "antigravity-ide", "agy-ide") ||
			hasBundle("antigravity.app", "antigravity ide.app")

	case "kiro":
		return hasBase("kiro") || hasBundle("kiro.app")

	case "opencode":
		return hasBase("opencode") || hasBundle("opencode.app")

	case "pi":
		if hasBase("pi", "pi-agent") {
			return true
		}
		for _, tok := range tokens {
			if strings.Contains(tok, "@mariozechner/pi") {
				return true
			}
		}

	case "ohmypi":
		return hasBase("ohmypi", "oh-my-pi", "omp")

	case "deepseek":
		if hasBase("deepseek", "deepseek-harness", "dsh") {
			return true
		}
		for _, tok := range tokens {
			if strings.Contains(tok, "@deepseek-ai/dsh") {
				return true
			}
		}

	case "windsurf":
		return hasBase("windsurf") || hasBundle("windsurf.app")

	case "copilot":
		if strings.Contains(lower, "microsoft") {
			return false
		}
		return hasBase("copilot", "gh-copilot", "github-copilot") ||
			hasBundle("github copilot.app") ||
			strings.Contains(lower, "github copilot")

	case "goose":
		return hasBase("goose")

	case "roo":
		return hasBase("roo", "roo-cline", "roo-code", "roo_code")

	case "zed":
		return hasBase("zed") || hasBundle("zed.app")

	case "vscode":
		return hasBase("code") || hasBundle("visual studio code.app", "code.app") ||
			strings.Contains(lower, "visual studio code")

	case "ollama":
		return hasBase("ollama") || hasBundle("ollama.app")

	case "openhands":
		return hasBase("openhands", "all-hands")

	case "devin":
		return hasBase("devin")

	case "amazon-q":
		return hasBase("amazon-q", "aws-q") || (hasTokenMatch("q") && hasTokenMatch("chat"))

	case "cody":
		return hasBase("cody", "cody-cli")

	case "continue":
		return hasBase("continue")

	case "mentat":
		if strings.Contains(lower, "experimentation") {
			return false
		}
		return hasBase("mentat")

	case "claude-desktop":
		return hasBundle("claude.app") && !strings.Contains(lower, "claude-code")
	}

	return false
}

// RunningAppGroup aggregates a root application process and all its child/helper processes.
type RunningAppGroup struct {
	AgentID         string                 `json:"agent_id"`
	DisplayName     string                 `json:"display_name"`
	RootProcess     *RunningAgentProcess   `json:"root_process"`
	HelperProcesses []*RunningAgentProcess `json:"helper_processes"`
	AllPIDs         []int                  `json:"all_pids"`
	Protected       bool                   `json:"protected"`
	AppBundle       string                 `json:"app_bundle,omitempty"`
}

// IsGUIApp returns true if the application process runs from a macOS .app bundle.
func (g *RunningAppGroup) IsGUIApp() bool {
	if g.AppBundle != "" {
		return true
	}
	if g.RootProcess != nil && (strings.Contains(g.RootProcess.Command, ".app/") || strings.Contains(g.RootProcess.Command, ".app ")) {
		return true
	}
	return false
}

// ExtractAppBundle extracts "/path/to/AppName.app" from a command line if present.
func ExtractAppBundle(cmdLine string) string {
	idx := strings.Index(cmdLine, ".app")
	if idx == -1 {
		return ""
	}
	bundleEnd := idx + 4

	prefix := cmdLine[:idx]
	bundleStart := 0
	if spaceSlashIdx := strings.LastIndex(prefix, " /"); spaceSlashIdx != -1 {
		bundleStart = spaceSlashIdx + 1
	} else if spaceTildeIdx := strings.LastIndex(prefix, " ~/"); spaceTildeIdx != -1 {
		bundleStart = spaceTildeIdx + 1
	} else if strings.HasPrefix(prefix, "/") || strings.HasPrefix(prefix, "~/") {
		bundleStart = 0
	} else if lastSpace := strings.LastIndex(prefix, " "); lastSpace != -1 {
		bundleStart = lastSpace + 1
	}

	return strings.TrimSpace(cmdLine[bundleStart:bundleEnd])
}

// ExtractExecutableFromCommand extracts the executable binary path from a command line string.
// Handles paths with spaces like "/Applications/Visual Studio Code.app/Contents/MacOS/Code".
func ExtractExecutableFromCommand(cmdLine string) string {
	cmdLine = strings.TrimSpace(cmdLine)
	if cmdLine == "" {
		return ""
	}

	// 1. If inside a .app bundle, check executable inside Contents/MacOS/
	if idx := strings.Index(cmdLine, ".app/"); idx != -1 {
		appPart := cmdLine[:idx+4]
		rest := cmdLine[idx+5:]
		parts := strings.Split(rest, " ")
		candidateRel := ""
		for _, p := range parts {
			if candidateRel == "" {
				candidateRel = p
			} else {
				candidateRel += " " + p
			}
			fullCandidate := filepath.Join(appPart, candidateRel)
			if fi, err := os.Stat(fullCandidate); err == nil && !fi.IsDir() {
				return fullCandidate
			}
		}
	}

	// 2. Generic path with potential spaces: test progressively longer space-separated prefixes
	parts := strings.Split(cmdLine, " ")
	candidate := ""
	for _, p := range parts {
		if candidate == "" {
			candidate = p
		} else {
			candidate += " " + p
		}
		if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
			return candidate
		}
	}

	// 3. Fallback to first field
	fields := strings.Fields(cmdLine)
	if len(fields) > 0 {
		return fields[0]
	}
	return ""
}

// ExtractExecutableAndArgs splits a command line into the resolved executable and its arguments.
// Argument quoting is approximated because ps output is already flattened.
func ExtractExecutableAndArgs(cmdLine string) (string, []string) {
	exe := ExtractExecutableFromCommand(cmdLine)
	if exe == "" {
		return "", nil
	}
	idx := strings.Index(cmdLine, exe)
	if idx == -1 {
		return exe, nil
	}
	rest := strings.TrimSpace(cmdLine[idx+len(exe):])
	if rest == "" {
		return exe, nil
	}
	return exe, strings.Fields(rest)
}

// isHelperProcess returns true if a command line represents an internal child/worker/helper process.
func isHelperProcess(cmdLine string) bool {
	lower := strings.ToLower(cmdLine)
	return strings.Contains(lower, "--type=gpu-process") ||
		strings.Contains(lower, "--type=renderer") ||
		strings.Contains(lower, "--type=utility") ||
		strings.Contains(lower, "--type=crashpad-handler") ||
		strings.Contains(lower, "chrome_crashpad_handler") ||
		strings.Contains(lower, "helper (renderer)") ||
		strings.Contains(lower, "helper (plugin)") ||
		strings.Contains(lower, "helper (gpu)") ||
		strings.Contains(lower, "helper.app") ||
		strings.Contains(lower, "shipit") ||
		strings.Contains(lower, "languageserver") ||
		strings.Contains(lower, "eslintserver")
}

// GroupAgentProcesses clusters running processes by application root, collapsing helper processes.
func GroupAgentProcesses(running []*RunningAgentProcess) []*RunningAppGroup {
	if len(running) == 0 {
		return nil
	}

	pidMap := make(map[int]*RunningAgentProcess)
	for _, p := range running {
		pidMap[p.PID] = p
	}

	type groupEntry struct {
		root    *RunningAgentProcess
		helpers []*RunningAgentProcess
		bundle  string
	}

	var rootEntries []*groupEntry
	bundleMap := make(map[string]*groupEntry)
	rootPIDMap := make(map[int]*groupEntry)

	// Sort running by PID ascending so parent processes come first
	sortedProcs := append([]*RunningAgentProcess(nil), running...)
	sort.Slice(sortedProcs, func(i, j int) bool {
		return sortedProcs[i].PID < sortedProcs[j].PID
	})

	for _, p := range sortedProcs {
		bundle := ExtractAppBundle(p.Command)
		isHelper := isHelperProcess(p.Command)

		// Check if any ancestor is in pidMap
		hasAncestorInMap := false
		var ancestorInMap *RunningAgentProcess
		if p.Hierarchy != nil {
			for _, anc := range p.Hierarchy.Ancestors {
				if parentProc, exists := pidMap[anc.PID]; exists {
					hasAncestorInMap = true
					ancestorInMap = parentProc
					break
				}
			}
		}

		// Also check PPID
		if !hasAncestorInMap && p.PPID > 0 {
			if parentProc, exists := pidMap[p.PPID]; exists {
				hasAncestorInMap = true
				ancestorInMap = parentProc
			}
		}

		if (hasAncestorInMap || isHelper) && (bundle != "" && bundleMap[bundle] != nil) {
			bundleMap[bundle].helpers = append(bundleMap[bundle].helpers, p)
			continue
		}

		if hasAncestorInMap && ancestorInMap != nil {
			if g, exists := rootPIDMap[ancestorInMap.PID]; exists {
				g.helpers = append(g.helpers, p)
				continue
			}
			found := false
			for _, g := range rootEntries {
				for _, h := range g.helpers {
					if h.PID == ancestorInMap.PID {
						g.helpers = append(g.helpers, p)
						found = true
						break
					}
				}
				if found {
					break
				}
			}
			if found {
				continue
			}
		}

		if bundle != "" && bundleMap[bundle] != nil {
			bundleMap[bundle].helpers = append(bundleMap[bundle].helpers, p)
			continue
		}

		entry := &groupEntry{
			root:   p,
			bundle: bundle,
		}
		rootEntries = append(rootEntries, entry)
		rootPIDMap[p.PID] = entry
		if bundle != "" {
			bundleMap[bundle] = entry
		}
	}

	var groups []*RunningAppGroup
	for _, entry := range rootEntries {
		allPIDs := []int{entry.root.PID}
		for _, h := range entry.helpers {
			allPIDs = append(allPIDs, h.PID)
		}

		groups = append(groups, &RunningAppGroup{
			AgentID:         entry.root.AgentID,
			DisplayName:     entry.root.DisplayName,
			RootProcess:     entry.root,
			HelperProcesses: entry.helpers,
			AllPIDs:         allPIDs,
			Protected:       entry.root.Protected,
			AppBundle:       entry.bundle,
		})
	}

	return groups
}
