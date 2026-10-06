package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// AuditEvent represents a single recorded security boundary event.
type AuditEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Agent     string    `json:"agent"`
	Operation string    `json:"operation"`
	Resource  string    `json:"resource"`
	Result    string    `json:"result"`
	Details   string    `json:"details,omitempty"`
}

var (
	bearerRegex        = regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*`)
	basicAuthRegex     = regexp.MustCompile(`(?i)Authorization:\s*Basic\s+[A-Za-z0-9+/=]+`)
	privateKeyRegex    = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----`)
	secretValRegex     = regexp.MustCompile(`(?i)(secret|key|token|password|auth|pass|passwd)=[^&\s,;"']+`)
	spaceCredsRegex    = regexp.MustCompile(`(?i)(--api-key|--token|--secret|--password|--passwd|-p)\s+([^\s]+)`)
	apiKeyPatternRegex = regexp.MustCompile(`\b(sk-live-[A-Za-z0-9_\-]+|sk-ant-[A-Za-z0-9_\-]+|sk-[A-Za-z0-9_\-]{16,}|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b`)
	jsonTokenRegex     = regexp.MustCompile(`(?i)"(token|access_token|refresh_token|secret|password|api_key|apiKey|secret_key|private_key)"\s*:\s*"[^"]*"`)
	queryParamsRegex   = regexp.MustCompile(`(?i)([?&](token|access_token|secret|password|api_key|key)=)[^&\s]+`)
	jwtRegex           = regexp.MustCompile(`\beyJ[A-Za-z0-9-_]{10,}\.eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\b`)
)

const maxLogSizeBytes = 10 * 1024 * 1024 // 10MB

// Logger manages thread-safe, redacted audit logging to ~/.secretharbor/audit.log.
type Logger struct {
	mu      sync.Mutex
	logFile *os.File
	path    string
}

// GlobalLogger is the default audit logger.
var GlobalLogger, _ = NewLogger()

func getAuditDir() (string, error) {
	dir := os.Getenv("SECRETHARBOR_DIR")
	if dir != "" {
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = os.Getenv("HOME")
	}
	if home == "" {
		tmpBase := os.TempDir()
		user := os.Getenv("USER")
		if user == "" {
			user = fmt.Sprintf("uid-%d", os.Getuid())
		}
		dir = filepath.Join(tmpBase, fmt.Sprintf(".secretharbor-%s", user))
	} else {
		dir = filepath.Join(home, ".secretharbor")
	}
	return dir, nil
}

// NewLogger initializes the audit logger at ~/.secretharbor/audit.log (or SECRETHARBOR_DIR).
func NewLogger() (*Logger, error) {
	dir, err := getAuditDir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	logPath := filepath.Join(dir, "audit.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}

	return &Logger{
		logFile: f,
		path:    logPath,
	}, nil
}

func (l *Logger) checkRotateLocked() {
	if l.logFile == nil {
		return
	}
	fi, err := l.logFile.Stat()
	if err != nil || fi.Size() < maxLogSizeBytes {
		return
	}
	_ = l.logFile.Close()
	rotatedPath := l.path + ".1"
	_ = os.Rename(l.path, rotatedPath)
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err == nil {
		l.logFile = f
	}
}

// Log records an event with automatic redaction.
func (l *Logger) Log(agent, op, resource, result, details string) {
	if l == nil {
		return
	}

	event := AuditEvent{
		Timestamp: time.Now().UTC(),
		Agent:     agent,
		Operation: op,
		Resource:  Redact(resource),
		Result:    result,
		Details:   Redact(details),
	}

	data, err := json.Marshal(event)
	if err != nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.checkRotateLocked()
	if l.logFile != nil {
		_, _ = l.logFile.Write(append(data, '\n'))
	}
}

// ReadLogs reads and parses recent audit events with bounded memory usage.
func ReadLogs(maxEntries int) ([]AuditEvent, error) {
	dir, err := getAuditDir()
	if err != nil {
		return nil, err
	}
	logPath := filepath.Join(dir, "audit.log")
	f, err := os.Open(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	limit := maxEntries
	if limit <= 0 {
		limit = 1000
	}

	var events []AuditEvent
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		var ev AuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err == nil {
			if len(events) >= limit {
				events = events[1:]
			}
			events = append(events, ev)
		}
	}
	if err := scanner.Err(); err != nil {
		return events, err
	}

	return events, nil
}

// Redact scrubs sensitive tokens, credentials, and keys from a string before logging.
func Redact(input string) string {
	if input == "" {
		return ""
	}
	s := privateKeyRegex.ReplaceAllString(input, "-----BEGIN PRIVATE KEY----- [REDACTED] -----END PRIVATE KEY-----")
	s = basicAuthRegex.ReplaceAllString(s, "Authorization: Basic [REDACTED]")
	s = bearerRegex.ReplaceAllString(s, "Bearer [REDACTED]")
	s = jwtRegex.ReplaceAllString(s, "[REDACTED JWT]")
	s = apiKeyPatternRegex.ReplaceAllString(s, "[REDACTED]")
	s = jsonTokenRegex.ReplaceAllStringFunc(s, func(match string) string {
		parts := strings.SplitN(match, ":", 2)
		if len(parts) == 2 {
			return fmt.Sprintf("%s:\"[REDACTED]\"", parts[0])
		}
		return match
	})
	s = queryParamsRegex.ReplaceAllString(s, "${1}[REDACTED]")
	s = spaceCredsRegex.ReplaceAllString(s, "$1 [REDACTED]")
	s = secretValRegex.ReplaceAllStringFunc(s, func(match string) string {
		parts := strings.SplitN(match, "=", 2)
		if len(parts) == 2 {
			return fmt.Sprintf("%s=[REDACTED]", parts[0])
		}
		return match
	})
	return s
}
