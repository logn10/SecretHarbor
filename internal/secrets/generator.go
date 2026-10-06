package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// GenerateFakeValue creates a structurally realistic synthetic secret for a given key.
// It is completely decoupled from the real secret value.
func GenerateFakeValue(keyName string) string {
	upper := strings.ToUpper(keyName)

	// Deterministic salt based on the key name itself, never the real secret
	h := sha256.Sum256([]byte("secretharbor:" + keyName))
	shortHex := hex.EncodeToString(h[:8])
	medHex := hex.EncodeToString(h[:16])

	switch {
	case strings.Contains(upper, "STRIPE"):
		if strings.Contains(upper, "PUBLIC") || strings.Contains(upper, "PUBLISHABLE") {
			return fmt.Sprintf("pk_test_secretharbor_fake_%s", shortHex)
		}
		return fmt.Sprintf("sk_test_secretharbor_fake_%s", shortHex)

	case strings.Contains(upper, "OPENAI"):
		return fmt.Sprintf("sk-proj-secretharbor-fake-%s", medHex)

	case strings.Contains(upper, "ANTHROPIC"):
		return fmt.Sprintf("sk-ant-api03-secretharbor-fake-%s", medHex)

	case strings.Contains(upper, "GEMINI") || strings.Contains(upper, "GOOGLE_AI"):
		return fmt.Sprintf("AIzaSyFakeSecretHarbor_%s", shortHex)

	case strings.Contains(upper, "GITHUB") || strings.Contains(upper, "GH_TOKEN"):
		return fmt.Sprintf("ghp_secretharbor_fake_%s", medHex)

	case strings.Contains(upper, "AWS_ACCESS_KEY"):
		return fmt.Sprintf("AKIAFAKEHARBOR%s", strings.ToUpper(shortHex))

	case strings.Contains(upper, "AWS_SECRET"):
		return fmt.Sprintf("secretharbor_fake_aws_secret_%s", medHex)

	case strings.Contains(upper, "DATABASE_URL") || strings.Contains(upper, "DB_URL"):
		return "postgresql://secretharbor_user:fake_password@localhost:5432/fake_db?sslmode=disable"

	case strings.Contains(upper, "MONGO"):
		return "mongodb://secretharbor_user:fake_password@localhost:27017/fake_db"

	case strings.Contains(upper, "REDIS"):
		return "redis://:fake_password@localhost:6379/0"

	case strings.Contains(upper, "JWT") || strings.Contains(upper, "TOKEN"):
		// Structurally valid 3-part base64 token (header.payload.signature)
		return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmYWtlX3VzZXIiLCJyb2xlIjoiZGV2ZWxvcGVyIn0.c2VjcmV0aGFyYm9yX2Zha2Vfc2lnbmF0dXJl"

	case strings.Contains(upper, "PASSWORD") || strings.Contains(upper, "PASS"):
		return fmt.Sprintf("fake_password_%s", shortHex)

	case strings.Contains(upper, "SECRET") || strings.Contains(upper, "KEY"):
		return fmt.Sprintf("secretharbor_fake_%s_%s", sanitizeIdent(keyName), shortHex)

	default:
		return fmt.Sprintf("secretharbor_fake_%s", shortHex)
	}
}

// IsLikelySecretVar returns true if the environment variable name looks sensitive.
func IsLikelySecretVar(key string) bool {
	upper := strings.ToUpper(strings.TrimSpace(key))
	if upper == "" {
		return false
	}
	if strings.HasPrefix(upper, "SECRETHARBOR_") || strings.HasPrefix(upper, "SHB_") {
		return false
	}
	// Non-secret standard shell variables, CA bundles, and TLS trust store paths
	switch upper {
	case "PWD", "OLDPWD", "HOME", "PATH", "SHELL", "USER", "TERM",
		"TMPDIR", "EDITOR", "COLORTERM", "LANG", "LC_ALL", "LC_CTYPE",
		"NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SSL_CERT_DIR",
		"REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "CARGO_HTTP_CAINFO",
		"GIT_SSL_CAINFO", "AWS_CA_BUNDLE", "NO_PROXY", "no_proxy":
		return false
	}

	// Exact keyword matches
	exactKeywords := map[string]bool{
		"SECRET": true, "KEY": true, "TOKEN": true, "PASSWORD": true,
		"PASSWD": true, "PASS": true, "CREDENTIAL": true, "CREDENTIALS": true,
		"APIKEY": true, "PRIVATE": true, "SIGNATURE": true, "SALT": true,
		"DATABASE": true, "DATABASE_URL": true, "DB_URL": true, "DB_PASSWORD": true,
		"PASSPHRASE": true, "PASSKEY": true, "SECRETKEY": true, "PRIVATEKEY": true,
		"AUTH": true,
	}
	if exactKeywords[upper] {
		return true
	}

	// Standard prefixes
	prefixes := []string{
		"SECRET_", "API_", "AUTH_", "PRIVATE_", "TOKEN_",
		"CREDENTIAL_", "PASSWD_", "DB_", "DATABASE_",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(upper, p) {
			return true
		}
	}

	// Standard suffixes
	suffixes := []string{
		"_KEY", "_TOKEN", "_SECRET", "_PASSWORD", "_AUTH",
		"_CREDENTIAL", "_CREDENTIALS", "_PASS", "_PASSWD",
		"_APIKEY", "_PASSPHRASE", "_PASSKEY", "_SIGNATURE", "_SALT",
	}
	for _, s := range suffixes {
		if strings.HasSuffix(upper, s) {
			return true
		}
	}

	// Tokenized word boundary matching (split by _ and -)
	// Ensures words like MONKEY, AUTHORS, PASSENGER, KEYBOARD, BASALT are NOT matched!
	tokens := strings.FieldsFunc(upper, func(r rune) bool {
		return r == '_' || r == '-'
	})
	sensitiveTokens := map[string]bool{
		"SECRET": true, "KEY": true, "TOKEN": true, "PASSWORD": true,
		"PASSWD": true, "CREDENTIAL": true, "CREDENTIALS": true,
		"APIKEY": true, "SIGNATURE": true, "PASSPHRASE": true,
		"PASSKEY": true, "AUTH": true, "SALT": true,
	}
	for _, tok := range tokens {
		if sensitiveTokens[tok] {
			return true
		}
	}

	return false
}

// EnvEntry represents a parsed line or multiline block in an environment file.
type EnvEntry struct {
	RawText   string
	IsComment bool
	IsBlank   bool
	HasExport bool
	Key       string
	RawKey    string
	Value     string
	QuoteType byte // '"', '\'', '`', or 0
	EOL       string
}

// ParseEnvEntries parses .env content supporting export, multiline quoted strings (single,
// double, backtick), escaped quotes, unquoted line continuations, and CRLF line endings.
func ParseEnvEntries(content string) []EnvEntry {
	var entries []EnvEntry
	n := len(content)
	i := 0

	for i < n {
		start := i

		// Skip spaces/tabs at beginning of line
		for i < n && (content[i] == ' ' || content[i] == '\t') {
			i++
		}

		if i >= n {
			entries = append(entries, EnvEntry{
				RawText: content[start:],
				IsBlank: true,
			})
			break
		}

		// Blank line
		if content[i] == '\r' || content[i] == '\n' {
			eol := "\n"
			if content[i] == '\r' && i+1 < n && content[i+1] == '\n' {
				i += 2
				eol = "\r\n"
			} else {
				i++
			}
			entries = append(entries, EnvEntry{
				RawText: content[start:i],
				IsBlank: true,
				EOL:     eol,
			})
			continue
		}

		// Comment line
		if content[i] == '#' {
			for i < n && content[i] != '\n' && content[i] != '\r' {
				i++
			}
			eol := "\n"
			if i < n && content[i] == '\r' {
				if i+1 < n && content[i+1] == '\n' {
					i += 2
					eol = "\r\n"
				} else {
					i++
				}
			} else if i < n && content[i] == '\n' {
				i++
			}
			entries = append(entries, EnvEntry{
				RawText:   content[start:i],
				IsComment: true,
				EOL:       eol,
			})
			continue
		}

		// Check for export prefix
		hasExport := false
		if strings.HasPrefix(content[i:], "export ") || strings.HasPrefix(content[i:], "export\t") {
			hasExport = true
			i += 7
			for i < n && (content[i] == ' ' || content[i] == '\t') {
				i++
			}
		}

		// Scan key until '=' or newline
		keyStart := i
		for i < n && content[i] != '=' && content[i] != '\n' && content[i] != '\r' {
			i++
		}

		if i >= n || content[i] != '=' {
			// No '=' found on this line
			for i < n && content[i] != '\n' && content[i] != '\r' {
				i++
			}
			eol := "\n"
			if i < n && content[i] == '\r' {
				if i+1 < n && content[i+1] == '\n' {
					i += 2
					eol = "\r\n"
				} else {
					i++
				}
			} else if i < n && content[i] == '\n' {
				i++
			}
			entries = append(entries, EnvEntry{
				RawText: content[start:i],
				EOL:     eol,
			})
			continue
		}

		rawKey := content[keyStart:i]
		cleanKey := strings.TrimSpace(rawKey)
		i++ // skip '='

		// Skip whitespace after '='
		for i < n && (content[i] == ' ' || content[i] == '\t') {
			i++
		}

		var parsedVal strings.Builder
		quoteType := byte(0)

		if i < n && (content[i] == '"' || content[i] == '\'' || content[i] == '`') {
			quoteType = content[i]
			i++ // skip opening quote
			for i < n {
				ch := content[i]
				if quoteType == '"' && ch == '\\' {
					if i+1 < n {
						next := content[i+1]
						if next == '"' || next == '\\' {
							parsedVal.WriteByte(next)
							i += 2
							continue
						} else if next == 'n' {
							parsedVal.WriteByte('\n')
							i += 2
							continue
						} else if next == 'r' {
							parsedVal.WriteByte('\r')
							i += 2
							continue
						} else if next == 't' {
							parsedVal.WriteByte('\t')
							i += 2
							continue
						}
					}
					parsedVal.WriteByte(ch)
					i++
				} else if ch == quoteType {
					i++ // skip closing quote
					break
				} else {
					parsedVal.WriteByte(ch)
					i++
				}
			}
			// Skip any trailing inline comment or spaces on the closing line
			for i < n && content[i] != '\n' && content[i] != '\r' {
				i++
			}
		} else {
			// Unquoted value
			for i < n {
				// Line continuation: '\' followed by \r?\n
				if content[i] == '\\' && i+1 < n && (content[i+1] == '\r' || content[i+1] == '\n') {
					i++ // skip '\'
					if i < n && content[i] == '\r' {
						i++
					}
					if i < n && content[i] == '\n' {
						i++
					}
					continue
				}
				if content[i] == '\n' || content[i] == '\r' {
					break
				}
				parsedVal.WriteByte(content[i])
				i++
			}
		}

		eol := "\n"
		if i < n && content[i] == '\r' {
			if i+1 < n && content[i+1] == '\n' {
				i += 2
				eol = "\r\n"
			} else {
				i++
				eol = "\r"
			}
		} else if i < n && content[i] == '\n' {
			i++
			eol = "\n"
		}

		val := parsedVal.String()
		if quoteType == 0 {
			// For unquoted, strip trailing inline comments if preceded by space
			if idx := strings.Index(val, " #"); idx != -1 {
				val = val[:idx]
			}
			val = strings.TrimSpace(val)
		}

		entries = append(entries, EnvEntry{
			RawText:   content[start:i],
			HasExport: hasExport,
			Key:       cleanKey,
			RawKey:    rawKey,
			Value:     val,
			QuoteType: quoteType,
			EOL:       eol,
		})
	}

	return entries
}

// VirtualizeEnvContent reads an existing .env content and produces a synthetic fake .env.
// Comments and structure are preserved. When a multiline secret assignment is encountered,
// the ENTIRE multiline assignment is replaced with the synthetic fake assignment, leaving no
// secret material behind (BUG-001). Supports export, single/double quotes, unquoted continuations,
// backticks, and CRLF (BUG-062).
func VirtualizeEnvContent(r io.Reader) (string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}

	entries := ParseEnvEntries(string(data))
	var out strings.Builder

	for _, entry := range entries {
		if entry.IsBlank || entry.IsComment {
			out.WriteString(entry.RawText)
			continue
		}

		if entry.Key == "" {
			// Unparseable line (e.g. raw secret material without an assignment):
			// never copy it verbatim into the synthetic file.
			eol := entry.EOL
			if eol == "" {
				eol = "\n"
			}
			out.WriteString("# [REDACTED BY SECRETHARBOR]" + eol)
			continue
		}

		if IsLikelySecretVar(entry.Key) {
			fakeVal := GenerateFakeValue(entry.Key)
			prefix := ""
			if entry.HasExport {
				prefix = "export "
			}
			eol := entry.EOL
			if eol == "" {
				eol = "\n"
			}
			out.WriteString(fmt.Sprintf("%s%s=%s%s", prefix, entry.RawKey, fakeVal, eol))
		} else {
			// Non-secret variable like PORT=3000 or NODE_ENV=development: keep as-is
			out.WriteString(entry.RawText)
		}
	}

	return out.String(), nil
}

func sanitizeIdent(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	res := strings.Trim(b.String(), "_")
	if len(res) > 16 {
		res = res[:16]
	}
	return res
}
