// Package redact removes key and secret material from every string that
// leaves the process: logs, reports, evidence, audit entries and AI prompts
// (spec §3.3 rule 6). It combines pattern rules with a registry of exact
// values known at runtime (loaded keys, discovered keys, detected secrets).
package redact

import (
	"regexp"
	"sort"
	"strings"
	"sync"
)

type rule struct {
	re    *regexp.Regexp
	label string
	group int // capture group holding the secret; 0 = whole match
}

var rules = []rule{
	{regexp.MustCompile(`ser\.[A-Za-z0-9_\-]{8,}`), "SERVER_KEY", 0},
	{regexp.MustCompile(`(?i)(Api-Key|Token|Bearer)\s+[A-Za-z0-9._\-]{8,}`), "AUTH", 0},
	{regexp.MustCompile(`(?i)((?:x-environment-key|x-api-key|authorization)["']?\s*[:=]\s*["']?)([A-Za-z0-9._\-]{8,})`), "KEY", 2},
	{regexp.MustCompile(`\b[A-Za-z0-9]{8}\.[A-Za-z0-9]{32}\b`), "ORG_API_KEY", 0},
	{regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{10,}`), "ANTHROPIC_KEY", 0},
	{regexp.MustCompile(`acme_live_[0-9a-fA-F]{8,}`), "SECRET", 0},
	{regexp.MustCompile(`\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{8,}`), "SECRET", 0},
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), "AWS_KEY", 0},
	{regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}`), "GITHUB_TOKEN", 0},
	{regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9\-]{10,}`), "SLACK_TOKEN", 0},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}`), "JWT", 0},
	{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`), "PRIVATE_KEY", 0},
	{regexp.MustCompile(`(?i)((?:secret|password|passwd|api[_-]?key|token|private[_-]?key)["']?\s*[:=]\s*["'])([^"'\s]{6,})`), "SECRET", 2},
}

var (
	mu       sync.RWMutex
	registry = map[string]string{} // exact value -> label
	ordered  []string              // longest first
)

// Register adds an exact secret value that must never appear in output.
// Values shorter than 6 characters are ignored to avoid mangling text.
func Register(value, label string) {
	v := strings.TrimSpace(value)
	if len(v) < 6 {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if _, ok := registry[v]; ok {
		return
	}
	registry[v] = label
	ordered = append(ordered, v)
	sort.Slice(ordered, func(i, j int) bool { return len(ordered[i]) > len(ordered[j]) })
}

// Fingerprint returns a safe description of a secret: label, length and
// its first 4 characters (spec §8.2).
func Fingerprint(value, label string) string {
	p := value
	if len(p) > 4 {
		p = p[:4]
	}
	return "[" + label + " len=" + itoa(len(value)) + " prefix=" + p + "…]"
}

// String returns s with every known and pattern-matched secret replaced.
func String(s string) string {
	if s == "" {
		return s
	}
	mu.RLock()
	for _, v := range ordered {
		if strings.Contains(s, v) {
			s = strings.ReplaceAll(s, v, Fingerprint(v, registry[v]))
		}
	}
	mu.RUnlock()
	for _, r := range rules {
		if r.group == 0 {
			s = r.re.ReplaceAllStringFunc(s, func(m string) string {
				if strings.HasPrefix(m, "[") {
					return m
				}
				return Fingerprint(m, r.label)
			})
			continue
		}
		s = r.re.ReplaceAllStringFunc(s, func(m string) string {
			sub := r.re.FindStringSubmatchIndex(m)
			if sub == nil || sub[2*r.group] < 0 {
				return m
			}
			secret := m[sub[2*r.group]:sub[2*r.group+1]]
			if strings.HasPrefix(secret, "[") || strings.HasPrefix(secret, "<") {
				return m
			}
			return m[:sub[2*r.group]] + Fingerprint(secret, r.label) + m[sub[2*r.group+1]:]
		})
	}
	return s
}

// ContainsSecret reports whether s still holds anything String would change.
func ContainsSecret(s string) bool { return String(s) != s }

// Reset clears the runtime registry. Tests only.
func Reset() {
	mu.Lock()
	registry = map[string]string{}
	ordered = nil
	mu.Unlock()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
