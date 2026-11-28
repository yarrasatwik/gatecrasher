package ai

import (
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
	"github.com/yarrasatwik/gatecrasher/internal/secrets"
)

// maxValueRunes bounds how much of a flag value is shown to the model.
const maxValueRunes = 600

// scrub renders a value for a prompt with every secret replaced by its
// fingerprint (label, length, first 4 characters) and then passes the text
// through redact. name is the flag name, used for context-sensitive detection.
func scrub(name string, v any) string { return truncateRunes(scrubFull(name, v), maxValueRunes) }

// scrubFull is scrub without the length bound (used for whole source files).
func scrubFull(name string, v any) string {
	text := flagsmith.ValueString(v)
	type hit struct{ secret, label string }
	var hits []hit
	for _, sig := range secrets.Scan(name, v) {
		if sig.Secret != "" {
			hits = append(hits, hit{sig.Secret, strings.ToUpper(sig.Kind)})
		}
	}
	sort.Slice(hits, func(i, j int) bool { return len(hits[i].secret) > len(hits[j].secret) })
	for _, h := range hits {
		text = strings.ReplaceAll(text, h.secret, redact.Fingerprint(h.secret, h.label))
	}
	return redact.String(text)
}

// scrubText is scrub for free text (finding fields, evidence, snippets).
func scrubText(s string) string { return scrub("", s) }

func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}
