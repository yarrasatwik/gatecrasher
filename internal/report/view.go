package report

import (
	"fmt"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

// engineModule is the Flagsmith SDK module whose version is reported as the
// evaluation engine version.
const engineModule = "github.com/Flagsmith/flagsmith-go-client/v5"

// engineVersion reports the linked Flagsmith engine version, or a generic
// label when build information is unavailable.
func engineVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == engineModule {
				if d.Replace != nil && d.Replace.Version != "" {
					return d.Replace.Version
				}
				return d.Version
			}
		}
	}
	return "Flagsmith Go SDK (version unavailable)"
}

// humanDuration renders milliseconds as e.g. "18.5 s" or "420 ms".
func humanDuration(ms int64) string {
	if ms < 1000 {
		return strconv.FormatInt(ms, 10) + " ms"
	}
	return fmt.Sprintf("%.1f s", (time.Duration(ms) * time.Millisecond).Seconds())
}

// tri renders an optional boolean setting as a mark and a word so state never
// depends on color alone. goodWhen is the value considered secure.
func tri(b *bool, goodWhen bool, onWord, offWord string) (mark, word string) {
	switch {
	case b == nil:
		return "?", "Unknown"
	case *b == goodWhen:
		return "✓", wordFor(*b, onWord, offWord)
	default:
		return "✗", wordFor(*b, onWord, offWord)
	}
}

func wordFor(b bool, onWord, offWord string) string {
	if b {
		return onWord
	}
	return offWord
}

// yesNo renders a bool as a mark and a word.
func yesNo(b bool) string {
	if b {
		return "✓ Yes"
	}
	return "✗ No"
}

// liveWord renders an optional live-verification result.
func liveWord(b *bool) string {
	if b == nil {
		return "— Not run"
	}
	return yesNo(*b)
}

// statusWord renders a status with a mark so it is legible without color.
func statusWord(s model.Status) string {
	switch s {
	case model.StatusBlocked:
		return "✓ BLOCKED"
	case model.StatusExploitable:
		return "✗ EXPLOITABLE"
	case model.StatusHidden:
		return "✗ HIDDEN (still open)"
	case model.StatusNeedsReview:
		return "? NEEDS REVIEW (not counted)"
	default:
		return "? " + string(s)
	}
}

// reviewNote is shown above every list of AI-only suggestions.
const reviewNote = "Not counted. Only the AI flagged these: no deterministic rule and no probe agrees, so they are not findings, not ways in and not in the severity totals. A person can confirm one in the web UI; that decision is written to the audit log."

// reviewItems returns the AI-only suggestions of a report.
func reviewItems(r *model.Report) []model.Finding {
	var out []model.Finding
	for _, f := range r.Findings {
		if f.Status == model.StatusNeedsReview {
			out = append(out, f)
		}
	}
	return out
}

// aiReason is the AI's stated reason for a suggestion.
func aiReason(f model.Finding) string {
	reason := ""
	for _, e := range f.Evidence {
		if e.Note != "" {
			reason = e.Note
		}
	}
	return reason
}

// reachVia describes how an attacker reaches a flag state.
func reachVia(r model.Reachable) string {
	var parts []string
	if len(r.ForgedTraits) > 0 {
		parts = append(parts, "forged traits "+joinKV(r.ForgedTraits))
	}
	if r.Identifier != "" {
		parts = append(parts, "identifier "+r.Identifier)
	}
	if r.Segment != "" {
		parts = append(parts, "segment "+r.Segment)
	}
	if len(parts) == 0 {
		return "public key only"
	}
	return strings.Join(parts, ", ")
}

func joinKV(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + m[k]
	}
	return strings.Join(parts, ", ")
}

// codeLocation is a repo file and line found by impact analysis.
type codeLocation struct {
	File string
	Line int
}

var impactRe = regexp.MustCompile(`(?i)\bimpact:\s*([^\s:]+):(\d+)`)

// impactLocations extracts "impact: path/file.js:42" markers from a finding's
// notes and evidence notes. Paths are normalised to relative, slash-separated
// form; absolute paths and parent traversals are rejected.
func impactLocations(f model.Finding) []codeLocation {
	texts := append([]string{}, f.Notes...)
	for _, e := range f.Evidence {
		texts = append(texts, e.Note)
	}
	var out []codeLocation
	seen := map[codeLocation]bool{}
	for _, t := range texts {
		for _, m := range impactRe.FindAllStringSubmatch(t, -1) {
			line, err := strconv.Atoi(m[2])
			file, ok := cleanRepoPath(m[1])
			if err != nil || line < 1 || !ok {
				continue
			}
			loc := codeLocation{File: file, Line: line}
			if !seen[loc] {
				seen[loc] = true
				out = append(out, loc)
			}
		}
	}
	return out
}

// cleanRepoPath turns p into a safe repo-relative slash path.
func cleanRepoPath(p string) (string, bool) {
	p = strings.ReplaceAll(p, "\\", "/")
	for strings.HasPrefix(p, "./") {
		p = p[2:]
	}
	if p == "" || strings.HasPrefix(p, "/") {
		return "", false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == "" {
			return "", false
		}
	}
	return p, true
}
