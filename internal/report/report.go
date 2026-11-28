// Package report renders the canonical audit report (model.Report) into JSON,
// compact JSON, Markdown, self-contained HTML and SARIF 2.1.0 (spec §8.13).
//
// Every writer works on a redacted deep copy of the report, so no registered
// key or secret can reach any output format, and none of them mutates the
// caller's report.
package report

import (
	"reflect"
	"strings"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
	"github.com/yarrasatwik/gatecrasher/internal/severity"
)

// ToolName is the product name written into every report.
const ToolName = "Gatecrasher"

// Finalize makes r ready to publish: it stamps the schema version and tool
// name, sorts findings (worst first) and recomputes Stats.BySeverity with a
// count for every severity level. AI-only suggestions (NEEDS_REVIEW) are in
// no severity total. It then recomputes the root causes and the headline
// counts (ways_in, finding_count, blocked_count, open_count) from the
// findings' current statuses. It is idempotent.
func Finalize(r *model.Report) {
	r.SchemaVersion = model.SchemaVersion
	if r.Tool == "" {
		r.Tool = ToolName
	}
	if r.Findings == nil {
		r.Findings = []model.Finding{}
	}
	if r.Scope == nil {
		r.Scope = []string{}
	}
	severity.Sort(r.Findings)
	counts := make(map[string]int, int(model.SevCritical)+1)
	for s := model.SevInfo; s <= model.SevCritical; s++ {
		counts[s.String()] = 0
	}
	for _, f := range r.Findings {
		if f.Status != model.StatusNeedsReview {
			counts[f.Severity.String()]++
		}
	}
	r.Stats.BySeverity = counts
	for i := range r.Findings {
		if r.Findings[i].RootCause == "" {
			r.Findings[i].RootCause = fallbackCauseID(r.Findings[i])
		}
	}
	s := Summarize(r)
	r.RootCauses = s.RootCauses
	if r.RootCauses == nil {
		r.RootCauses = []model.RootCause{}
	}
	r.WaysIn, r.FindingCount, r.BlockedCount, r.OpenCount, r.ReviewCount = s.WaysIn, s.Findings, s.Blocked, s.Open, s.Review
}

// WaysIn returns the number of distinct ways an attacker can get in: the
// exploitable root causes (see Summarize). Several findings with one root
// cause are one way in. HIDDEN findings keep their root cause open; AI-only
// suggestions (NEEDS_REVIEW) and hardening notes never count.
func WaysIn(r *model.Report) int {
	return Summarize(r).WaysIn
}

// prepare returns a finalized, redacted deep copy of r for rendering.
func prepare(r *model.Report) *model.Report {
	cp := deepRedact(reflect.ValueOf(r)).Interface().(*model.Report)
	Finalize(cp)
	return cp
}

var timeType = reflect.TypeOf(time.Time{})

// deepRedact returns a deep copy of v in which every string, including map
// keys, has passed through redact.String.
func deepRedact(v reflect.Value) reflect.Value {
	switch v.Kind() {
	case reflect.String:
		out := reflect.New(v.Type()).Elem()
		out.SetString(redact.String(v.String()))
		return out
	case reflect.Ptr:
		if v.IsNil() {
			return v
		}
		out := reflect.New(v.Type().Elem())
		out.Elem().Set(deepRedact(v.Elem()))
		return out
	case reflect.Interface:
		if v.IsNil() {
			return v
		}
		out := reflect.New(v.Type()).Elem()
		out.Set(deepRedact(v.Elem()))
		return out
	case reflect.Struct:
		out := reflect.New(v.Type()).Elem()
		out.Set(v)
		if v.Type() == timeType {
			return out
		}
		for i := 0; i < v.NumField(); i++ {
			if out.Field(i).CanSet() {
				out.Field(i).Set(deepRedact(v.Field(i)))
			}
		}
		return out
	case reflect.Slice:
		if v.IsNil() {
			return v
		}
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(deepRedact(v.Index(i)))
		}
		return out
	case reflect.Map:
		if v.IsNil() {
			return v
		}
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		iter := v.MapRange()
		for iter.Next() {
			out.SetMapIndex(deepRedact(iter.Key()), deepRedact(iter.Value()))
		}
		return out
	default:
		return v
	}
}

// oneLine collapses all whitespace runs to single spaces and truncates to max
// runes, adding an ellipsis when it cuts.
func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if max > 0 && len(r) > max {
		return string(r[:max-1]) + "…"
	}
	return s
}

// headline is the short human title of a finding: the explanation title when
// present, else the finding title.
func headline(f model.Finding) string {
	if f.Explanation != nil && strings.TrimSpace(f.Explanation.Title) != "" {
		return f.Explanation.Title
	}
	return f.Title
}

// severityOrder lists severities from worst to best, for display.
func severityOrder() []model.Severity {
	return []model.Severity{model.SevCritical, model.SevHigh, model.SevMedium, model.SevLow, model.SevInfo}
}
