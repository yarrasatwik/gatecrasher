package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

// Summary is the headline arithmetic of a report: root causes and counts.
type Summary struct {
	// WaysIn is the number of exploitable root causes.
	WaysIn int
	// Findings, Blocked and Open satisfy Findings − Blocked = Open.
	Findings, Blocked, Open int
	// Review counts AI-only suggestions (in no other number).
	Review int
	// RootCauses is sorted highest severity first.
	RootCauses []model.RootCause
}

// fallbackCauseID is the root cause of a finding nobody grouped: itself.
func fallbackCauseID(f model.Finding) string {
	return "RC-" + strings.TrimPrefix(f.ID, "GC-")
}

// isSetting reports whether f is a configuration observation rather than a
// reproduced exploit.
func isSetting(f model.Finding) bool {
	switch f.Type {
	case model.FSettingClientTraitsOn, model.FSettingSensitiveData, model.FFlagNotServerOnly:
		return true
	}
	return false
}

// needsReview reports whether f is a deterministic "look at this" item
// rather than a proven problem: a value that only looks random
// (POSSIBLE_SECRET). It is a LOW finding, but never a way in on its own.
func needsReview(f model.Finding) bool {
	return f.Type == model.FPossibleSecret ||
		(f.Type == model.FFlagNotServerOnly && f.Category == model.CatPossibleSecret)
}

func hasProbe(f model.Finding) bool {
	for _, m := range f.DetectedBy {
		if m == model.MethodProbe {
			return true
		}
	}
	return false
}

// Summarize computes the root causes and counts of r without changing it.
// Findings are grouped by their RootCause link (assigned by the audit); a
// finding without one is its own root cause.
//
// A root cause is exploitable, and therefore a way in, when at least one of
// its findings is open (EXPLOITABLE, HIDDEN or UNKNOWN) and it is more than
// hardening. Hardening is a root cause made only of settings findings that no
// live probe reproduced: a risky setting nothing currently exploits. A root
// cause made only of POSSIBLE_SECRET items (a value that merely looks random)
// needs a human review and is not a way in either.
func Summarize(r *model.Report) Summary {
	t := Count(r)
	s := Summary{Findings: t.Found, Blocked: t.Blocked, Open: t.Remaining, Review: t.Review}
	meta := map[string]model.RootCause{}
	for _, c := range r.RootCauses {
		meta[c.ID] = c
	}
	type acc struct {
		cause         model.RootCause
		open, exploit bool
		counted       bool
	}
	byID := map[string]*acc{}
	var order []string
	for _, f := range r.Findings {
		id := f.RootCause
		if id == "" {
			id = fallbackCauseID(f)
		}
		a := byID[id]
		if a == nil {
			c, ok := meta[id]
			if !ok {
				c = model.RootCause{ID: id, Title: f.Title, Environment: f.Environment, Subject: f.Subject}
			}
			c.FindingIDs, c.Severity, c.Exploitable = nil, model.SevInfo, false
			a = &acc{cause: c}
			byID[id] = a
			order = append(order, id)
		}
		a.cause.FindingIDs = append(a.cause.FindingIDs, f.ID)
		if !f.Counted() {
			continue
		}
		if !a.counted || f.Severity > a.cause.Severity {
			a.cause.Severity = f.Severity
		}
		a.counted = true
		a.open = a.open || f.Open()
		a.exploit = a.exploit || (!needsReview(f) && (!isSetting(f) || hasProbe(f)))
	}
	for _, id := range order {
		a := byID[id]
		a.cause.Exploitable = a.open && a.exploit
		if a.cause.Exploitable {
			s.WaysIn++
		}
		s.RootCauses = append(s.RootCauses, a.cause)
	}
	sort.SliceStable(s.RootCauses, func(i, j int) bool {
		a, b := s.RootCauses[i], s.RootCauses[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Exploitable != b.Exploitable {
			return a.Exploitable
		}
		if a.Title != b.Title {
			return a.Title < b.Title
		}
		return a.ID < b.ID
	})
	return s
}

// Headline is the one-line result every surface shows: "N ways in · M
// findings", where N counts exploitable root causes and M confirmed findings.
func Headline(r *model.Report) string {
	s := Summarize(r)
	return HeadlineOf(s.WaysIn, s.Findings)
}

// IncompleteNote is the sentence every surface shows when the request budget
// stopped a stage; empty for a complete run.
func IncompleteNote(r *model.Report) string {
	if len(r.Stats.Incomplete) == 0 {
		return ""
	}
	return "incomplete (budget): " + strings.Join(r.Stats.Incomplete, ", ") +
		". These stages did not finish, so what they could not check is unknown and not reported as safe."
}

// RequestsLine renders the requests actually used, with the budget if one applied.
func RequestsLine(r *model.Report) string {
	if r.Stats.Budget > 0 {
		return fmt.Sprintf("%d of %d used", r.Stats.ProbesSent, r.Stats.Budget)
	}
	return fmt.Sprintf("%d", r.Stats.ProbesSent)
}

func stageRequestLines(r *model.Report) []string {
	keys := make([]string, 0, len(r.Stats.StageRequests))
	for k := range r.Stats.StageRequests {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		line := fmt.Sprintf("%s: %d requests", k, r.Stats.StageRequests[k])
		for _, inc := range r.Stats.Incomplete {
			if inc == k {
				line += " (incomplete (budget))"
			}
		}
		out = append(out, line)
	}
	return out
}

// HeadlineOf formats the headline from the two numbers.
func HeadlineOf(waysIn, findings int) string {
	w, f := "ways in", "findings"
	if waysIn == 1 {
		w = "way in"
	}
	if findings == 1 {
		f = "finding"
	}
	return fmt.Sprintf("%d %s · %d %s", waysIn, w, findings, f)
}

// Group is one root cause with its findings, for display.
type Group struct {
	Cause    model.RootCause
	Findings []model.Finding
	// Kind is "way in", "hardening", "needs review", "closed" or "control held".
	Kind string
}

// GroupByRootCause returns the findings of r under their root causes,
// highest severity first. AI-only suggestions are not findings and are left
// out (they have their own section); a root cause with nothing else is
// skipped.
func GroupByRootCause(r *model.Report) []Group {
	s := Summarize(r)
	byID := map[string]model.Finding{}
	for _, f := range r.Findings {
		byID[f.ID] = f
	}
	var out []Group
	for _, c := range s.RootCauses {
		g := Group{Cause: c}
		open, control, review := false, true, true
		for _, id := range c.FindingIDs {
			f := byID[id]
			if f.Status == model.StatusNeedsReview {
				continue
			}
			g.Findings = append(g.Findings, f)
			open = open || f.Open()
			control = control && f.Type == model.FControlOK
			review = review && needsReview(f)
		}
		if len(g.Findings) == 0 {
			continue
		}
		switch {
		case control:
			g.Kind = "control held"
		case c.Exploitable:
			g.Kind = "way in"
		case open && review:
			g.Kind = "needs review"
		case open:
			g.Kind = "hardening"
		default:
			g.Kind = "closed"
		}
		out = append(out, g)
	}
	return out
}
