package report

import (
	"fmt"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

// Tally is the open/closed arithmetic of a report. Remaining is counted from
// the open statuses, not derived, so "found − blocked = remaining" is a real
// check: a status nobody accounts for breaks it.
type Tally struct {
	// Found is every finding that is a problem (controls that held are not).
	Found int
	// Blocked is how many of them a re-attack proved closed.
	Blocked int
	// Remaining is how many are still open: EXPLOITABLE, HIDDEN or UNKNOWN.
	Remaining int
	// Hidden is the part of Remaining that client SDKs can no longer reach
	// although the mechanism still exists on a server path.
	Hidden int
}

// Count tallies the findings of r.
func Count(r *model.Report) Tally {
	var t Tally
	for _, f := range r.Findings {
		if !counted(f) {
			continue
		}
		t.Found++
		switch f.Status {
		case model.StatusBlocked:
			t.Blocked++
		case model.StatusHidden:
			t.Hidden++
			t.Remaining++
		case model.StatusExploitable, model.StatusUnknown:
			t.Remaining++
		}
	}
	return t
}

// counted reports whether f is a problem that the headline numbers count.
func counted(f model.Finding) bool {
	return f.Type != model.FControlOK
}

// open reports whether f is a counted finding that is not closed. HIDDEN and
// UNKNOWN are open: neither is ever reported as safe.
func open(f model.Finding) bool {
	return counted(f) && f.Status != model.StatusBlocked
}

// CheckTally verifies that the report's numbers are consistent: found −
// blocked = remaining exactly, and every finding that was re-attacked carries
// the status its latest re-attack produced (a HIDDEN result can never be
// shown as BLOCKED).
func CheckTally(r *model.Report) error {
	t := Count(r)
	if t.Found-t.Blocked != t.Remaining {
		return fmt.Errorf("report %s: found %d − blocked %d = %d, but %d findings are open", r.ID, t.Found, t.Blocked, t.Found-t.Blocked, t.Remaining)
	}
	after := map[string]model.Status{}
	for _, row := range r.BeforeAfter {
		after[row.FindingID] = row.After
	}
	for _, f := range r.Findings {
		if st, ok := after[f.ID]; ok && st != f.Status {
			return fmt.Errorf("report %s: finding %s is %s but its re-attack ended %s", r.ID, f.ID, f.Status, st)
		}
	}
	return nil
}
