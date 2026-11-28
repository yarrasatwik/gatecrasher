package app

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/httpx"
	"github.com/yarrasatwik/gatecrasher/internal/model"
)

// tracker follows one audit's request budget stage by stage. A stage the
// budget stops is recorded in Stats.Incomplete; the audit carries on with
// what it has, and nothing the stage could not check is ever reported safe.
type tracker struct {
	b *httpx.Budget
	r *model.Report
}

// stage runs fn as the named stage and records the requests it sent. When the
// budget is already used up the stage is skipped (no new probes start) and
// marked incomplete. When the budget refused any request of fn, or fn failed
// with ErrBudget, the stage is marked incomplete and the error is dropped:
// running out of budget is a result, not a failure.
func (t *tracker) stage(name string, fn func() error) error {
	if t.b.Exhausted() {
		t.mark(name)
		return nil
	}
	refused, used := t.b.Refused(), t.b.Used()
	err := fn()
	if n := t.b.Used() - used; n > 0 {
		t.r.Stats.StageRequests[name] += n
	}
	if errors.Is(err, httpx.ErrBudget) || t.b.Refused() > refused {
		t.mark(name)
		return nil
	}
	return err
}

// mark records a stage as incomplete (budget), once.
func (t *tracker) mark(name string) {
	if !t.hit(name) {
		t.r.Stats.Incomplete = append(t.r.Stats.Incomplete, name)
	}
}

// hit reports whether the stage was stopped by the budget.
func (t *tracker) hit(name string) bool {
	for _, s := range t.r.Stats.Incomplete {
		if s == name {
			return true
		}
	}
	return false
}

// hourlyBudget is the rolling one-hour request allowance of watch re-checks.
type hourlyBudget struct {
	mu   sync.Mutex
	max  int
	now  func() time.Time
	uses []hourlyUse
}

type hourlyUse struct {
	at time.Time
	n  int
}

func newHourlyBudget(max int, now func() time.Time) *hourlyBudget {
	if now == nil {
		now = time.Now
	}
	return &hourlyBudget{max: max, now: now}
}

// remaining is how many requests may still be sent in the current hour.
func (h *hourlyBudget) remaining() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	cutoff := h.now().Add(-time.Hour)
	kept := h.uses[:0]
	used := 0
	for _, u := range h.uses {
		if u.at.After(cutoff) {
			kept = append(kept, u)
			used += u.n
		}
	}
	h.uses = kept
	return max(0, h.max-used)
}

// record notes n requests sent now.
func (h *hourlyBudget) record(n int) {
	if n <= 0 {
		return
	}
	h.mu.Lock()
	h.uses = append(h.uses, hourlyUse{at: h.now(), n: n})
	h.mu.Unlock()
}

func errHourly(limit int) error {
	return fmt.Errorf("re-check skipped: the limit of %d requests per hour is used up (watch.max_requests_per_hour); it frees up as requests age past one hour", limit)
}
