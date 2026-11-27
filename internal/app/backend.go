package app

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/yarrasatwik/gatecrasher/internal/fixes"
	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/server"
	"github.com/yarrasatwik/gatecrasher/internal/watch"
)

// Backend adapts App to the web UI's server.Backend interface.
type Backend struct {
	A *App
	// Audit configures the "Run full audit" button.
	Audit AuditOptions
}

var _ server.Backend = (*Backend)(nil)

// RunAudit runs a full audit and saves it.
func (b *Backend) RunAudit(ctx context.Context, progress func(stage, msg string)) (string, error) {
	o := b.Audit
	o.Progress = progress
	r, err := b.A.Audit(ctx, o)
	if err != nil {
		return "", err
	}
	if _, err := b.A.SaveReport(r); err != nil {
		return "", err
	}
	if b.A.receiver != nil {
		b.A.receiver.Seed(findingIDs(r))
	}
	return r.ID, nil
}

// Reports lists saved reports, newest first.
func (b *Backend) Reports() []server.ReportSummary {
	var out []server.ReportSummary
	_ = filepath.WalkDir(b.A.Cfg.ReportDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasPrefix(d.Name(), "r-") || filepath.Ext(p) != ".json" {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		var r model.Report
		if json.Unmarshal(raw, &r) == nil {
			out = append(out, server.SummarizeReport(&r))
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// Report loads one report.
func (b *Backend) Report(id string) (*model.Report, error) {
	r, err := b.A.LoadReport(id)
	if err != nil {
		return nil, errors.Join(server.ErrNotFound, err)
	}
	return r, nil
}

// Plans lists every plan.
func (b *Backend) Plans() []model.PlanRecord {
	recs, err := b.A.Store.List()
	if err != nil {
		return nil
	}
	out := make([]model.PlanRecord, 0, len(recs))
	for i := len(recs) - 1; i >= 0; i-- {
		out = append(out, *recs[i])
	}
	return out
}

// Plan loads one plan.
func (b *Backend) Plan(id string) (*model.PlanRecord, error) {
	rec, err := b.A.Store.Get(id)
	if errors.Is(err, fixes.ErrPlanNotFound) {
		return nil, errors.Join(server.ErrNotFound, err)
	}
	return rec, err
}

// MakePlans builds plans for a report.
func (b *Backend) MakePlans(ctx context.Context, reportID string) error {
	_, err := b.A.MakePlans(ctx, reportID, "")
	return err
}

// Approve records a web approval.
func (b *Backend) Approve(ctx context.Context, id, typedEnv, typedContaminate, by string) error {
	_, err := b.A.Approve(id, by, "web", typedEnv, typedContaminate)
	return err
}

// Reject records a web rejection.
func (b *Backend) Reject(ctx context.Context, id, by string) error {
	_, err := b.A.Reject(id, by, "rejected in web UI")
	return err
}

// Apply applies an approved plan.
func (b *Backend) Apply(ctx context.Context, id string) error {
	_, err := b.A.Apply(ctx, id)
	return err
}

// Verify re-checks an applied plan.
func (b *Backend) Verify(ctx context.Context, id string) error {
	_, err := b.A.Verify(ctx, id, "web")
	return err
}

// Rollback undoes an applied plan.
func (b *Backend) Rollback(ctx context.Context, id string) error {
	_, err := b.A.Rollback(ctx, id, "web")
	return err
}

// AuditEntries returns the hash-chained log.
func (b *Backend) AuditEntries() []server.AuditRow {
	es, err := b.A.Log.Entries()
	if err != nil {
		return nil
	}
	out := make([]server.AuditRow, 0, len(es))
	for _, e := range es {
		row := server.AuditRow{Seq: e.Seq, Action: string(e.Action), Subject: e.PlanID, Actor: e.Actor,
			Detail: string(e.Details), PrevHash: e.PrevHash, Hash: e.Hash}
		row.Time, _ = parseTime(e.Time)
		out = append(out, row)
	}
	return out
}

// ChainValid verifies the audit chain.
func (b *Backend) ChainValid() (bool, int) {
	ok, broken, err := b.A.Log.Verify()
	if err != nil || !ok {
		return false, broken
	}
	es, _ := b.A.Log.Entries()
	return true, len(es)
}

// Alerts returns retained watch alerts.
func (b *Backend) Alerts() []watch.Alert { return b.A.alerts.list() }

// SubscribeAlerts streams new alerts.
func (b *Backend) SubscribeAlerts() (<-chan watch.Alert, func()) { return b.A.alerts.subscribe() }

// Config returns the secret-free configuration view.
func (b *Backend) Config() server.SafeConfigView {
	c := b.A.Cfg
	return server.SafeConfigView{Target: c.TargetURL, Scope: c.Lock().Entries(), AIMode: string(b.A.AI.Mode()),
		Project: c.Flagsmith.Project, Environments: c.Flagsmith.Environments, Production: c.Flagsmith.ProductionEnvironments, Version: Version}
}

func findingIDs(r *model.Report) []string {
	ids := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		ids = append(ids, f.ID)
	}
	return ids
}

// alertHub fans watch alerts out to the web UI. It exists independently of
// a receiver so the UI works whether or not watch mode is running.
type alertHub struct {
	mu   sync.Mutex
	last []watch.Alert
	subs map[chan watch.Alert]struct{}
}

func newAlertHub() *alertHub { return &alertHub{subs: map[chan watch.Alert]struct{}{}} }

func (h *alertHub) publish(al watch.Alert) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.last = append([]watch.Alert{al}, h.last...)
	if len(h.last) > 200 {
		h.last = h.last[:200]
	}
	for c := range h.subs {
		select {
		case c <- al:
		default:
		}
	}
}

func (h *alertHub) list() []watch.Alert {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]watch.Alert(nil), h.last...)
}

func (h *alertHub) subscribe() (<-chan watch.Alert, func()) {
	c := make(chan watch.Alert, 16)
	h.mu.Lock()
	h.subs[c] = struct{}{}
	h.mu.Unlock()
	return c, func() {
		h.mu.Lock()
		if _, ok := h.subs[c]; ok {
			delete(h.subs, c)
			close(c)
		}
		h.mu.Unlock()
	}
}
