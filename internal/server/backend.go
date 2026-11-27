// Package server is Gatecrasher's local web UI (spec §8.14): a dashboard,
// report viewer, plan approval cards, live watch alerts and the audit log.
// It renders server-side with html/template, uses HTMX only for audit
// progress, and talks to the rest of the tool through the Backend interface.
package server

import (
	"context"
	"errors"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/watch"
)

// ErrNotFound is returned (possibly wrapped) by a Backend when a report or
// plan does not exist; the server answers 404.
var ErrNotFound = errors.New("not found")

// ReportSummary is one row of the recent-reports list.
type ReportSummary struct {
	ID          string         `json:"id"`
	CreatedAt   time.Time      `json:"created_at"`
	Target      string         `json:"target,omitempty"`
	Environment string         `json:"environment,omitempty"`
	AIMode      string         `json:"ai_mode,omitempty"`
	WaysIn      int            `json:"ways_in"`
	BySeverity  map[string]int `json:"by_severity,omitempty"`
}

// WaysIn counts the exploitable findings of a report (the "N ways in"
// headline), ignoring controls that held.
func WaysIn(r *model.Report) int {
	n := 0
	for _, f := range r.Findings {
		if f.Type != model.FControlOK && f.Status == model.StatusExploitable {
			n++
		}
	}
	return n
}

// SummarizeReport builds the ReportSummary of a full report.
func SummarizeReport(r *model.Report) ReportSummary {
	return ReportSummary{ID: r.ID, CreatedAt: r.CreatedAt, Target: r.Target, Environment: r.Environment,
		AIMode: r.AIMode, WaysIn: WaysIn(r), BySeverity: r.Stats.BySeverity}
}

// AuditRow is one entry of the hash-chained audit log, as displayed.
type AuditRow struct {
	Seq      int       `json:"seq"`
	Time     time.Time `json:"time"`
	Action   string    `json:"action"`
	Subject  string    `json:"subject,omitempty"`
	Actor    string    `json:"actor,omitempty"`
	Detail   string    `json:"detail,omitempty"`
	PrevHash string    `json:"prev_hash"`
	Hash     string    `json:"hash"`
}

// SafeConfigView is the part of the configuration the UI may show. It never
// carries keys, tokens or secrets.
type SafeConfigView struct {
	Target       string   `json:"target"`
	Scope        []string `json:"scope"`
	AIMode       string   `json:"ai_mode"`
	Project      string   `json:"project,omitempty"`
	Environments []string `json:"environments"`
	Production   []string `json:"production_environments,omitempty"`
	Version      string   `json:"version,omitempty"`
}

// Backend is everything the UI needs from the rest of Gatecrasher. The
// lead implements it; tests use a fake.
type Backend interface {
	// RunAudit runs a full audit, reporting progress, and returns the new report ID.
	RunAudit(ctx context.Context, progress func(stage, msg string)) (reportID string, err error)
	// Reports lists known reports.
	Reports() []ReportSummary
	// Report loads one report; ErrNotFound if missing.
	Report(id string) (*model.Report, error)
	// Plans lists every plan with its lifecycle state.
	Plans() []model.PlanRecord
	// Plan loads one plan; ErrNotFound if missing.
	Plan(id string) (*model.PlanRecord, error)
	// MakePlans builds fix plans for a report's findings.
	MakePlans(ctx context.Context, reportID string) error
	// Approve records a human approval. typedEnv is what the human typed
	// to confirm a Production change; typedContaminate is the experiment
	// confirmation text. The backend must re-validate both.
	Approve(ctx context.Context, id, typedEnv, typedContaminate, by string) error
	// Reject records a rejection.
	Reject(ctx context.Context, id, by string) error
	// Apply applies an approved plan.
	Apply(ctx context.Context, id string) error
	// Verify re-attacks to confirm an applied plan worked.
	Verify(ctx context.Context, id string) error
	// Rollback restores the pre-change state of an applied plan.
	Rollback(ctx context.Context, id string) error
	// AuditEntries returns the audit log, oldest first.
	AuditEntries() []AuditRow
	// ChainValid verifies the hash chain. If valid it returns (true, n)
	// with n entries verified; otherwise (false, seq) with the Seq of the
	// first broken entry.
	ChainValid() (valid bool, n int)
	// Alerts returns retained watch alerts, newest first.
	Alerts() []watch.Alert
	// SubscribeAlerts streams future alerts; call the func to unsubscribe.
	SubscribeAlerts() (<-chan watch.Alert, func())
	// Config returns the secret-free configuration view.
	Config() SafeConfigView
}
