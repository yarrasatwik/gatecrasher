package server

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/watch"
)

// fakeBackend is an in-memory Backend for tests.
type fakeBackend struct {
	mu       sync.Mutex
	reports  map[string]*model.Report
	plans    map[string]*model.PlanRecord
	audit    []AuditRow
	chainOK  bool
	chainN   int
	alerts   []watch.Alert
	subs     []chan watch.Alert
	cfg      SafeConfigView
	calls    []string
	failWith error

	// runGate, when non-nil, blocks RunAudit until closed.
	runGate chan struct{}
}

func newFakeBackend() *fakeBackend {
	rep := sampleReport("R1")
	return &fakeBackend{
		reports: map[string]*model.Report{"R1": rep},
		plans:   map[string]*model.PlanRecord{},
		chainOK: true, chainN: 2,
		audit: []AuditRow{
			{Seq: 1, Time: time.Unix(1700000000, 0), Action: "plan.create", Subject: "P1", Hash: "aaaaaaaaaaaaaaaaaaaa", PrevHash: "0000000000000000"},
			{Seq: 2, Time: time.Unix(1700000100, 0), Action: "plan.approve", Subject: "P1", Actor: "web", Hash: "bbbbbbbbbbbbbbbbbbbb", PrevHash: "aaaaaaaaaaaaaaaaaaaa"},
		},
		cfg: SafeConfigView{Target: "https://shop.example.com", Scope: []string{"shop.example.com", "localhost:8000"},
			AIMode: "off (heuristics)", Project: "Shop", Environments: []string{"Development", "Production"}, Production: []string{"Production"}},
	}
}

func (f *fakeBackend) record(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, s)
}

func (f *fakeBackend) called(prefix string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if len(c) >= len(prefix) && c[:len(prefix)] == prefix {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakeBackend) addPlan(rec model.PlanRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.plans[rec.Plan.ID] = &rec
}

func (f *fakeBackend) RunAudit(ctx context.Context, progress func(stage, msg string)) (string, error) {
	progress("recon", "fetching target")
	if f.runGate != nil {
		select {
		case <-f.runGate:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	progress("attack", "probing with ser.abcdefghijklmnop")
	if f.failWith != nil {
		return "", f.failWith
	}
	return "R1", nil
}

func (f *fakeBackend) Reports() []ReportSummary {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []ReportSummary
	for _, r := range f.reports {
		out = append(out, SummarizeReport(r))
	}
	return out
}

func (f *fakeBackend) Report(id string) (*model.Report, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.reports[id]; ok {
		return r, nil
	}
	return nil, fmt.Errorf("report %q: %w", id, ErrNotFound)
}

func (f *fakeBackend) Plans() []model.PlanRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []model.PlanRecord
	for _, p := range f.plans {
		out = append(out, *p)
	}
	return out
}

func (f *fakeBackend) Plan(id string) (*model.PlanRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p, ok := f.plans[id]; ok {
		cp := *p
		return &cp, nil
	}
	return nil, fmt.Errorf("plan %q: %w", id, ErrNotFound)
}

func (f *fakeBackend) MakePlans(_ context.Context, reportID string) error {
	f.record("make " + reportID)
	if _, err := f.Report(reportID); err != nil {
		return err
	}
	return f.failWith
}

func (f *fakeBackend) setState(id string, st model.PlanState) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.plans[id].State = st
}

func (f *fakeBackend) Approve(_ context.Context, id, typedEnv, typedContaminate, by string) error {
	f.record(fmt.Sprintf("approve %s env=%q contaminate=%q by=%s", id, typedEnv, typedContaminate, by))
	if f.failWith != nil {
		return f.failWith
	}
	f.setState(id, model.PlanApproved)
	return nil
}

func (f *fakeBackend) Reject(_ context.Context, id, by string) error {
	f.record("reject " + id + " by=" + by)
	f.setState(id, model.PlanRejected)
	return nil
}

func (f *fakeBackend) Apply(_ context.Context, id string) error {
	f.record("apply " + id)
	if f.failWith != nil {
		return f.failWith
	}
	f.setState(id, model.PlanApplied)
	return nil
}

func (f *fakeBackend) Verify(_ context.Context, id string) error {
	f.record("verify " + id)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.plans[id].State = model.PlanVerified
	f.plans[id].Verify = []model.VerifyRow{{FindingID: "GC-AAAA1111", Title: "Forgeable segment", Before: model.StatusExploitable, After: model.StatusBlocked, Proof: "probe returned default"}}
	return nil
}

func (f *fakeBackend) Rollback(_ context.Context, id string) error {
	f.record("rollback " + id)
	f.setState(id, model.PlanRolledBack)
	return nil
}

func (f *fakeBackend) AuditEntries() []AuditRow { return f.audit }

func (f *fakeBackend) ChainValid() (bool, int) { return f.chainOK, f.chainN }

func (f *fakeBackend) Alerts() []watch.Alert {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]watch.Alert(nil), f.alerts...)
}

func (f *fakeBackend) SubscribeAlerts() (<-chan watch.Alert, func()) {
	ch := make(chan watch.Alert, 4)
	f.mu.Lock()
	f.subs = append(f.subs, ch)
	f.mu.Unlock()
	return ch, func() {}
}

// push stores an alert and delivers it to subscribers.
func (f *fakeBackend) push(a watch.Alert) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.alerts = append([]watch.Alert{a}, f.alerts...)
	for _, ch := range f.subs {
		ch <- a
	}
}

func (f *fakeBackend) subscribers() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.subs)
}

func (f *fakeBackend) Config() SafeConfigView { return f.cfg }

func sampleReport(id string) *model.Report {
	f1 := model.Finding{
		ID: "GC-AAAA1111", Type: model.FSegmentForgeable, Severity: model.SevCritical, Title: "Anyone can join the beta segment",
		Environment: "Production", Subject: "beta_ui", Category: model.CatSecurityControl, DetectedBy: []model.Method{model.MethodProbe, model.MethodEngine},
		Confirmed: true, Status: model.StatusExploitable, Traits: map[string]string{"plan": "enterprise"},
		Unlocked:    []model.FlagChange{{Flag: "beta_ui", Before: "false", After: "true"}},
		Explanation: &model.Explanation{Title: "t", WhatHappened: "An outsider set a trait.", WhyItMatters: "It unlocks a flag.", BusinessImpact: "Free access.", FixSummary: "Disable client traits.", Source: "template"},
		Repro:       "curl -H 'X-Environment-Key: <CLIENT_KEY>' https://api/identities/",
		Evidence:    []model.Evidence{{Kind: "request", Request: "POST /identities/ with ser.abcdefghijklmnop", Response: "200 OK"}},
		FixPlanID:   "P1",
	}
	f2 := model.Finding{ID: "GC-BBBB2222", Type: model.FSecretExposed, Severity: model.SevHigh, Title: "Secret in remote config", Status: model.StatusExploitable, Confirmed: true}
	f3 := model.Finding{ID: "GC-CCCC3333", Type: model.FControlOK, Severity: model.SevInfo, Title: "Server-only flags hidden", Status: model.StatusBlocked}
	allow := true
	return &model.Report{
		SchemaVersion: model.SchemaVersion, ID: id, Tool: "gatecrasher", Version: "test", CreatedAt: time.Unix(1700000000, 0),
		Target: "https://shop.example.com", Environment: "Production", AIMode: "off (heuristics)", Scope: []string{"shop.example.com"},
		Findings: []model.Finding{f1, f2, f3},
		Settings: []model.EnvSettings{{Environment: "Production", AllowClientTraits: &allow}},
		Reachability: []model.Reachable{{Environment: "Production", Flag: "beta_ui", Enabled: true, Value: "on", Segment: "beta",
			Forgeable: "yes", EngineVerified: true, ForgedTraits: map[string]string{"plan": "enterprise"}}},
		Stats: model.Stats{ProbesSent: 42, DurationMS: 2500, BySeverity: map[string]int{"critical": 1, "high": 1}},
		Notes: []string{"scan complete"},
	}
}

func samplePlan(id string, production, experiment bool, state model.PlanState) model.PlanRecord {
	p := model.Plan{
		ID: id, CreatedAt: time.Unix(1700000200, 0), Environment: "Production", Production: production, Title: "Disable client traits",
		TargetObject:   "environment:Production",
		BeforeSnapshot: map[string]any{"allow_client_traits": true},
		Operations: []model.Operation{
			{Kind: "env.patch", Description: "Turn off allow_client_traits", Automatic: true, Method: "PATCH", Path: "environments/KEY/",
				Body: map[string]any{"allow_client_traits": false}, Before: map[string]any{"allow_client_traits": true}},
			{Kind: "pr.draft", Description: "Open a PR moving the secret out", Draft: "diff --git a/app.js b/app.js\n-const k = 'x'\n+const k = process.env.K"},
		},
		Impact:            []model.ImpactItem{{File: "web/app.js", Line: 42, Snippet: "client.identify(user, {plan})", Message: "App sends traits from the browser", Breaks: true}},
		FindingsAddressed: []string{"GC-AAAA1111"},
		Hash:              "0123456789abcdef0123456789abcdef",
	}
	if experiment {
		p.ExperimentWarning = "Flag checkout_v2 is in a running experiment."
	}
	return model.PlanRecord{Plan: p, State: state}
}
