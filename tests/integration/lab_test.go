//go:build lab

// Package integration runs Gatecrasher end to end against the self-hosted
// Flagsmith lab (make lab-up lab-seed; the demo shop on :3030). Run with:
//
//	go test -tags lab -count=1 -timeout 15m ./tests/integration/...
package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/app"
	"github.com/yarrasatwik/gatecrasher/internal/config"
	"github.com/yarrasatwik/gatecrasher/internal/fixes"
	"github.com/yarrasatwik/gatecrasher/internal/lab"
	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
	"github.com/yarrasatwik/gatecrasher/internal/scope"
)

var root string

func TestMain(m *testing.M) {
	r, err := lab.FindRepoRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	root = r
	if err := os.Chdir(root); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	os.Exit(m.Run())
}

// newApp builds an App on a private state/report dir.
func newApp(t *testing.T) *app.App {
	t.Helper()
	cfg, err := config.Load(filepath.Join(root, "gatecrasher.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg.StateDir, cfg.ReportDir = filepath.Join(dir, "state"), filepath.Join(dir, "reports")
	cfg.PropagationTimeoutS = 90
	if cfg.OrgAPIKey == "" {
		t.Fatal("GATECRASHER_ORG_API_KEY missing: run the lab seed first")
	}
	a, err := app.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func reset(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if _, err := lab.Reset(ctx, lab.Options{RepoRoot: root, EnvPath: "-"}); err != nil {
		t.Fatalf("lab reset: %v", err)
	}
}

func fullAudit(t *testing.T, a *app.App, parity int) *model.Report {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	r, err := a.Audit(ctx, app.AuditOptions{Outside: true, Inside: true, ParitySamples: parity, Explain: true})
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if _, err := a.SaveReport(r); err != nil {
		t.Fatal(err)
	}
	return r
}

// expectation identifies one planted vulnerability (spec §7).
type expectation struct {
	types []model.FindingType
	flag  string // subject or unlocked flag
}

var planted = []expectation{
	{[]model.FindingType{model.FTraitForgery}, "premium_export"},
	{[]model.FindingType{model.FTraitForgery}, "admin_panel"},
	{[]model.FindingType{model.FTraitForgery}, "staff_preview"},
	{[]model.FindingType{model.FPercentageReroll}, "early_access_ai"},
	{[]model.FindingType{model.FExperimentRigging, model.FVariantReroll}, "pricing_page"},
	{[]model.FindingType{model.FSecretExposed}, "payment_config"},
	{[]model.FindingType{model.FInternalURL}, "internal_api_url"},
	{[]model.FindingType{model.FUnreleasedProduct}, "project_nightjar_launch_2026_12_15"},
	{[]model.FindingType{model.FIdentityOverrideLeak}, "beta_dashboard"},
	{[]model.FindingType{model.FIdentityTraitLeak}, ""},
	{[]model.FindingType{model.FSettingClientTraitsOn}, ""},
	{[]model.FindingType{model.FSettingSensitiveData}, ""},
}

func mentions(f model.Finding, flag string) bool {
	if flag == "" || f.Subject == flag {
		return true
	}
	for _, u := range f.Unlocked {
		if u.Flag == flag {
			return true
		}
	}
	return false
}

func find(r *model.Report, e expectation) *model.Finding {
	for i := range r.Findings {
		f := &r.Findings[i]
		for _, t := range e.types {
			if f.Type == t && mentions(*f, e.flag) {
				return f
			}
		}
	}
	return nil
}

func assertAllPlanted(t *testing.T, r *model.Report) {
	t.Helper()
	for _, e := range planted {
		f := find(r, e)
		if f == nil {
			t.Errorf("planted vulnerability not found: %v %s", e.types, e.flag)
			continue
		}
		if f.Status != model.StatusExploitable {
			t.Errorf("%s: status %s, want EXPLOITABLE", f.Title, f.Status)
		}
	}
	for _, f := range r.Findings {
		for _, control := range []string{"maintenance_mode", "banner_text"} {
			if mentions(f, control) && f.Subject != "" {
				t.Errorf("false positive on control %s: %s", control, f.Title)
			}
		}
	}
}

func TestAuditFindsEveryPlantedVulnerability(t *testing.T) {
	reset(t)
	a := newApp(t)
	r := fullAudit(t, a, 300)
	assertAllPlanted(t, r)
	for _, e := range planted[:3] {
		f := find(r, e)
		if f == nil {
			continue
		}
		live := false
		for _, m := range f.DetectedBy {
			live = live || m == model.MethodProbe
		}
		if !live || !f.Confirmed {
			t.Errorf("%s: not reproduced against the live API", f.Title)
		}
	}
	if r.Stats.ParityChecked != 300 || r.Stats.ParityAgreed != 300 {
		t.Errorf("parity %d/%d, want 300/300", r.Stats.ParityAgreed, r.Stats.ParityChecked)
	}
	raw, _ := json.Marshal(r)
	if redact.ContainsSecret(string(raw)) {
		t.Error("report JSON contains key or secret material")
	}
	t.Logf("MEASURED audit: %d findings, %d requests, %d ms, parity %d/%d",
		len(r.Findings), r.Stats.ProbesSent, r.Stats.DurationMS, r.Stats.ParityAgreed, r.Stats.ParityChecked)
}

func TestOutOfScopeTargetRefused(t *testing.T) {
	a := newApp(t)
	_, err := a.Audit(context.Background(), app.AuditOptions{Target: "https://example.com/", Outside: true})
	if !errors.Is(err, scope.ErrOutOfScope) {
		t.Fatalf("want ErrOutOfScope, got %v", err)
	}
}

func TestFixVerifyRollbackAndReset(t *testing.T) {
	reset(t)
	a := newApp(t)
	ctx := context.Background()
	before := fullAudit(t, a, 0)
	recs, err := a.MakePlans(ctx, "latest", "")
	if err != nil {
		t.Fatal(err)
	}
	var applied []*model.PlanRecord
	for _, rec := range recs {
		if !hasAuto(rec.Plan) {
			continue
		}
		if _, err := a.Approve(rec.Plan.ID, "it", "cli", "", ""); err == nil {
			t.Fatalf("%s: production approval without typed environment name was accepted", rec.Plan.ID)
		}
		if _, err := a.Approve(rec.Plan.ID, "it", "cli", rec.Plan.Environment, ""); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		done, err := a.Apply(ctx, rec.Plan.ID)
		if err != nil {
			t.Fatalf("apply %s: %v", rec.Plan.ID, err)
		}
		t.Logf("MEASURED fix %q live after %d ms (apply call %d ms)", rec.Plan.Title, done.TookMS, time.Since(start).Milliseconds())
		v, err := a.Verify(ctx, rec.Plan.ID, "it")
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range v.Verify {
			if row.After != model.StatusBlocked {
				t.Errorf("after fix %s: %s is %s, want BLOCKED (%s)", rec.Plan.ID, row.Title, row.After, row.Proof)
			}
		}
		applied = append(applied, v)
		if e, err := a.Admin.Environment(ctx, mustEnvKey(t, a)); err == nil {
			t.Logf("  after %s: allow_client_traits=%v hide_sensitive_data=%v", rec.Plan.ID, e.AllowClientTraits, e.HideSensitiveData)
		}
	}
	if len(applied) < 3 {
		t.Fatalf("expected at least 3 automatic plans, got %d", len(applied))
	}
	checkShop(t)
	after := fullAudit(t, a, 0)
	if n := ways(after); n >= ways(before) || n > 2 {
		t.Errorf("ways in after fixes = %d (before %d); only re-roll guidance should remain", n, ways(before))
		for _, f := range after.Findings {
			if f.Status == model.StatusExploitable {
				t.Logf("  still open: %s %s %v", f.Type, f.Title, f.DetectedBy)
			}
		}
	}
	for _, rec := range applied {
		for i := 0; i < 2; i++ {
			if _, err := a.Rollback(ctx, rec.Plan.ID, "it"); err != nil {
				t.Fatalf("rollback %s (run %d): %v", rec.Plan.ID, i+1, err)
			}
		}
	}
	time.Sleep(25 * time.Second) // SDK environment cache
	assertAllPlanted(t, fullAudit(t, a, 0))
	ok, broken, err := a.Log.Verify()
	if !ok || err != nil {
		t.Fatalf("audit chain broken at %d: %v", broken, err)
	}
	reset(t)
	assertAllPlanted(t, fullAudit(t, a, 0))
}

func TestStalePlanRefused(t *testing.T) {
	reset(t)
	defer reset(t)
	a := newApp(t)
	ctx := context.Background()
	fullAudit(t, a, 0)
	recs, err := a.MakePlans(ctx, "latest", "")
	if err != nil {
		t.Fatal(err)
	}
	var target *model.PlanRecord
	for _, r := range recs {
		for _, op := range r.Plan.Operations {
			if op.Automatic && strings.Contains(op.Path, "environments/") {
				target = r
			}
		}
	}
	if target == nil {
		t.Fatal("no environment plan")
	}
	if _, err := a.Approve(target.Plan.ID, "it", "cli", target.Plan.Environment, ""); err != nil {
		t.Fatal(err)
	}
	env, err := a.Environment(ctx, target.Plan.Environment)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Admin.Do(ctx, "PATCH", "environments/"+env.APIKey+"/", map[string]any{"hide_sensitive_data": true}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Apply(ctx, target.Plan.ID); !errors.Is(err, fixes.ErrStalePlan) {
		t.Fatalf("want ErrStalePlan after out-of-band change, got %v", err)
	}
}

func TestWatchAlertsOnNewForgeableSegment(t *testing.T) {
	reset(t)
	defer reset(t)
	a := newApp(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	w, err := a.StartWatch(ctx, fmt.Sprintf("http://host.docker.internal:%d/webhook", port), "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close(context.Background()) }()
	srv := &http.Server{Handler: w.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	alerts, unsub := w.Receiver.Subscribe()
	defer unsub()

	p, _, err := a.Project(ctx)
	if err != nil {
		t.Fatal(err)
	}
	env, err := a.Environment(ctx, "Production")
	if err != nil {
		t.Fatal(err)
	}
	feats, err := a.Admin.Features(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	featID := 0
	for _, f := range feats {
		if f.Name == "beta_dashboard" {
			featID = f.ID
		}
	}
	var seg struct {
		ID int `json:"id"`
	}
	rules := []map[string]any{{"type": "ALL", "conditions": []any{}, "rules": []map[string]any{{"type": "ANY", "rules": []any{},
		"conditions": []map[string]any{{"property": "is_beta", "operator": "EQUAL", "value": "true"}}}}}}
	if err := a.Admin.Do(ctx, "POST", fmt.Sprintf("projects/%d/segments/", p.ID), map[string]any{"name": "beta_users", "project": p.ID, "rules": rules}, &seg); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := a.Admin.Do(ctx, "POST", fmt.Sprintf("environments/%s/features/%d/create-segment-override/", env.APIKey, featID),
		map[string]any{"feature_segment": map[string]any{"segment": seg.ID}, "enabled": true,
			"feature_state_value": map[string]any{"type": "unicode", "string_value": ""}}, nil); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(30 * time.Second)
	for {
		select {
		case al := <-alerts:
			for _, f := range al.Findings {
				if mentions(f, "beta_dashboard") && strings.Contains(f.Title, "is_beta") {
					t.Logf("MEASURED watch alert %d ms after the dashboard change (re-check %d ms)", time.Since(start).Milliseconds(), al.LatencyMS)
					return
				}
			}
		case <-deadline:
			t.Fatal("no watch alert within 30s of adding a forgeable segment")
		}
	}
}

func mustEnvKey(t *testing.T, a *app.App) string {
	t.Helper()
	e, err := a.Environment(context.Background(), "Production")
	if err != nil {
		t.Fatal(err)
	}
	return e.APIKey
}

func checkShop(t *testing.T) {
	t.Helper()
	resp, err := http.Get("http://localhost:3030/api/checkout-config")
	if err != nil {
		t.Logf("shop not running; skipping shop check: %v", err)
		return
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != 200 || body["provider"] == nil {
		t.Errorf("shop server path broken after fixes: HTTP %d %v", resp.StatusCode, body)
	}
}

func hasAuto(p model.Plan) bool {
	for _, op := range p.Operations {
		if op.Automatic {
			return true
		}
	}
	return false
}

func ways(r *model.Report) int {
	n := 0
	for _, f := range r.Findings {
		if f.Status == model.StatusExploitable && f.Type != model.FControlOK {
			n++
		}
	}
	return n
}
