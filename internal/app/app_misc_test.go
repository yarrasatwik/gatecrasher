package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/config"
	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/watch"
)

func TestProjectEnvironmentAndHelpers(t *testing.T) {
	s := newStubFlagsmith(t)
	a := newTestApp(t, s, nil)
	ctx := context.Background()
	if !a.InsideView() || a.ReportDir() != a.Cfg.ReportDir {
		t.Fatal("inside view / report dir")
	}
	p, envs, err := a.Project(ctx)
	if err != nil || p.Name != "Acme Shop" || len(envs) != 2 {
		t.Fatalf("project = %+v %d %v", p, len(envs), err)
	}
	if p2, _, _ := a.Project(ctx); p2 != p {
		t.Fatal("project is cached")
	}
	if e, err := a.Environment(ctx, "production"); err != nil || e.Name != "Production" {
		t.Fatalf("env = %+v %v", e, err)
	}
	if _, err := a.Environment(ctx, "Staging"); err == nil || !strings.Contains(err.Error(), "Development, Production") {
		t.Fatalf("missing env err = %v", err)
	}
	refs, keys, err := a.EnvRefs(ctx)
	if err != nil || len(refs) != 2 || !refs[1].Production || refs[0].Production || keys["Production"] != stubClientKey {
		t.Fatalf("refs = %+v %v", refs, err)
	}
	if ap, err := a.Applier(ctx); err != nil || ap == nil {
		t.Fatalf("applier: %v", err)
	}
	if !strings.Contains(EngineVersion(), "flagsmith-go-client") {
		t.Fatalf("engine version = %q", EngineVersion())
	}
	if _, err := a.reportPath("../x"); err == nil {
		t.Fatal("path traversal in a report id must be refused")
	}
	if p, err := a.reportPath("r-1"); err != nil || !strings.HasSuffix(p, "r-1.json") {
		t.Fatalf("reportPath = %q %v", p, err)
	}
	if _, err := a.LoadReport("r-none"); err == nil {
		t.Fatal("missing report must error")
	}
}

func TestWithoutOrgKeyInsideViewIsSkipped(t *testing.T) {
	s := newStubFlagsmith(t)
	a := newTestApp(t, s, func(c *config.Config) { c.OrgAPIKey = "" })
	ctx := context.Background()
	if a.InsideView() {
		t.Fatal("no key, no inside view")
	}
	if _, _, err := a.Project(ctx); !errors.Is(err, flagsmith.ErrNoAdminKey) {
		t.Fatalf("project: %v", err)
	}
	if _, err := a.Applier(ctx); !errors.Is(err, flagsmith.ErrNoAdminKey) {
		t.Fatalf("applier: %v", err)
	}
	if _, err := a.MakePlans(ctx, "latest", ""); err == nil {
		t.Fatal("MakePlans needs a report first")
	}
	r, err := a.Audit(ctx, AuditOptions{Inside: true})
	if err != nil || len(r.Findings) != 0 || len(r.Notes) == 0 || !strings.Contains(r.Notes[0], "no organisation API key") {
		t.Fatalf("report = %+v err=%v", r.Notes, err)
	}
}

func TestAdminFailureSurfacesFromAudit(t *testing.T) {
	s := newStubFlagsmith(t)
	s.failAdmin = true
	a := newTestApp(t, s, nil)
	if _, err := a.Audit(context.Background(), AuditOptions{Inside: true}); err == nil || !strings.Contains(err.Error(), "inside view") {
		t.Fatalf("err = %v", err)
	}
}

func TestNewAIProviders(t *testing.T) {
	for _, mode := range []string{"off", "none", "", "api"} {
		cfg := &config.Config{AI: config.AISettings{Provider: mode}, Model: "m"}
		c, err := newAI(cfg)
		if err != nil || c == nil || c.Mode().On() {
			t.Fatalf("newAI(%q) = %v %v", mode, c, err)
		}
	}
	if _, err := newAI(&config.Config{AI: config.AISettings{Provider: "gpt"}}); err == nil || !strings.Contains(err.Error(), "unknown ai provider") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunningExperimentsAreFoundAndWarned(t *testing.T) {
	s := newStubFlagsmith(t)
	s.experiments = true
	a := newTestApp(t, s, nil)
	ctx := context.Background()
	r, err := a.Audit(ctx, AuditOptions{Inside: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range r.Notes {
		if strings.Contains(n, "Experiment status unknown") {
			t.Fatalf("experiments were readable but notes say %q", n)
		}
	}
	env, _ := a.Environment(ctx, "Production")
	feats, _ := a.Admin.Features(ctx, 1)
	running, known := a.runningExperiments(ctx, env, feats)
	if !known {
		t.Fatal("experiments should be known")
	}
	for flag, exp := range running {
		if flag == "" || exp == "" {
			t.Fatalf("running = %v", running)
		}
	}
}

func TestParityRunsAgainstTheStub(t *testing.T) {
	s := newStubFlagsmith(t)
	a := newTestApp(t, s, nil)
	r, err := a.Audit(context.Background(), AuditOptions{Inside: true, ParitySamples: 20})
	if err != nil {
		t.Fatal(err)
	}
	if r.Stats.ParityChecked == 0 {
		t.Fatalf("parity stats = %+v notes=%v", r.Stats, r.Notes)
	}
}

func TestConfirmFindingThroughBackend(t *testing.T) {
	s := newStubFlagsmith(t)
	a := newTestApp(t, s, nil)
	b := &Backend{A: a}
	r := auditAndSave(t, a)
	// Nothing awaits review in this lab, so a confirmation is refused.
	if err := b.ConfirmFinding(context.Background(), r.ID, r.Findings[0].ID, "alice"); !errors.Is(err, ErrNotReviewable) {
		t.Fatalf("err = %v", err)
	}
	if got := findingIDs(r); len(got) != len(r.Findings) {
		t.Fatalf("findingIDs = %d", len(got))
	}
}

func TestWatchModeLifecycleAndRecheck(t *testing.T) {
	s := newStubFlagsmith(t)
	a := newTestApp(t, s, nil)
	ctx := context.Background()
	w, err := a.StartWatch(ctx, "http://127.0.0.1:1/hook", "http://127.0.0.1:2")
	if err != nil {
		t.Fatal(err)
	}
	if w.Handler() == nil || a.receiver == nil {
		t.Fatal("watcher not started")
	}

	// A change to a segment re-maps and returns the findings tied to it.
	got, err := a.recheckChange(ctx, watch.Change{Kind: "SEGMENT_UPDATED", Environment: "Production", Segment: "gold_plan"})
	if err != nil || len(got) == 0 {
		t.Fatalf("segment recheck = %d %v", len(got), err)
	}
	for _, f := range got {
		if !related(f, watch.Change{Segment: "gold_plan"}) {
			t.Errorf("unrelated finding returned: %s %s", f.Type, f.Subject)
		}
	}
	all, err := a.recheckChange(ctx, watch.Change{Kind: "ENVIRONMENT_UPDATED", Environment: "unknown-env"})
	if err != nil || len(all) < len(got) {
		t.Fatalf("whole-env recheck = %d %v", len(all), err)
	}

	if err := w.Close(ctx); err != nil || a.receiver != nil {
		t.Fatalf("close: %v", err)
	}
	var sawCreate, sawDelete bool
	for _, w := range s.writeLog() {
		sawCreate = sawCreate || strings.HasPrefix(w, "POST organisations/1/webhooks/ ")
		sawDelete = sawDelete || strings.HasPrefix(w, "DELETE organisations/1/webhooks/1/")
	}
	if !sawCreate || !sawDelete {
		t.Fatalf("webhook not registered and removed: %v", s.writeLog())
	}
}

func TestRelatedAndEnvironmentLookup(t *testing.T) {
	f := model.Finding{Type: model.FTraitForgery, Subject: "gold_plan", Unlocked: []model.FlagChange{{Flag: "premium_export"}}}
	for _, c := range []struct {
		name string
		c    watch.Change
		want bool
	}{
		{"segment", watch.Change{Segment: "GOLD_PLAN"}, true},
		{"feature subject", watch.Change{Feature: "gold_plan"}, true},
		{"unlocked flag", watch.Change{Feature: "Premium_Export"}, true},
		{"other", watch.Change{Feature: "banner_text", Segment: "staff"}, false},
	} {
		if related(f, c.c) != c.want {
			t.Errorf("%s: related = %v", c.name, !c.want)
		}
	}
	if !related(model.Finding{Type: model.FSettingClientTraitsOn}, watch.Change{Feature: "x"}) {
		t.Error("environment-wide settings are related to every change")
	}

	s := newStubFlagsmith(t)
	a := newTestApp(t, s, nil)
	for _, in := range []string{"production", stubClientKey, "2"} {
		if name, err := a.environmentByKeyOrName(context.Background(), in); err != nil || name != "Production" {
			t.Errorf("lookup %q = %q %v", in, name, err)
		}
	}
	if _, err := a.environmentByKeyOrName(context.Background(), "nope"); err == nil {
		t.Fatal("expected unknown environment")
	}
}

func TestSmallHelpers(t *testing.T) {
	if nonEmpty("  ", "d") != "d" || nonEmpty("x", "d") != "x" {
		t.Fatal("nonEmpty")
	}
	if maskIdentifier("ceo@acmeshop.dev") != "ce***@acmeshop.dev" {
		t.Fatalf("mask = %q", maskIdentifier("ceo@acmeshop.dev"))
	}
	if trim("abcdef", 3) != "abc…" || trim("ab", 3) != "ab" {
		t.Fatal("trim")
	}
	for v, want := range map[any]string{nil: "null", "s": "string", float64(1): "number", true: "boolean"} {
		if got := valueType(v); got == "" {
			t.Errorf("valueType(%v) = %q, want something like %s", v, got, want)
		}
	}
	if !strings.HasPrefix(probeID(), "gc-probe-") || !strings.HasPrefix(newReportID(), "r-") {
		t.Fatal("ids")
	}
	if !autoFixable(model.Finding{Type: model.FTraitForgery}) || autoFixable(model.Finding{Type: model.FPercentageReroll}) {
		t.Fatal("autoFixable")
	}
	rows := mergeRows([]model.VerifyRow{{FindingID: "a", After: model.StatusExploitable}},
		[]model.VerifyRow{{FindingID: "a", After: model.StatusBlocked}, {FindingID: "b"}})
	if len(rows) != 2 || rows[0].After != model.StatusBlocked {
		t.Fatalf("mergeRows = %+v", rows)
	}
}
