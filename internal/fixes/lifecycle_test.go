package fixes

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/audit"
	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/verify"
)

// approved plans and approves the Production client-traits fix.
func approved(t *testing.T, h *harness, findings ...model.Finding) *model.PlanRecord {
	t.Helper()
	if len(findings) == 0 {
		findings = []model.Finding{traitFinding()}
	}
	recs := h.planFor(t, shopApp(t), findings...)
	if len(recs) != 1 {
		t.Fatalf("want 1 plan, got %d", len(recs))
	}
	rec, err := h.store.Approve(recs[0].Plan.ID, "alice", "cli", "Production", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func auditActions(t *testing.T, l *audit.Log) []audit.Action {
	t.Helper()
	es, err := l.Entries()
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.Action
	for _, e := range es {
		out = append(out, e.Action)
	}
	return out
}

func TestApproveRequiresTypedProductionName(t *testing.T) {
	h := newHarness(t)
	recs := h.planFor(t, "", traitFinding())
	for _, typed := range []string{"", "production", "Production ", "Staging"} {
		_, err := h.store.Approve(recs[0].Plan.ID, "alice", "cli", typed, "", 0)
		if !errors.Is(err, ErrConfirmEnvironment) {
			t.Fatalf("typed %q: err = %v", typed, err)
		}
	}
	rec, _ := h.store.Get(recs[0].Plan.ID)
	if rec.State != model.PlanPending || rec.Approval != nil {
		t.Fatalf("a refused approval must leave the plan pending: %+v", rec)
	}
	rec, err := h.store.Approve(recs[0].Plan.ID, "alice", "web", "Production", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	a := rec.Approval
	if a.PlanHash != rec.Plan.Hash || a.ConfirmedEnvironment != "Production" || a.ExpiresAt.Sub(a.ApprovedAt) != DefaultApprovalTTL {
		t.Fatalf("approval = %+v", a)
	}
}

func TestApproveNonProductionDoesNotNeedTypedName(t *testing.T) {
	rec := &model.PlanRecord{Plan: model.Plan{ID: "plan-00000001", Environment: "Staging"}, State: model.PlanPending}
	rec.Plan.Hash = rec.Plan.ComputeHash()
	if err := Approve(rec, "bob", "cli", "", "", time.Minute); err != nil {
		t.Fatal(err)
	}
	if rec.State != model.PlanApproved || rec.Approval.ExpiresAt.Sub(rec.Approval.ApprovedAt) != time.Minute {
		t.Fatalf("rec = %+v", rec)
	}
	if err := Approve(rec, "bob", "cli", "", "", 0); err == nil || !strings.Contains(err.Error(), "already approved") {
		t.Fatalf("double approval: %v", err)
	}
}

func TestApproveRequiresContaminateConfirmation(t *testing.T) {
	h := newHarness(t)
	h.fake.experiments = []map[string]any{{"id": float64(1), "name": "e", "status": "RUNNING", "feature": float64(5)}}
	recs := h.planFor(t, "", secretFinding())
	_, err := h.store.Approve(recs[0].Plan.ID, "alice", "cli", "Production", "yes", 0)
	if !errors.Is(err, ErrConfirmContaminate) || !strings.Contains(err.Error(), "contaminates experiment") {
		t.Fatalf("err = %v", err)
	}
	rec, err := h.store.Approve(recs[0].Plan.ID, "alice", "cli", "Production", ContaminateToken, 0)
	if err != nil || !rec.Approval.ContaminateConfirmed {
		t.Fatalf("rec=%+v err=%v", rec, err)
	}
}

func TestApproveRefusesTamperedPlanAndBadInput(t *testing.T) {
	h := newHarness(t)
	recs := h.planFor(t, "", traitFinding())
	rec := recs[0]
	rec.Plan.Operations[0].Body["allow_client_traits"] = true
	if err := Approve(rec, "alice", "cli", "Production", "", 0); !errors.Is(err, ErrPlanTampered) {
		t.Fatalf("err = %v", err)
	}
	rec.Plan.Operations[0].Body["allow_client_traits"] = false
	for _, tc := range []struct{ by, ch string }{{"", "cli"}, {"alice", "slack"}} {
		if err := Approve(rec, tc.by, tc.ch, "Production", "", 0); err == nil {
			t.Fatalf("accepted %+v", tc)
		}
	}
}

func TestRejectPlan(t *testing.T) {
	h := newHarness(t)
	recs := h.planFor(t, "", traitFinding())
	rec, err := h.store.Reject(recs[0].Plan.ID, "alice", "not now")
	if err != nil || rec.State != model.PlanRejected {
		t.Fatalf("rec=%+v err=%v", rec, err)
	}
	if _, err := h.store.Approve(recs[0].Plan.ID, "alice", "cli", "Production", "", 0); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("approving a rejected plan: %v", err)
	}
	if err := h.applier().Apply(t.Context(), rec); err == nil {
		t.Fatal("applied a rejected plan")
	}
}

func TestApplyRefusesStalePlanAfterOutOfBandChange(t *testing.T) {
	h := newHarness(t)
	rec := approved(t, h)
	h.fake.set("allow_client_traits", false) // a human fixed it (or changed it) in the dashboard
	err := h.applier().Apply(t.Context(), rec)
	if !errors.Is(err, ErrStalePlan) || !strings.Contains(err.Error(), "state changed since plan; re-plan") {
		t.Fatalf("err = %v", err)
	}
	if rec.State != model.PlanStale {
		t.Fatalf("state = %s", rec.State)
	}
	saved, _ := h.store.Get(rec.Plan.ID)
	if saved.State != model.PlanStale {
		t.Fatalf("stale state not persisted: %s", saved.State)
	}
	if len(h.fake.writeLog()) != 0 {
		t.Fatalf("a stale plan must not write anything: %v", h.fake.writeLog())
	}
	acts := auditActions(t, h.log)
	if acts[len(acts)-1] != audit.ActionRefuse {
		t.Fatalf("refusal not audited: %v", acts)
	}
}

func TestApplyRefusesExpiredApproval(t *testing.T) {
	h := newHarness(t)
	rec := approved(t, h)
	rec.Approval.ExpiresAt = time.Now().Add(-time.Minute)
	if err := h.store.Save(rec); err != nil {
		t.Fatal(err)
	}
	if err := h.applier().Apply(t.Context(), rec); !errors.Is(err, ErrApprovalExpired) {
		t.Fatalf("err = %v", err)
	}
	if len(h.fake.writeLog()) != 0 || h.fake.get("allow_client_traits") != true {
		t.Fatal("expired approval must not change anything")
	}
	// A fresh approval makes it applicable again.
	rec2, err := h.store.Approve(rec.Plan.ID, "alice", "cli", "Production", "", 0)
	if err != nil {
		t.Fatalf("re-approving after expiry: %v", err)
	}
	if err := h.applier().Apply(t.Context(), rec2); err != nil {
		t.Fatal(err)
	}
}

func TestApplyRefusesHashMismatchAndMissingApproval(t *testing.T) {
	h := newHarness(t)
	rec := approved(t, h)
	rec.Plan.Operations[0].Body = map[string]any{"allow_client_traits": false, "hide_sensitive_data": false}
	if err := h.applier().Apply(t.Context(), rec); !errors.Is(err, ErrPlanTampered) {
		t.Fatalf("tampered plan: %v", err)
	}
	rec = approved(t, newHarness(t))
	rec.Approval.PlanHash = "deadbeef"
	if err := h.applier().Apply(t.Context(), rec); !errors.Is(err, ErrPlanTampered) {
		t.Fatalf("approval bound to another hash: %v", err)
	}
	pending := &model.PlanRecord{Plan: rec.Plan, State: model.PlanPending}
	if err := h.applier().Apply(t.Context(), pending); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("unapproved: %v", err)
	}
	if len(h.fake.writeLog()) != 0 {
		t.Fatal("nothing may be written")
	}
}

func TestApplyRefusesWhenExperimentStartedAfterPlanning(t *testing.T) {
	h := newHarness(t)
	rec := approved(t, h, secretFinding())
	h.fake.experiments = []map[string]any{{"id": float64(1), "name": "late", "status": "RUNNING", "feature": float64(5)}}
	err := h.applier().Apply(t.Context(), rec)
	if !errors.Is(err, ErrConfirmContaminate) {
		t.Fatalf("err = %v", err)
	}
	if h.fake.featureField(5, "is_server_key_only") != false {
		t.Fatal("flag was changed despite the running experiment")
	}
}

func TestApplyWaitsForPropagationAndRollbackRestoresExactly(t *testing.T) {
	h := newHarness(t)
	h.fake.docLag = 3
	rec := approved(t, h, traitFinding(), leakFinding())
	if err := h.applier().Apply(t.Context(), rec); err != nil {
		t.Fatal(err)
	}
	if rec.State != model.PlanApplied || rec.AppliedAt == nil {
		t.Fatalf("rec = %+v", rec)
	}
	if rec.TookMS < 10 {
		t.Fatalf("propagation_ms = %d; the doc lags 3 polls of 5ms so waiting must be recorded", rec.TookMS)
	}
	if h.fake.get("allow_client_traits") != false || h.fake.get("hide_sensitive_data") != true {
		t.Fatalf("env not patched: %v %v", h.fake.get("allow_client_traits"), h.fake.get("hide_sensitive_data"))
	}
	// An unrelated field changed meanwhile must survive the rollback.
	h.fake.set("use_v2_feature_versioning", false)

	for run := 1; run <= 2; run++ {
		writesBefore := len(h.fake.writeLog())
		if err := h.applier().Rollback(t.Context(), rec, "alice"); err != nil {
			t.Fatalf("rollback run %d: %v", run, err)
		}
		if run == 2 && len(h.fake.writeLog()) != writesBefore {
			t.Fatal("second rollback must be a no-op")
		}
		if h.fake.get("allow_client_traits") != true || h.fake.get("hide_sensitive_data") != false {
			t.Fatalf("run %d: not restored: %v %v", run, h.fake.get("allow_client_traits"), h.fake.get("hide_sensitive_data"))
		}
		if rec.State != model.PlanRolledBack {
			t.Fatalf("state = %s", rec.State)
		}
	}
	if err := h.applier().Apply(t.Context(), rec); err == nil {
		t.Fatal("a rolled-back plan must not be re-applicable")
	}
}

func TestRollbackIsIdempotentWhenLiveAlreadyOriginal(t *testing.T) {
	h := newHarness(t)
	rec := approved(t, h)
	if err := h.applier().Apply(t.Context(), rec); err != nil {
		t.Fatal(err)
	}
	h.fake.set("allow_client_traits", true) // restored by hand
	n := len(h.fake.writeLog())
	if err := h.applier().Rollback(t.Context(), rec, "alice"); err != nil {
		t.Fatal(err)
	}
	if len(h.fake.writeLog()) != n || rec.State != model.PlanRolledBack {
		t.Fatalf("writes=%v state=%s", h.fake.writeLog()[n:], rec.State)
	}
	pending := &model.PlanRecord{Plan: rec.Plan, State: model.PlanApproved}
	if err := h.applier().Rollback(t.Context(), pending, "alice"); err == nil {
		t.Fatal("rolling back a plan that was never applied should fail")
	}
}

func TestServerOnlyApplyFallsBackToLiveReadWhenDocOmitsField(t *testing.T) {
	h := newHarness(t)
	h.fake.docOmitsServerOnly = true
	h.fake.docLag = 1
	rec := approved(t, h, secretFinding())
	if err := h.applier().Apply(t.Context(), rec); err != nil {
		t.Fatal(err)
	}
	if h.fake.featureField(5, "is_server_key_only") != true {
		t.Fatal("feature not patched")
	}
	if err := h.applier().Rollback(t.Context(), rec, "alice"); err != nil {
		t.Fatal(err)
	}
	if h.fake.featureField(5, "is_server_key_only") != false {
		t.Fatal("feature not restored")
	}
}

func TestApplyReportsPropagationTimeout(t *testing.T) {
	h := newHarness(t)
	h.fake.docLag = 1 << 20
	rec := approved(t, h)
	ap := h.applier(func(c *Config) { c.Timeout = 60 * time.Millisecond })
	err := ap.Apply(t.Context(), rec)
	if err == nil || !strings.Contains(err.Error(), "not visible in the environment document") {
		t.Fatalf("err = %v", err)
	}
	if rec.State != model.PlanApplied {
		t.Fatalf("the write happened, so state must be applied, got %s", rec.State)
	}
}

func TestApplyFailureIsRecorded(t *testing.T) {
	h := newHarness(t)
	rec := approved(t, h)
	h.fake.failPatch = true
	err := h.applier().Apply(t.Context(), rec)
	if err == nil || rec.Error == "" {
		t.Fatalf("err=%v rec.Error=%q", err, rec.Error)
	}
	if rec.State != model.PlanApproved {
		t.Fatalf("nothing applied, state should stay approved: %s", rec.State)
	}
}

type fakeCLI struct {
	supports bool
	fail     bool
	ran      []string
}

func (c *fakeCLI) Supports(op model.Operation) bool { return c.supports && op.Kind == OpEnvPatch }
func (c *fakeCLI) Run(_ context.Context, op model.Operation, _ map[string]any) error {
	c.ran = append(c.ran, op.Path)
	if c.fail {
		return errors.New("cli exploded")
	}
	return nil
}

func TestApplyPrefersCLIWhenSupportedThenFallsBack(t *testing.T) {
	// The CLI "executes" but the fake Admin never sees a write, so CLI use is
	// visible as a missing PATCH; propagation is then skipped by timeout.
	h := newHarness(t)
	rec := approved(t, h)
	cli := &fakeCLI{supports: true}
	ap := h.applier(func(c *Config) { c.UseCLI, c.CLI, c.Timeout = true, cli, 40*time.Millisecond })
	_ = ap.Apply(t.Context(), rec)
	if len(cli.ran) != 1 || len(h.fake.writeLog()) != 0 {
		t.Fatalf("cli=%v writes=%v", cli.ran, h.fake.writeLog())
	}

	h2 := newHarness(t)
	rec2 := approved(t, h2)
	failing := &fakeCLI{supports: true, fail: true}
	ap2 := h2.applier(func(c *Config) { c.UseCLI, c.CLI = true, failing })
	if err := ap2.Apply(t.Context(), rec2); err != nil {
		t.Fatal(err)
	}
	if h2.fake.get("allow_client_traits") != false {
		t.Fatal("admin API fallback did not run")
	}
	es, _ := h2.log.Entries()
	found := false
	for _, e := range es {
		found = found || strings.Contains(string(e.Details), "used the Admin API instead")
	}
	if !found {
		t.Fatal("fallback not audited")
	}

	h3 := newHarness(t)
	rec3 := approved(t, h3)
	unsupported := &fakeCLI{supports: false}
	ap3 := h3.applier(func(c *Config) { c.UseCLI, c.CLI = true, unsupported })
	if err := ap3.Apply(t.Context(), rec3); err != nil || len(unsupported.ran) != 0 {
		t.Fatalf("err=%v ran=%v", err, unsupported.ran)
	}
}

func TestFeatureStateV2VersioningFlow(t *testing.T) {
	h := newHarness(t)
	h.fake.env["use_v2_feature_versioning"] = true
	h.fake.docEnv["use_v2_feature_versioning"] = true
	p := model.Plan{
		ID: "plan-00000f5a", CreatedAt: time.Now().UTC(), Environment: "Staging", EnvironmentKey: testEnvKey,
		Operations: []model.Operation{{
			Kind: OpFeatureStatePatch, Method: "PATCH", Path: "environments/" + testEnvKey + "/featurestates/9/",
			Body: map[string]any{"enabled": true, "feature_state_value": "on"}, Before: map[string]any{"enabled": false, "feature_state_value": "off"},
			Automatic: true, Via: ViaAdminAPI,
		}},
		BeforeSnapshot: map[string]any{"enabled": false, "feature_state_value": "off"},
	}
	p.Hash = p.ComputeHash()
	rec := &model.PlanRecord{Plan: p, State: model.PlanPending}
	if err := Approve(rec, "alice", "cli", "", "", 0); err != nil {
		t.Fatal(err)
	}
	if err := h.applier().Apply(t.Context(), rec); err != nil {
		t.Fatal(err)
	}
	if len(h.fake.published) != 1 {
		t.Fatalf("version not published: %v", h.fake.published)
	}
	log := strings.Join(h.fake.writeLog(), "\n")
	if !strings.Contains(log, "POST environments/"+testEnvKey+"/features/6/versions/") || !strings.Contains(log, "versions/ver-1/featurestates/100/") || strings.Contains(log, "featurestates/101/") {
		t.Fatalf("v2 flow wrong:\n%s", log)
	}
}

func TestFullLifecycleLeavesAValidAuditChain(t *testing.T) {
	h := newHarness(t)
	findings := []model.Finding{traitFinding()}
	rec := approved(t, h, findings...)
	ap := h.applier()
	if err := ap.Apply(t.Context(), rec); err != nil {
		t.Fatal(err)
	}
	rows := verify.Rerun(t.Context(), rec, findings, func(_ context.Context, f model.Finding) (model.Status, string, error) {
		return model.StatusBlocked, "POST identities: plan trait ignored", nil
	})
	if err := ap.RecordVerify(rec, "alice", rows); err != nil {
		t.Fatal(err)
	}
	if rec.State != model.PlanVerified || len(rec.Verify) != 1 || rec.Verify[0].Before != model.StatusExploitable || rec.Verify[0].After != model.StatusBlocked {
		t.Fatalf("rec = %+v", rec)
	}
	if err := ap.Rollback(t.Context(), rec, "alice"); err != nil {
		t.Fatal(err)
	}
	_ = h.applier().Apply(t.Context(), rec) // refused: plan is rolled back
	other := h.planFor(t, "", secretFinding())
	if _, err := h.store.Reject(other[0].Plan.ID, "alice", "later"); err != nil {
		t.Fatal(err)
	}

	ok, at, err := h.log.Verify()
	if err != nil || !ok {
		t.Fatalf("audit chain broken at %d (err %v)", at, err)
	}
	seen := map[audit.Action]bool{}
	for _, a := range auditActions(t, h.log) {
		seen[a] = true
	}
	for _, want := range []audit.Action{audit.ActionPlan, audit.ActionApprove, audit.ActionApply, audit.ActionVerify, audit.ActionRollback, audit.ActionRefuse, audit.ActionReject} {
		if !seen[want] {
			t.Errorf("audit log has no %q entry", want)
		}
	}
	raw := ""
	es, _ := h.log.Entries()
	for _, e := range es {
		raw += string(e.Details)
	}
	if strings.Contains(raw, testOrgKey) || strings.Contains(raw, testEnvKey) {
		t.Fatal("audit log leaked a key")
	}
}
