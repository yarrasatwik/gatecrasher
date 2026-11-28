package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/audit"
	"github.com/yarrasatwik/gatecrasher/internal/fixes"
	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/watch"
)

// auditAndSave runs the inside audit and saves the report like the CLI does.
func auditAndSave(t *testing.T, a *App) *model.Report {
	t.Helper()
	r, err := a.Audit(context.Background(), AuditOptions{Inside: true, Explain: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.SaveReport(r); err != nil {
		t.Fatal(err)
	}
	return r
}

func planFor(t *testing.T, recs []*model.PlanRecord, title string) *model.PlanRecord {
	t.Helper()
	for _, r := range recs {
		if strings.Contains(r.Plan.Title, title) {
			return r
		}
	}
	t.Fatalf("no plan titled %q in %d plans", title, len(recs))
	return nil
}

func statusOf(r *model.Report, id string) model.Status {
	for _, f := range r.Findings {
		if f.ID == id {
			return f.Status
		}
	}
	return ""
}

func TestLifecycleAuditPlanApproveApplyVerifyRollback(t *testing.T) {
	s := newStubFlagsmith(t)
	a := newTestApp(t, s, nil)
	ctx := context.Background()

	// audit + consolidate
	r := auditAndSave(t, a)
	byType := map[model.FindingType]int{}
	for _, f := range r.Findings {
		byType[f.Type]++
		if f.Status != model.StatusExploitable {
			t.Errorf("%s %s is %s in a vulnerable lab", f.ID, f.Type, f.Status)
		}
		if f.Explanation == nil {
			t.Errorf("finding %s has no (template) explanation", f.ID)
		}
	}
	for _, typ := range []model.FindingType{model.FTraitForgery, model.FSettingClientTraitsOn, model.FSettingSensitiveData,
		model.FFlagNotServerOnly, model.FPercentageReroll, model.FVariantReroll, model.FIdentityOverrideLeak, model.FIdentityTraitLeak} {
		if byType[typ] == 0 {
			t.Errorf("audit did not report %s (got %v)", typ, byType)
		}
	}
	if len(r.RootCauses) == 0 || r.Stats.ProbesSent == 0 || r.Environment != "Production" {
		t.Fatalf("root causes=%d probes=%d env=%s", len(r.RootCauses), r.Stats.ProbesSent, r.Environment)
	}
	if loaded, err := a.LoadReport("latest"); err != nil || loaded.ID != r.ID {
		t.Fatalf("latest report = %v, %v", loaded, err)
	}

	// plan
	recs, err := a.MakePlans(ctx, r.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	envPlan := planFor(t, recs, "Disable client-set traits")
	if !envPlan.Plan.Production || envPlan.State != model.PlanPending || len(envPlan.Plan.FindingsAddressed) < 5 {
		t.Fatalf("env plan = %+v", envPlan.Plan)
	}
	linked, _ := a.LoadReport("latest")
	for _, id := range envPlan.Plan.FindingsAddressed {
		for _, f := range linked.Findings {
			if f.ID == id && f.FixPlanID != envPlan.Plan.ID {
				t.Errorf("finding %s links %q, want %s", id, f.FixPlanID, envPlan.Plan.ID)
			}
		}
	}

	// A pending plan cannot be applied; a production approval needs the typed name.
	if _, err := a.Apply(ctx, envPlan.Plan.ID); !errors.Is(err, fixes.ErrNotApproved) {
		t.Fatalf("apply before approval: %v", err)
	}
	if _, err := a.Approve(envPlan.Plan.ID, "alice", fixes.ChannelWeb, "prod", ""); !errors.Is(err, fixes.ErrConfirmEnvironment) {
		t.Fatalf("approve without typed env: %v", err)
	}
	if s.envBool("allow_client_traits") != true {
		t.Fatal("nothing may be written before approval")
	}

	// approve + apply
	if _, err := a.Approve(envPlan.Plan.ID, "alice", fixes.ChannelWeb, "Production", ""); err != nil {
		t.Fatal(err)
	}
	applied, err := a.Apply(ctx, envPlan.Plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if applied.State != model.PlanApplied || applied.AppliedAt == nil || applied.TookMS < 0 {
		t.Fatalf("applied = %+v", applied)
	}
	if s.envBool("allow_client_traits") || !s.envBool("hide_sensitive_data") {
		t.Fatalf("stub env not fixed: traits=%v hide=%v", s.envBool("allow_client_traits"), s.envBool("hide_sensitive_data"))
	}

	// verify: every addressed finding is BLOCKED and the report agrees.
	verified, err := a.Verify(ctx, envPlan.Plan.ID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if verified.State != model.PlanVerified || len(verified.Verify) == 0 {
		t.Fatalf("verified = %s rows=%d err=%q", verified.State, len(verified.Verify), verified.Error)
	}
	for _, row := range verified.Verify {
		if row.Before != model.StatusExploitable || row.After != model.StatusBlocked {
			t.Errorf("row %+v", row)
		}
	}
	after, _ := a.LoadReport("latest")
	if len(after.BeforeAfter) != len(verified.Verify) {
		t.Fatalf("report before/after rows = %d, want %d", len(after.BeforeAfter), len(verified.Verify))
	}
	for _, id := range envPlan.Plan.FindingsAddressed {
		if st := statusOf(after, id); st != model.StatusBlocked {
			t.Errorf("after verify %s is %s", id, st)
		}
	}
	// Unrelated findings are untouched.
	if st := statusOf(after, linkedFinding(t, r, model.FPercentageReroll)); st != model.StatusExploitable {
		t.Errorf("reroll finding is %s after an unrelated fix", st)
	}

	// rollback: the setting is restored and the findings reopen.
	rolled, err := a.Rollback(ctx, envPlan.Plan.ID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if rolled.State != model.PlanRolledBack || !s.envBool("allow_client_traits") || s.envBool("hide_sensitive_data") {
		t.Fatalf("rollback: state=%s traits=%v hide=%v", rolled.State, s.envBool("allow_client_traits"), s.envBool("hide_sensitive_data"))
	}
	reopened, _ := a.LoadReport("latest")
	for _, id := range envPlan.Plan.FindingsAddressed {
		if st := statusOf(reopened, id); st != model.StatusExploitable {
			t.Errorf("after rollback %s is %s, want EXPLOITABLE", id, st)
		}
	}
	if len(reopened.BeforeAfter) != 0 {
		t.Errorf("rollback left %d before/after rows", len(reopened.BeforeAfter))
	}
	// Rolling back twice is a no-op.
	if _, err := a.Rollback(ctx, envPlan.Plan.ID, "alice"); err != nil {
		t.Fatalf("second rollback: %v", err)
	}

	// Every step is in the hash-chained audit log, and the chain is intact.
	seen := map[audit.Action]bool{}
	entries, err := a.Log.Entries()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		seen[e.Action] = true
	}
	for _, act := range []audit.Action{audit.ActionPlan, audit.ActionApprove, audit.ActionRefuse, audit.ActionApply, audit.ActionVerify, audit.ActionRollback} {
		if !seen[act] {
			t.Errorf("audit log has no %q entry", act)
		}
	}
	if ok, broken, err := a.Log.Verify(); err != nil || !ok {
		t.Fatalf("audit chain broken at %d: %v", broken, err)
	}
}

func linkedFinding(t *testing.T, r *model.Report, typ model.FindingType) string {
	t.Helper()
	for _, f := range r.Findings {
		if f.Type == typ {
			return f.ID
		}
	}
	t.Fatalf("no %s finding", typ)
	return ""
}

func TestServerOnlyFixApplyVerifyRollback(t *testing.T) {
	s := newStubFlagsmith(t)
	a := newTestApp(t, s, nil)
	ctx := context.Background()
	r := auditAndSave(t, a)
	recs, err := a.MakePlans(ctx, r.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	rec := planFor(t, recs, "`payment_config` Server-side only")
	if _, err := a.Approve(rec.Plan.ID, "alice", fixes.ChannelWeb, "Production", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Apply(ctx, rec.Plan.ID); err != nil {
		t.Fatal(err)
	}
	if s.featureField(6, "is_server_key_only") != true {
		t.Fatalf("feature not marked server-only: %v", s.featureField(6, "is_server_key_only"))
	}
	v, err := a.Verify(ctx, rec.Plan.ID, "alice")
	if err != nil || v.State != model.PlanVerified {
		t.Fatalf("verify: %v state=%v", err, v)
	}
	// A new audit sees the fix: the finding is gone from the open set.
	if _, err := a.Rollback(ctx, rec.Plan.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	if s.featureField(6, "is_server_key_only") != false {
		t.Fatalf("rollback did not restore: %v", s.featureField(6, "is_server_key_only"))
	}
}

func TestStalePlanIsRefused(t *testing.T) {
	s := newStubFlagsmith(t)
	a := newTestApp(t, s, nil)
	ctx := context.Background()
	r := auditAndSave(t, a)
	recs, err := a.MakePlans(ctx, r.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	rec := planFor(t, recs, "Disable client-set traits")
	if _, err := a.Approve(rec.Plan.ID, "alice", fixes.ChannelWeb, "Production", ""); err != nil {
		t.Fatal(err)
	}
	// Someone fixes the setting by hand after the plan was made.
	s.setEnv("allow_client_traits", false)
	before := len(s.writeLog())
	got, err := a.Apply(ctx, rec.Plan.ID)
	if !errors.Is(err, fixes.ErrStalePlan) {
		t.Fatalf("err = %v, want ErrStalePlan", err)
	}
	if got.State != model.PlanStale || !strings.Contains(got.Error, "allow_client_traits") {
		t.Fatalf("record = %s %q", got.State, got.Error)
	}
	if len(s.writeLog()) != before {
		t.Fatalf("a stale plan wrote to Flagsmith: %v", s.writeLog())
	}
	// A stale plan cannot be approved again; the finding needs a fresh plan.
	if _, err := a.Approve(rec.Plan.ID, "alice", fixes.ChannelWeb, "Production", ""); err == nil {
		t.Fatal("stale plan was approved again")
	}
	// Rolling back something that was never applied changes nothing.
	if _, err := a.Rollback(ctx, rec.Plan.ID, "alice"); err == nil {
		t.Fatal("rollback of a never-applied plan must fail")
	}
}

func TestRejectAndSinglePlan(t *testing.T) {
	s := newStubFlagsmith(t)
	a := newTestApp(t, s, nil)
	ctx := context.Background()
	r := auditAndSave(t, a)
	var settingID string
	for _, f := range r.Findings {
		if f.Type == model.FSettingClientTraitsOn {
			settingID = f.ID
		}
	}
	recs, err := a.MakePlans(ctx, r.ID, settingID)
	if err != nil || len(recs) != 1 {
		t.Fatalf("plans = %d, %v", len(recs), err)
	}
	if _, err := a.MakePlans(ctx, r.ID, "GC-DOESNOTEXIST"); err == nil {
		t.Fatal("expected an error for an unknown finding")
	}
	rej, err := a.Reject(recs[0].Plan.ID, "alice", "not this week")
	if err != nil || rej.State != model.PlanRejected {
		t.Fatalf("reject: %v %v", rej, err)
	}
	if _, err := a.Approve(recs[0].Plan.ID, "alice", fixes.ChannelWeb, "Production", ""); err == nil {
		t.Fatal("a rejected plan cannot be approved")
	}
	if _, err := a.Apply(ctx, "plan-nope"); err == nil {
		t.Fatal("unknown plan must error")
	}
	if len(s.writeLog()) != 0 {
		t.Fatalf("writes = %v", s.writeLog())
	}
}

// HIDDEN: a flag that is Server-side only keeps its engine-proven rollout
// finding open as HIDDEN (not fixed, not gone), and verify keeps saying so.
func TestHiddenFindingSurvivesServerOnlyFlag(t *testing.T) {
	s := newStubFlagsmith(t)
	s.features[4]["is_server_key_only"] = true // early_access_ai
	a := newTestApp(t, s, nil)
	ctx := context.Background()
	r := auditAndSave(t, a)
	var reroll *model.Finding
	for i := range r.Findings {
		if r.Findings[i].Type == model.FPercentageReroll && r.Findings[i].Subject == "early_access_ai" {
			reroll = &r.Findings[i]
		}
	}
	if reroll == nil || reroll.Status != model.StatusHidden {
		t.Fatalf("reroll finding = %+v", reroll)
	}
	if !reroll.Open() {
		t.Fatal("a HIDDEN finding is still open")
	}
	notes := strings.Join(reroll.Notes, " ")
	if !strings.Contains(notes, "Hidden is not fixed") {
		t.Fatalf("notes = %q", notes)
	}
	// Recheck of the same finding agrees: still HIDDEN, never BLOCKED.
	st, proof, err := a.Recheck(ctx, *reroll)
	if err != nil || st != model.StatusHidden || proof == "" {
		t.Fatalf("recheck = %s %q %v", st, proof, err)
	}
	if loaded, _ := a.LoadReport(r.ID); statusOf(loaded, reroll.ID) != model.StatusHidden {
		t.Fatal("saved report lost HIDDEN")
	}
}

func TestBackendDrivesTheWholeLifecycle(t *testing.T) {
	s := newStubFlagsmith(t)
	a := newTestApp(t, s, nil)
	b := &Backend{A: a, Audit: AuditOptions{Inside: true}}
	ctx := context.Background()

	var stages []string
	id, err := b.RunAudit(ctx, func(stage, msg string) { stages = append(stages, stage) })
	if err != nil || id == "" || len(stages) == 0 {
		t.Fatalf("RunAudit = %q, %v (stages %v)", id, err, stages)
	}
	if sums := b.Reports(); len(sums) != 1 || sums[0].ID != id {
		t.Fatalf("Reports = %+v", sums)
	}
	if _, err := b.Report(id); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Report("r-missing"); err == nil {
		t.Fatal("expected not found")
	}
	if err := b.MakePlans(ctx, id); err != nil {
		t.Fatal(err)
	}
	plans := b.Plans()
	if len(plans) < 5 {
		t.Fatalf("plans = %d", len(plans))
	}
	var envPlan, rejectPlan string
	for _, p := range plans {
		if strings.Contains(p.Plan.Title, "Disable client-set traits") {
			envPlan = p.Plan.ID
		} else if strings.Contains(p.Plan.Title, "`internal_api_url`") {
			rejectPlan = p.Plan.ID
		}
	}
	if _, err := b.Plan(envPlan); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Plan("plan-missing"); err == nil {
		t.Fatal("expected not found")
	}
	if err := b.Reject(ctx, rejectPlan, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := b.Approve(ctx, envPlan, "wrong", "", "alice"); err == nil {
		t.Fatal("production approval without the typed name must fail")
	}
	if err := b.Approve(ctx, envPlan, "Production", "", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := b.Apply(ctx, envPlan); err != nil {
		t.Fatal(err)
	}
	if err := b.Verify(ctx, envPlan); err != nil {
		t.Fatal(err)
	}
	if err := b.Rollback(ctx, envPlan); err != nil {
		t.Fatal(err)
	}
	rows := b.AuditEntries()
	if len(rows) < 6 || rows[0].Hash == "" || rows[0].Time.IsZero() {
		t.Fatalf("audit rows = %d", len(rows))
	}
	if ok, n := b.ChainValid(); !ok || n != len(rows) {
		t.Fatalf("chain = %v %d", ok, n)
	}
	cv := b.Config()
	if cv.Project != "Acme Shop" || len(cv.Production) == 0 || cv.AIMode == "" {
		t.Fatalf("config = %+v", cv)
	}
	if len(b.Alerts()) != 0 {
		t.Fatal("no alerts expected")
	}
	ch, cancel := b.SubscribeAlerts()
	a.alerts.publish(watch.Alert{ID: "x"})
	if got := <-ch; got.ID != "x" {
		t.Fatalf("alert = %+v", got)
	}
	cancel()
	cancel() // idempotent
	if len(b.Alerts()) != 1 {
		t.Fatalf("alerts = %d", len(b.Alerts()))
	}
}
