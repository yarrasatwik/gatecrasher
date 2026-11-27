package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/fixes"
	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
	"github.com/yarrasatwik/gatecrasher/internal/verify"
)

// MakePlans builds fix plans for a report's open findings (optionally only
// one finding), stores them as pending, and links them from the report.
func (a *App) MakePlans(ctx context.Context, reportID, onlyFinding string) ([]*model.PlanRecord, error) {
	r, err := a.LoadReport(reportID)
	if err != nil {
		return nil, err
	}
	p, _, err := a.Project(ctx)
	if err != nil {
		return nil, err
	}
	refs, _, err := a.EnvRefs(ctx)
	if err != nil {
		return nil, err
	}
	var open []model.Finding
	for _, f := range r.Findings {
		if f.Status == model.StatusBlocked || f.Type == model.FControlOK {
			continue
		}
		if onlyFinding != "" && f.ID != onlyFinding {
			continue
		}
		open = append(open, f)
	}
	if onlyFinding != "" && len(open) == 0 {
		return nil, fmt.Errorf("finding %s not found or already blocked", onlyFinding)
	}
	pl := fixes.NewPlanner(fixes.PlannerConfig{Admin: a.Admin, ProjectID: p.ID, Environments: refs,
		RepoDir: a.Cfg.AppRepo, Draft: a.prDraft(ctx)})
	plans, err := pl.Plan(ctx, open)
	if err != nil {
		return nil, err
	}
	recs, err := a.Store.Create(plans)
	if err != nil {
		return nil, err
	}
	link := map[string]string{}
	for _, rec := range recs {
		for _, id := range rec.Plan.FindingsAddressed {
			link[id] = rec.Plan.ID
		}
	}
	for i := range r.Findings {
		if id, ok := link[r.Findings[i].ID]; ok {
			r.Findings[i].FixPlanID = id
		}
	}
	if _, err := a.SaveReport(r); err != nil {
		return recs, err
	}
	return recs, nil
}

// prDraft lets the AI write PR drafts when it is on; otherwise the planner's
// deterministic drafts are used.
func (a *App) prDraft(ctx context.Context) fixes.DraftFunc {
	if !a.AI.Mode().On() {
		return nil
	}
	return func(f model.Finding, impact []model.ImpactItem) string {
		d := a.AI.FixPR(ctx, f, impact)
		if d == nil {
			return ""
		}
		return redact.String(fmt.Sprintf("%s\n\n%s\n\n%s", d.Title, d.Body, d.Diff))
	}
}

// Approve records a human approval for one plan.
func (a *App) Approve(id, by, channel, typedEnv, typedContaminate string) (*model.PlanRecord, error) {
	return a.Store.Approve(id, by, channel, typedEnv, typedContaminate, time.Duration(a.Cfg.ApprovalTTLMinutes)*time.Minute)
}

// Reject records a rejection.
func (a *App) Reject(id, by, reason string) (*model.PlanRecord, error) {
	return a.Store.Reject(id, by, reason)
}

// Apply executes an approved plan (re-checking live state first).
func (a *App) Apply(ctx context.Context, id string) (*model.PlanRecord, error) {
	rec, err := a.Store.Get(id)
	if err != nil {
		return nil, err
	}
	ap, err := a.Applier(ctx)
	if err != nil {
		return nil, err
	}
	if err := ap.Apply(ctx, rec); err != nil {
		return rec, err
	}
	// The applier waits for the environment document. The SDK endpoints can
	// serve a cached environment for a while longer, so also wait until the
	// live API stops reproducing the addressed findings. The measured time
	// is what "the fix took effect" means to a user.
	took, err := a.waitLive(ctx, rec)
	if err == nil {
		rec.TookMS = took.Milliseconds()
		err = a.Store.Save(rec)
	}
	return rec, err
}

// waitLive polls Recheck for every automatically fixable finding of the
// plan until all are BLOCKED or the propagation timeout passes.
func (a *App) waitLive(ctx context.Context, rec *model.PlanRecord) (time.Duration, error) {
	start := time.Now()
	if rec.AppliedAt != nil {
		start = *rec.AppliedAt
	}
	fs := a.planFindings(rec)
	deadline := time.Now().Add(a.Cfg.PropagationTimeout())
	for {
		pending := 0
		for _, f := range fs {
			if !autoFixable(f) {
				continue
			}
			if st, _, err := a.Recheck(ctx, f); err == nil && st == model.StatusExploitable {
				pending++
			}
		}
		if pending == 0 {
			return time.Since(start), nil
		}
		if time.Now().After(deadline) {
			return time.Since(start), fmt.Errorf("%d finding(s) still reproduce after %s; run verify later", pending, a.Cfg.PropagationTimeout())
		}
		select {
		case <-ctx.Done():
			return time.Since(start), ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// autoFixable reports whether an applied plan is expected to block f.
func autoFixable(f model.Finding) bool {
	switch f.Type {
	case model.FPercentageReroll, model.FVariantReroll, model.FExperimentRigging:
		return false
	}
	return true
}

// planFindings returns the latest report's findings addressed by rec, with
// their status as first reported (so before/after stays honest on re-runs).
func (a *App) planFindings(rec *model.PlanRecord) []model.Finding {
	r, err := a.LoadReport("latest")
	if err != nil {
		return nil
	}
	want := map[string]bool{}
	for _, id := range rec.Plan.FindingsAddressed {
		want[id] = true
	}
	first := map[string]model.Status{}
	for _, row := range rec.Verify {
		first[row.FindingID] = row.Before
	}
	var fs []model.Finding
	for _, f := range r.Findings {
		if !want[f.ID] {
			continue
		}
		if st, ok := first[f.ID]; ok {
			f.Status = st
		} else if f.Status == model.StatusBlocked {
			f.Status = model.StatusExploitable
		}
		fs = append(fs, f)
	}
	return fs
}

// Rollback restores the plan's before-snapshot.
func (a *App) Rollback(ctx context.Context, id, by string) (*model.PlanRecord, error) {
	rec, err := a.Store.Get(id)
	if err != nil {
		return nil, err
	}
	ap, err := a.Applier(ctx)
	if err != nil {
		return nil, err
	}
	err = ap.Rollback(ctx, rec, by)
	return rec, err
}

// Verify re-runs exactly the checks behind the plan's findings and records
// a before/after table on the plan and in the latest report.
func (a *App) Verify(ctx context.Context, id, by string) (*model.PlanRecord, error) {
	rec, err := a.Store.Get(id)
	if err != nil {
		return nil, err
	}
	fs := a.planFindings(rec)
	r, err := a.LoadReport("latest")
	if err != nil {
		return nil, err
	}
	rows := verify.Rerun(ctx, rec, fs, a.Recheck)
	ap, err := a.Applier(ctx)
	if err != nil {
		return nil, err
	}
	if err := ap.RecordVerify(rec, by, rows); err != nil {
		return rec, err
	}
	byID := map[string]model.VerifyRow{}
	for _, row := range rows {
		byID[row.FindingID] = row
	}
	r.BeforeAfter = mergeRows(r.BeforeAfter, rows)
	for i := range r.Findings {
		if row, ok := byID[r.Findings[i].ID]; ok {
			r.Findings[i].Status = row.After
		}
	}
	_, err = a.SaveReport(r)
	return rec, err
}

func mergeRows(old, add []model.VerifyRow) []model.VerifyRow {
	idx := map[string]int{}
	for i, r := range old {
		idx[r.FindingID] = i
	}
	for _, r := range add {
		if i, ok := idx[r.FindingID]; ok {
			old[i] = r
			continue
		}
		old = append(old, r)
	}
	return old
}

// Recheck re-runs the single check behind a finding against live
// Flagsmith and returns EXPLOITABLE or BLOCKED with a redacted proof.
func (a *App) Recheck(ctx context.Context, f model.Finding) (model.Status, string, error) {
	env, err := a.Environment(ctx, nonEmpty(f.Environment, a.defaultEnv()))
	if err != nil {
		return model.StatusUnknown, "", err
	}
	fresh, err := a.Admin.Environment(ctx, env.APIKey)
	if err != nil {
		return model.StatusUnknown, "", err
	}
	sdk := flagsmith.NewSDK(a.HTTP, a.Cfg.Flagsmith.APIURL, env.APIKey)
	switch f.Type {
	case model.FSettingClientTraitsOn:
		return statusIf(fresh.AllowClientTraits, fmt.Sprintf("allow_client_traits=%v", fresh.AllowClientTraits))
	case model.FSettingSensitiveData, model.FIdentityTraitLeak, model.FIdentityOverrideLeak:
		return statusIf(!fresh.HideSensitiveData, fmt.Sprintf("hide_sensitive_data=%v", fresh.HideSensitiveData))
	case model.FSecretExposed, model.FInternalURL, model.FUnreleasedProduct, model.FPricingLeak, model.FPIILeak, model.FFlagNotServerOnly:
		flags, ev, err := sdk.EnvironmentFlags(ctx)
		if err != nil {
			return model.StatusUnknown, "", err
		}
		_, visible := flags[f.Subject]
		return statusIf(visible, fmt.Sprintf("%s → %s visible to client key: %v", ev.Request, f.Subject, visible))
	case model.FSegmentForgeable, model.FTraitForgery, model.FPercentageReroll, model.FVariantReroll, model.FExperimentRigging:
		if len(f.Unlocked) == 0 {
			return model.StatusUnknown, "", errors.New("finding has no flag change to re-check")
		}
		id := f.ProofID
		if id == "" {
			id = probeID()
		}
		res, err := sdk.Identify(ctx, id, f.Traits)
		if err != nil {
			return model.StatusUnknown, "", err
		}
		want := f.Unlocked[0]
		got := res.Flags[want.Flag].State()
		return statusIf(got == want.After, fmt.Sprintf("%s → %s is %s (exploited state %s)", res.Evidence.Request, want.Flag, got, want.After))
	default:
		return model.StatusUnknown, "", fmt.Errorf("no automatic re-check for %s", f.Type)
	}
}

func statusIf(exploitable bool, proof string) (model.Status, string, error) {
	if exploitable {
		return model.StatusExploitable, redact.String(proof), nil
	}
	return model.StatusBlocked, redact.String(proof), nil
}

func nonEmpty(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
