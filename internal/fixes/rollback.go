package fixes

import (
	"context"
	"fmt"

	"github.com/yarrasatwik/gatecrasher/internal/audit"
	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

// Rollback restores the before-snapshot values of an applied plan, undoing
// its operations in reverse order. It is idempotent: fields that already hold
// their original value are left alone, and rolling back a plan that is
// already rolled back succeeds without writing anything. Every run is audited.
func (a *Applier) Rollback(ctx context.Context, rec *model.PlanRecord, by string) error {
	if by == "" {
		by = actorOf(rec)
	}
	if rec.State == model.PlanRolledBack {
		return a.record(by, audit.ActionRollback, rec.Plan.ID, map[string]any{"noop": true, "reason": "already rolled back"})
	}
	if rec.State != model.PlanApplied && rec.State != model.PlanVerified {
		return fmt.Errorf("plan %s is %s; only an applied plan can be rolled back (nothing was changed)", rec.Plan.ID, rec.State)
	}
	envKey, err := a.envKey(ctx, rec.Plan)
	if err != nil {
		return err
	}
	pending, restored, err := a.pendingRestores(ctx, rec.Plan)
	if err != nil {
		return err
	}
	if err := a.record(by, audit.ActionRollback, rec.Plan.ID, map[string]any{"phase": "begin", "to_restore": len(pending), "already_original": restored}); err != nil {
		return fmt.Errorf("not rolling back: %w", err)
	}
	if _, err := a.writeAll(ctx, rec, envKey, pending, func(s step) map[string]any { return s.op.Before }); err != nil {
		rec.Error = redact.String("rollback incomplete: " + err.Error())
		_ = a.save(rec)
		return err
	}
	_, werr := a.waitVisible(ctx, envKey, pending, func(s step) map[string]any { return s.op.Before })
	rec.State, rec.Error = model.PlanRolledBack, ""
	if werr != nil {
		rec.Error = redact.String(werr.Error())
	}
	if err := a.save(rec); err != nil {
		return err
	}
	if err := a.record(by, audit.ActionRollback, rec.Plan.ID, map[string]any{
		"phase": "done", "restored": len(pending), "already_original": restored, "visible": werr == nil,
	}); err != nil {
		return err
	}
	return werr
}

// pendingRestores returns the steps (in reverse plan order) whose live
// values differ from the snapshot, and how many were already original.
func (a *Applier) pendingRestores(ctx context.Context, p model.Plan) (pending []step, already int, err error) {
	steps := automaticSteps(p)
	for i := len(steps) - 1; i >= 0; i-- {
		s := steps[i]
		live, err := liveObject(ctx, a.cfg.Admin, s.op.Path)
		if err != nil {
			return nil, 0, err
		}
		if id, ok := live["feature"].(float64); ok && s.op.Kind == OpFeatureStatePatch {
			s.featureID = int(id)
		}
		if fieldsEqual(live, s.op.Before) {
			already++
			continue
		}
		pending = append(pending, s)
	}
	return pending, already, nil
}
