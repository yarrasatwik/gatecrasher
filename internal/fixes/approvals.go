package fixes

import (
	"fmt"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

// ContaminateToken is what a human must type to accept that changing a flag
// under a running experiment contaminates its results.
const ContaminateToken = "contaminate-experiment"

// DefaultApprovalTTL is how long an approval stays valid (spec §8.10).
const DefaultApprovalTTL = 30 * time.Minute

// Approve records a human approval on rec, bound to the plan's hash.
//
// Production plans require typedEnv to equal the environment name exactly.
// Plans with an experiment warning require typedContaminate to equal
// ContaminateToken. An approval covers exactly this plan and expires after
// ttl (DefaultApprovalTTL when ttl <= 0).
func Approve(rec *model.PlanRecord, by, channel, typedEnv, typedContaminate string, ttl time.Duration) error {
	return approveAt(time.Now(), rec, by, channel, typedEnv, typedContaminate, ttl)
}

func approveAt(now time.Time, rec *model.PlanRecord, by, channel, typedEnv, typedContaminate string, ttl time.Duration) error {
	if err := checkApprovable(now, rec); err != nil {
		return err
	}
	p := rec.Plan
	if p.Hash != p.ComputeHash() {
		return ErrPlanTampered
	}
	if by == "" {
		return fmt.Errorf("approval needs the name of the person approving")
	}
	if channel != "cli" && channel != "web" {
		return fmt.Errorf("approval channel must be \"cli\" or \"web\", got %q", channel)
	}
	if p.Production && typedEnv != p.Environment {
		return fmt.Errorf("%w (expected %q, got %q)", ErrConfirmEnvironment, p.Environment, typedEnv)
	}
	if p.ExperimentWarning != "" && typedContaminate != ContaminateToken {
		return fmt.Errorf("%w. %s", ErrConfirmContaminate, p.ExperimentWarning)
	}
	if ttl <= 0 {
		ttl = DefaultApprovalTTL
	}
	rec.Approval = &model.Approval{
		PlanID: p.ID, PlanHash: p.Hash, ApprovedAt: now.UTC(), ExpiresAt: now.UTC().Add(ttl),
		By: by, Channel: channel,
	}
	if p.Production {
		rec.Approval.ConfirmedEnvironment = typedEnv
	}
	rec.Approval.ContaminateConfirmed = p.ExperimentWarning != ""
	rec.State = model.PlanApproved
	rec.Error = ""
	return nil
}

func checkApprovable(now time.Time, rec *model.PlanRecord) error {
	switch rec.State {
	case model.PlanPending:
		return nil
	case model.PlanApproved:
		if rec.Approval == nil || now.After(rec.Approval.ExpiresAt) {
			return nil // the previous approval lapsed; a fresh one replaces it
		}
		return fmt.Errorf("plan %s is already approved (until %s)", rec.Plan.ID, rec.Approval.ExpiresAt.Format(time.RFC3339))
	default:
		return fmt.Errorf("plan %s is %s and cannot be approved; re-plan if the change is still needed", rec.Plan.ID, rec.State)
	}
}

// Reject marks a pending or approved plan as rejected and drops any approval.
func Reject(rec *model.PlanRecord, by, reason string) error {
	if rec.State != model.PlanPending && rec.State != model.PlanApproved {
		return fmt.Errorf("plan %s is %s and cannot be rejected", rec.Plan.ID, rec.State)
	}
	if by == "" {
		return fmt.Errorf("rejection needs the name of the person rejecting")
	}
	rec.Approval = nil
	rec.State = model.PlanRejected
	rec.Error = "rejected by " + by
	if reason != "" {
		rec.Error += ": " + reason
	}
	return nil
}

// checkApproval validates an approval for execution: it must exist, match
// this exact plan hash, be unexpired and carry the typed confirmations.
func checkApproval(now time.Time, rec *model.PlanRecord) error {
	a := rec.Approval
	if a == nil || rec.State != model.PlanApproved {
		if rec.State == model.PlanApproved || rec.State == model.PlanPending {
			return ErrNotApproved
		}
		return fmt.Errorf("plan %s is %s, not approved; it cannot be applied", rec.Plan.ID, rec.State)
	}
	p := rec.Plan
	if p.Hash != p.ComputeHash() || a.PlanHash != p.Hash || a.PlanID != p.ID {
		return ErrPlanTampered
	}
	if now.After(a.ExpiresAt) {
		return ErrApprovalExpired
	}
	if p.Production && a.ConfirmedEnvironment != p.Environment {
		return ErrConfirmEnvironment
	}
	if p.ExperimentWarning != "" && !a.ContaminateConfirmed {
		return ErrConfirmContaminate
	}
	return nil
}
