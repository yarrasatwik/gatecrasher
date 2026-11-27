package fixes

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/audit"
	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

// Config configures an Applier.
type Config struct {
	Admin AdminAPI
	// Store, when set, receives every state change of a plan record.
	Store *Store
	// Audit, when set, records every step. A failed audit write before a
	// change aborts the change.
	Audit     *audit.Log
	ProjectID int
	// EnvKeys maps environment name to client key. Needed because
	// Plan.EnvironmentKey is not persisted; unknown names are looked up
	// through the Admin API.
	EnvKeys map[string]string
	// UseCLI prefers the Flagsmith CLI when CLI supports the operation.
	UseCLI bool
	CLI    cliBridge
	// Timeout bounds the wait for propagation (default 150s).
	Timeout time.Duration
	// PollInterval is the propagation poll period (default 2s).
	PollInterval time.Duration
	// Now overrides the clock used for approval expiry (tests).
	Now func() time.Time
}

// Applier executes approved plans and rolls them back.
type Applier struct{ cfg Config }

// NewApplier returns an Applier with defaults filled in.
func NewApplier(cfg Config) *Applier {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 150 * time.Second
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 2 * time.Second
	}
	return &Applier{cfg: cfg}
}

func (a *Applier) now() time.Time {
	if a.cfg.Now != nil {
		return a.cfg.Now()
	}
	return time.Now()
}

// step is one automatic operation with the facts resolved from live state.
type step struct {
	op        model.Operation
	featureID int
}

var featurePathRe = regexp.MustCompile(`features/(\d+)/?$`)

// Apply executes an approved plan.
//
// It refuses unless the approval is valid, unexpired and bound to this exact
// plan hash; it re-reads live state and refuses with ErrStalePlan if any
// field the plan changes differs from the plan's snapshot. It then runs the
// automatic operations in order, waits until the change is visible in the
// environment document, records the propagation time, and audits each step.
func (a *Applier) Apply(ctx context.Context, rec *model.PlanRecord) error {
	if err := checkApproval(a.now(), rec); err != nil {
		return a.refuse(rec, err)
	}
	steps := automaticSteps(rec.Plan)
	if len(steps) == 0 {
		return a.refuse(rec, ErrNothingToApply)
	}
	envKey, err := a.envKey(ctx, rec.Plan)
	if err != nil {
		return err
	}
	if err := a.checkFresh(ctx, steps); err != nil {
		if errors.Is(err, ErrStalePlan) {
			rec.State, rec.Error = model.PlanStale, redact.String(err.Error())
			_ = a.save(rec)
		}
		return a.refuse(rec, err)
	}
	if err := a.checkExperiment(ctx, rec, envKey, steps); err != nil {
		return a.refuse(rec, err)
	}
	by := rec.Approval.By
	if err := a.record(by, audit.ActionApply, rec.Plan.ID, map[string]any{"phase": "begin", "operations": len(steps), "hash": rec.Plan.Hash}); err != nil {
		return fmt.Errorf("not applying: %w", err)
	}
	done, err := a.writeAll(ctx, rec, envKey, steps, func(s step) map[string]any { return s.op.Body })
	if err != nil {
		if done > 0 {
			applied := a.now().UTC()
			rec.State, rec.AppliedAt = model.PlanApplied, &applied
		}
		rec.Error = fmt.Sprintf("applied %d of %d operations: %s. Review the environment and run rollback if needed.", done, len(steps), redact.String(err.Error()))
		_ = a.save(rec)
		return err
	}
	applied := a.now().UTC()
	rec.State, rec.AppliedAt, rec.Error = model.PlanApplied, &applied, ""
	took, werr := a.waitVisible(ctx, envKey, steps, func(s step) map[string]any { return s.op.Body })
	rec.TookMS = took.Milliseconds()
	if werr != nil {
		rec.Error = redact.String(werr.Error())
	}
	if err := a.save(rec); err != nil {
		return err
	}
	if err := a.record(by, audit.ActionApply, rec.Plan.ID, map[string]any{
		"phase": "done", "propagation_ms": rec.TookMS, "visible": werr == nil,
	}); err != nil {
		return err
	}
	return werr
}

// RecordVerify stores the re-attack rows on the record, marks it verified
// when every row ended BLOCKED, and audits the outcome.
func (a *Applier) RecordVerify(rec *model.PlanRecord, by string, rows []model.VerifyRow) error {
	rec.Verify = rows
	blocked := 0
	for _, r := range rows {
		if r.After == model.StatusBlocked {
			blocked++
		}
	}
	if len(rows) > 0 && blocked == len(rows) {
		rec.State = model.PlanVerified
	}
	if err := a.save(rec); err != nil {
		return err
	}
	return a.record(by, audit.ActionVerify, rec.Plan.ID, map[string]any{"findings": len(rows), "blocked": blocked})
}

func automaticSteps(p model.Plan) []step {
	var out []step
	for _, op := range p.Operations {
		if !op.Automatic {
			continue
		}
		s := step{op: op}
		if m := featurePathRe.FindStringSubmatch(op.Path); m != nil && op.Kind == OpFeaturePatch {
			s.featureID, _ = strconv.Atoi(m[1])
		}
		out = append(out, s)
	}
	return out
}

// checkFresh re-reads every object the plan touches and compares the fields
// it changes with the plan's snapshot.
func (a *Applier) checkFresh(ctx context.Context, steps []step) error {
	for i := range steps {
		s := &steps[i]
		live, err := liveObject(ctx, a.cfg.Admin, s.op.Path)
		if err != nil {
			return err
		}
		if id, ok := live["feature"].(float64); ok && s.op.Kind == OpFeatureStatePatch {
			s.featureID = int(id)
		}
		for _, k := range sortedKeys(s.op.Before) {
			if !jsonEqual(live[k], s.op.Before[k]) {
				return fmt.Errorf("%w: %s on %s is %s now but was %s when the plan was made",
					ErrStalePlan, k, s.op.Path, show(live[k]), show(s.op.Before[k]))
			}
		}
	}
	return nil
}

func show(v any) string { return redact.String(fmt.Sprint(v)) }

// checkExperiment refuses a feature change that now sits under a running
// experiment unless the approval carries the typed confirmation.
func (a *Applier) checkExperiment(ctx context.Context, rec *model.PlanRecord, envKey string, steps []step) error {
	if rec.Approval.ContaminateConfirmed {
		return nil
	}
	for _, s := range steps {
		if s.op.Kind != OpFeaturePatch {
			continue
		}
		if exp := runningExperiment(ctx, a.cfg.Admin, envKey, s.featureID); exp != "" {
			return fmt.Errorf("%w (experiment %q started after the plan was made)", ErrConfirmContaminate, exp)
		}
	}
	return nil
}

// writeAll executes the steps in order and returns how many succeeded.
func (a *Applier) writeAll(ctx context.Context, rec *model.PlanRecord, envKey string, steps []step, bodyOf func(step) map[string]any) (int, error) {
	by := actorOf(rec)
	for i, s := range steps {
		via, note, err := a.execute(ctx, envKey, s, bodyOf(s))
		details := map[string]any{"phase": "step", "step": i + 1, "kind": s.op.Kind, "path": s.op.Path, "via": via, "fields": bodyOf(s)}
		if note != "" {
			details["note"] = note
		}
		if err != nil {
			details["error"] = err.Error()
			_ = a.record(by, audit.ActionApply, rec.Plan.ID, details)
			return i, fmt.Errorf("step %d (%s): %w", i+1, s.op.Description, err)
		}
		if err := a.record(by, audit.ActionApply, rec.Plan.ID, details); err != nil {
			return i + 1, err
		}
	}
	return len(steps), nil
}

func actorOf(rec *model.PlanRecord) string {
	if rec.Approval != nil && rec.Approval.By != "" {
		return rec.Approval.By
	}
	return "gatecrasher"
}

// execute performs one write, preferring the Flagsmith CLI when allowed and
// supported, and falling back to the Admin API if the CLI fails.
func (a *Applier) execute(ctx context.Context, envKey string, s step, body map[string]any) (via, note string, err error) {
	if s.op.Kind == OpFeatureStatePatch {
		return ViaAdminAPI, "", a.patchFeatureState(ctx, envKey, s, body)
	}
	if a.cfg.UseCLI && a.cfg.CLI != nil && a.cfg.CLI.Supports(s.op) {
		cliErr := a.cfg.CLI.Run(ctx, s.op, body)
		if cliErr == nil {
			return ViaCLI, "", nil
		}
		note = "flagsmith CLI failed, used the Admin API instead: " + cliErr.Error()
	}
	method := s.op.Method
	if method == "" {
		method = "PATCH"
	}
	return ViaAdminAPI, note, a.cfg.Admin.Do(ctx, method, s.op.Path, body, nil)
}

// patchFeatureState changes an environment feature state. With v2 feature
// versioning it creates a new version, patches the version's environment
// default state, then publishes the version.
func (a *Applier) patchFeatureState(ctx context.Context, envKey string, s step, body map[string]any) error {
	env, err := liveObject(ctx, a.cfg.Admin, envPath(envKey))
	if err != nil {
		return err
	}
	if v2, _ := env["use_v2_feature_versioning"].(bool); !v2 {
		return a.cfg.Admin.Do(ctx, "PATCH", s.op.Path, body, nil)
	}
	base := fmt.Sprintf("%sfeatures/%d/versions/", envPath(envKey), s.featureID)
	var ver struct {
		UUID string `json:"uuid"`
	}
	if err := a.cfg.Admin.Do(ctx, "POST", base, map[string]any{}, &ver); err != nil {
		return fmt.Errorf("create feature version: %w", err)
	}
	if ver.UUID == "" {
		return errors.New("create feature version: response had no uuid")
	}
	vpath := base + ver.UUID + "/"
	states, err := getList[flagsmith.FeatureState](ctx, a.cfg.Admin, vpath+"featurestates/")
	if err != nil {
		return fmt.Errorf("list version feature states: %w", err)
	}
	for _, st := range states {
		if st.FeatureSegment == nil && st.Identity == nil {
			if err := a.cfg.Admin.Do(ctx, "PATCH", fmt.Sprintf("%sfeaturestates/%d/", vpath, st.ID), body, nil); err != nil {
				return fmt.Errorf("patch version feature state: %w", err)
			}
			if err := a.cfg.Admin.Do(ctx, "POST", vpath+"publish/", map[string]any{}, nil); err != nil {
				return fmt.Errorf("publish feature version: %w", err)
			}
			return nil
		}
	}
	return errors.New("the new feature version has no environment-default feature state")
}

// waitVisible polls the environment document until every changed field is
// visible, or the timeout passes. It returns the elapsed time either way.
func (a *Applier) waitVisible(ctx context.Context, envKey string, steps []step, bodyOf func(step) map[string]any) (time.Duration, error) {
	start := time.Now()
	deadline := start.Add(a.cfg.Timeout)
	for {
		ok, err := a.allVisible(ctx, envKey, steps, bodyOf)
		if err != nil {
			return time.Since(start), err
		}
		if ok {
			return time.Since(start), nil
		}
		if time.Now().Add(a.cfg.PollInterval).After(deadline) {
			return time.Since(start), fmt.Errorf("the change was applied but is not visible in the environment document after %s; check Flagsmith, then verify or roll back", a.cfg.Timeout)
		}
		select {
		case <-ctx.Done():
			return time.Since(start), ctx.Err()
		case <-time.After(a.cfg.PollInterval):
		}
	}
}

func (a *Applier) allVisible(ctx context.Context, envKey string, steps []step, bodyOf func(step) map[string]any) (bool, error) {
	var doc map[string]any
	if err := a.cfg.Admin.Do(ctx, "GET", envPath(envKey)+"document/", nil, &doc); err != nil {
		return false, fmt.Errorf("read environment document: %w", err)
	}
	for _, s := range steps {
		ok, err := a.visible(ctx, doc, s, bodyOf(s))
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

// visible reports whether the document reflects the want fields of s.
func (a *Applier) visible(ctx context.Context, doc map[string]any, s step, want map[string]any) (bool, error) {
	switch s.op.Kind {
	case OpEnvPatch:
		return fieldsEqual(doc, want), nil
	case OpFeaturePatch:
		if obj := docFeature(doc, s.featureID); obj != nil && hasAll(obj, want) {
			return fieldsEqual(obj, want), nil
		}
		live, err := liveObject(ctx, a.cfg.Admin, s.op.Path)
		if err != nil {
			return false, err
		}
		return fieldsEqual(live, want), nil
	case OpFeatureStatePatch:
		for _, fs := range docFeatureStates(doc) {
			if f, _ := fs["feature"].(map[string]any); f != nil && jsonEqual(f["id"], float64(s.featureID)) {
				return fieldsEqual(fs, want), nil
			}
		}
		return false, nil
	}
	return true, nil
}

func fieldsEqual(have, want map[string]any) bool {
	for k, v := range want {
		if !jsonEqual(have[k], v) {
			return false
		}
	}
	return true
}

func hasAll(m, want map[string]any) bool {
	for k := range want {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}

func docFeatureStates(doc map[string]any) []map[string]any {
	raw, _ := doc["feature_states"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		if m, ok := r.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// docFeature returns the feature object of the document's feature state for
// the given feature id, or nil.
func docFeature(doc map[string]any, id int) map[string]any {
	for _, fs := range docFeatureStates(doc) {
		if f, _ := fs["feature"].(map[string]any); f != nil && jsonEqual(f["id"], float64(id)) {
			return f
		}
	}
	return nil
}

// runningExperiment returns the name of a running experiment on the feature
// ("" when none, or when the experiments API is unavailable).
func runningExperiment(ctx context.Context, admin AdminAPI, envKey string, featureID int) string {
	exps, err := getList[flagsmith.Experiment](ctx, admin, envPath(envKey)+"experiments/")
	if err != nil {
		return ""
	}
	for _, e := range exps {
		if e.Running() && e.FeatureID() == featureID {
			return e.Name
		}
	}
	return ""
}

// envKey resolves the environment's client key: the plan's own key (set at
// planning time, not persisted), the configured map, or an Admin lookup.
func (a *Applier) envKey(ctx context.Context, p model.Plan) (string, error) {
	key, err := a.lookupEnvKey(ctx, p)
	if err == nil {
		redact.Register(key, "CLIENT_KEY")
	}
	return key, err
}

func (a *Applier) lookupEnvKey(ctx context.Context, p model.Plan) (string, error) {
	if p.EnvironmentKey != "" {
		return p.EnvironmentKey, nil
	}
	if k := a.cfg.EnvKeys[p.Environment]; k != "" {
		return k, nil
	}
	envs, err := getList[flagsmith.Environment](ctx, a.cfg.Admin, fmt.Sprintf("environments/?project=%d", a.cfg.ProjectID))
	if err != nil {
		return "", fmt.Errorf("look up environment %q: %w", p.Environment, err)
	}
	for _, e := range envs {
		if strings.EqualFold(e.Name, p.Environment) {
			return e.APIKey, nil
		}
	}
	return "", fmt.Errorf("environment %q not found in project %d", p.Environment, a.cfg.ProjectID)
}

// refuse audits a refusal and returns the cause (joined with any audit
// failure).
func (a *Applier) refuse(rec *model.PlanRecord, cause error) error {
	aerr := a.record(actorOf(rec), audit.ActionRefuse, rec.Plan.ID, map[string]any{"stage": "apply", "reason": cause.Error(), "state": string(rec.State)})
	return errors.Join(cause, aerr)
}

func (a *Applier) record(actor string, action audit.Action, planID string, details map[string]any) error {
	if a.cfg.Audit == nil {
		return nil
	}
	_, err := a.cfg.Audit.Append(actor, action, planID, details)
	return err
}

func (a *Applier) save(rec *model.PlanRecord) error {
	if a.cfg.Store == nil {
		return nil
	}
	return a.cfg.Store.Save(rec)
}
