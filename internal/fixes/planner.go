// Package fixes turns findings into reviewable fix plans, binds human
// approvals to them, applies them through the Flagsmith Admin API (or CLI),
// and rolls them back (spec §8.9–§8.11). Every Flagsmith write happens in
// deterministic code, after approval, against a re-read of live state.
package fixes

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

// Operation kinds.
const (
	OpEnvPatch          = "env.patch"
	OpFeaturePatch      = "feature.patch"
	OpFeatureStatePatch = "featurestate.patch"
	OpPRDraft           = "pr.draft"
	OpManual            = "manual"
)

// Operation vias.
const (
	ViaAdminAPI = "admin-api"
	ViaCLI      = "flagsmith-cli"
)

// EnvRef identifies an environment the planner may plan for.
type EnvRef struct {
	Name string
	// Key is the environment's client API key, used in Admin API paths.
	Key        string
	Production bool
}

// DraftFunc writes the PR draft text for a finding. Gatecrasher's AI layer
// can supply one; the default is deterministic (see DefaultDraft). The
// output is redacted before it is stored.
type DraftFunc func(f model.Finding, impact []model.ImpactItem) string

// PlannerConfig configures a Planner.
type PlannerConfig struct {
	Admin        AdminAPI
	ProjectID    int
	Environments []EnvRef
	// RepoDir is the app repo scanned for client-side usage ("" skips impact).
	RepoDir string
	// Draft overrides the deterministic PR drafts.
	Draft DraftFunc
	// CLISupports marks operations the Flagsmith CLI will execute so their
	// plan shows Via "flagsmith-cli". Optional.
	CLISupports func(model.Operation) bool
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Planner builds fix plans from findings.
type Planner struct {
	cfg     PlannerConfig
	draft   DraftFunc
	usages  []Usage
	scanned bool
}

// NewPlanner returns a Planner.
func NewPlanner(cfg PlannerConfig) *Planner {
	p := &Planner{cfg: cfg, draft: cfg.Draft}
	if p.draft == nil {
		p.draft = DefaultDraft(cfg.RepoDir)
	}
	return p
}

type fixKind int

const (
	fixNone fixKind = iota
	fixClientTraits
	fixHideSensitive
	fixServerOnly
	fixReroll
)

func classify(t model.FindingType) fixKind {
	switch t {
	case model.FTraitForgery, model.FSettingClientTraitsOn, model.FSegmentForgeable:
		return fixClientTraits
	case model.FIdentityTraitLeak, model.FSettingSensitiveData, model.FIdentityOverrideLeak:
		return fixHideSensitive
	case model.FSecretExposed, model.FInternalURL, model.FPricingLeak, model.FPIILeak,
		model.FUnreleasedProduct, model.FFlagNotServerOnly:
		return fixServerOnly
	case model.FPercentageReroll, model.FVariantReroll, model.FExperimentRigging:
		return fixReroll
	}
	return fixNone
}

type group struct {
	env      EnvRef
	target   string
	findings []model.Finding
	// partial holds re-roll findings on the same flag that a Server-side
	// only plan hides but does not close.
	partial []model.Finding
}

// identifiersPrefix marks the target of a re-roll guidance plan. Re-rolling
// is fixed in the app (server-assigned identifiers), not on the feature, so
// it is never the same plan as a change to the feature.
const identifiersPrefix = "identifiers:"

// Plan returns one plan per (environment, target object) among the
// findings. Plans that fail to build are reported in the joined error while
// the others are still returned. Findings with nothing to fix, or whose fix
// is already in place, produce no plan.
//
// Re-roll and experiment-rigging findings always get their own guidance plan
// (PR draft: assign identifiers on the server). Marking a flag Server-side
// only hides it from client SDKs but does not stop re-rolling, so a
// Server-side only plan lists such a finding only as partially mitigated.
func (p *Planner) Plan(ctx context.Context, findings []model.Finding) ([]model.Plan, error) {
	groups, err := p.group(findings)
	var plans []model.Plan
	errs := []error{err}
	for _, g := range groups {
		var plan *model.Plan
		var berr error
		switch {
		case strings.HasPrefix(g.target, "environment:"):
			plan, berr = p.envPlan(ctx, g)
		case strings.HasPrefix(g.target, identifiersPrefix):
			plan = p.rerollPlan(g)
		default:
			plan, berr = p.featurePlan(ctx, g)
		}
		if berr != nil {
			errs = append(errs, fmt.Errorf("plan for %s on %s: %w", g.target, g.env.Name, berr))
			continue
		}
		if plan != nil {
			plans = append(plans, *plan)
		}
	}
	return plans, errors.Join(errs...)
}

func (p *Planner) group(findings []model.Finding) ([]*group, error) {
	byKey := map[string]*group{}
	var order []string
	var errs []error
	for _, f := range findings {
		kind := classify(f.Type)
		if kind == fixNone || f.Status == model.StatusBlocked {
			continue
		}
		env, err := p.env(f.Environment)
		if err != nil {
			errs = append(errs, fmt.Errorf("finding %s: %w", f.ID, err))
			continue
		}
		target := "feature:" + f.Subject
		switch kind {
		case fixClientTraits, fixHideSensitive:
			target = "environment:" + env.Name
		case fixReroll:
			target = identifiersPrefix + rerollFlag(f)
		}
		key := env.Name + "\x00" + target
		g := byKey[key]
		if g == nil {
			g = &group{env: env, target: target}
			byKey[key] = g
			order = append(order, key)
		}
		g.findings = append(g.findings, f)
	}
	for key, g := range byKey {
		if flag, ok := strings.CutPrefix(g.target, identifiersPrefix); ok {
			if fg := byKey[strings.TrimSuffix(key, g.target)+"feature:"+flag]; fg != nil {
				fg.partial = append(fg.partial, g.findings...)
			}
		}
	}
	sort.Strings(order)
	out := make([]*group, 0, len(order))
	for _, k := range order {
		out = append(out, byKey[k])
	}
	return out, errors.Join(errs...)
}

// rerollFlag is the flag a re-roll finding is about.
func rerollFlag(f model.Finding) string {
	if len(f.Unlocked) > 0 && f.Unlocked[0].Flag != "" {
		return f.Unlocked[0].Flag
	}
	return f.Subject
}

func (p *Planner) env(name string) (EnvRef, error) {
	if name == "" && len(p.cfg.Environments) > 0 {
		redact.Register(p.cfg.Environments[0].Key, "CLIENT_KEY")
		return p.cfg.Environments[0], nil
	}
	for _, e := range p.cfg.Environments {
		if strings.EqualFold(e.Name, name) {
			redact.Register(e.Key, "CLIENT_KEY")
			return e, nil
		}
	}
	return EnvRef{}, fmt.Errorf("unknown environment %q (not in the configured environments)", name)
}

func (p *Planner) now() time.Time {
	if p.cfg.Now != nil {
		return p.cfg.Now().UTC()
	}
	return time.Now().UTC()
}

func newPlanID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("crypto/rand unavailable: %v", err))
	}
	return "plan-" + hex.EncodeToString(b[:])
}

// finish stamps identity, findings and hash onto a plan under construction.
func (p *Planner) finish(g *group, plan model.Plan) *model.Plan {
	plan.ID = newPlanID()
	plan.CreatedAt = p.now()
	plan.Environment = g.env.Name
	plan.EnvironmentKey = g.env.Key
	plan.Production = g.env.Production
	plan.TargetObject = g.target
	plan.BeforeSnapshot = map[string]any{}
	for i := range plan.Operations {
		op := &plan.Operations[i]
		if p.cfg.CLISupports != nil && op.Automatic && p.cfg.CLISupports(*op) {
			op.Via = ViaCLI
		}
		for k, v := range op.Before {
			plan.BeforeSnapshot[k] = v
		}
	}
	seen := map[string]bool{}
	for _, f := range g.findings {
		if !seen[f.ID] {
			seen[f.ID] = true
			plan.FindingsAddressed = append(plan.FindingsAddressed, f.ID)
		}
	}
	sort.Strings(plan.FindingsAddressed)
	sort.Strings(plan.PartiallyMitigated)
	if plan.Impact == nil {
		plan.Impact = []model.ImpactItem{}
	}
	plan.Hash = plan.ComputeHash()
	return &plan
}

func (p *Planner) prDraft(f model.Finding, impact []model.ImpactItem, what string) model.Operation {
	return model.Operation{
		Kind:        OpPRDraft,
		Description: "Draft a pull request to " + what + " (review and open it yourself; Gatecrasher never pushes code).",
		Draft:       redact.String(p.draft(f, impact)),
	}
}

// envPlan builds the environment-settings plan.
func (p *Planner) envPlan(ctx context.Context, g *group) (*model.Plan, error) {
	live, err := liveObject(ctx, p.cfg.Admin, envPath(g.env.Key))
	if err != nil {
		return nil, err
	}
	var traitFinding *model.Finding
	hide := false
	for i, f := range g.findings {
		switch classify(f.Type) {
		case fixClientTraits:
			if traitFinding == nil {
				traitFinding = &g.findings[i]
			}
		case fixHideSensitive:
			hide = true
		}
	}
	plan := model.Plan{}
	var drafts []model.Operation
	if traitFinding != nil && !jsonEqual(live["allow_client_traits"], false) {
		plan.Operations = append(plan.Operations, settingOp(envPath(g.env.Key), "allow_client_traits", false, live,
			`Turn off "Allow client SDKs to set user traits" on `+g.env.Name))
		impact, draftOps := p.traitImpact(ctx, *traitFinding)
		plan.Impact = append(plan.Impact, impact...)
		drafts = append(drafts, draftOps...)
		plan.Title = "Disable client-set traits on " + g.env.Name
	}
	if hide && !jsonEqual(live["hide_sensitive_data"], true) {
		plan.Operations = append(plan.Operations, settingOp(envPath(g.env.Key), "hide_sensitive_data", true, live,
			`Turn on "Hide sensitive data" on `+g.env.Name))
		if plan.Title == "" {
			plan.Title = `Turn on "Hide sensitive data" on ` + g.env.Name
		} else {
			plan.Title += `, hide sensitive data`
		}
	}
	if len(plan.Operations) == 0 {
		return nil, nil
	}
	plan.Operations = append(plan.Operations, drafts...)
	return p.finish(g, plan), nil
}

func settingOp(path, field string, want any, live map[string]any, desc string) model.Operation {
	return model.Operation{
		Kind: OpEnvPatch, Description: desc, Method: "PATCH", Path: path,
		Body: map[string]any{field: want}, Before: map[string]any{field: live[field]},
		Automatic: true, Via: ViaAdminAPI,
	}
}

// traitImpact lists client-side trait writes the "client traits off" fix
// affects, plus the PR draft that moves them to the server.
func (p *Planner) traitImpact(ctx context.Context, f model.Finding) ([]model.ImpactItem, []model.Operation) {
	gating, known := p.gatingTraits(ctx)
	var items []model.ImpactItem
	for _, u := range p.scan() {
		if u.Kind != UsageTraitWrite {
			continue
		}
		hit := u.Names
		if known {
			hit = intersect(u.Names, gating)
		}
		item := model.ImpactItem{File: u.File, Line: u.Line, Snippet: u.Snippet}
		switch {
		case len(hit) > 0 || len(u.Names) == 0:
			item.Breaks = true
			item.Message = fmt.Sprintf("This will break: %s:%d sets %s client-side. Move it to your server (PR draft attached).",
				u.File, u.Line, traitList(hit))
		default:
			item.Message = fmt.Sprintf("%s:%d sets %s client-side; Flagsmith will ignore it after this change, and no segment uses it.",
				u.File, u.Line, traitList(u.Names))
		}
		items = append(items, item)
	}
	if len(items) == 0 {
		return nil, nil
	}
	return items, []model.Operation{p.prDraft(f, items, "move client-side trait writes to your server")}
}

func traitList(names []string) string {
	if len(names) == 0 {
		return "traits (names not statically known)"
	}
	return "`" + strings.Join(names, "`, `") + "`"
}

func intersect(a []string, set map[string]bool) []string {
	var out []string
	for _, n := range a {
		if set[n] {
			out = append(out, n)
		}
	}
	return out
}

// gatingTraits returns the trait names any project segment rule tests.
// known is false when segments could not be read.
func (p *Planner) gatingTraits(ctx context.Context) (map[string]bool, bool) {
	segs, err := getList[flagsmith.Segment](ctx, p.cfg.Admin, fmt.Sprintf("projects/%d/segments/?page_size=999", p.cfg.ProjectID))
	if err != nil {
		return nil, false
	}
	set := map[string]bool{}
	var walk func(rules []flagsmith.Rule)
	walk = func(rules []flagsmith.Rule) {
		for _, r := range rules {
			for _, c := range r.Conditions {
				if c.Property != "" {
					set[c.Property] = true
				}
			}
			walk(r.Rules)
		}
	}
	for _, s := range segs {
		walk(s.Rules)
	}
	return set, true
}

// scan returns (and caches) the client-side usage found in the repo.
func (p *Planner) scan() []Usage {
	if !p.scanned {
		p.scanned = true
		if p.cfg.RepoDir != "" {
			if us, err := ScanUsages(p.cfg.RepoDir); err == nil {
				p.usages = us
			}
		}
	}
	return p.usages
}

// featurePlan builds the plan for one flag.
func (p *Planner) featurePlan(ctx context.Context, g *group) (*model.Plan, error) {
	flag := strings.TrimPrefix(g.target, "feature:")
	feat, err := p.findFeature(ctx, flag)
	if err != nil {
		return nil, err
	}
	featPath := fmt.Sprintf("projects/%d/features/%d/", p.cfg.ProjectID, feat.ID)
	live, err := liveObject(ctx, p.cfg.Admin, featPath)
	if err != nil {
		return nil, err
	}
	plan := model.Plan{}
	needServerOnly := false
	for _, f := range g.findings {
		needServerOnly = needServerOnly || classify(f.Type) == fixServerOnly
	}
	auto := needServerOnly && !jsonEqual(live["is_server_key_only"], true)
	if auto {
		plan.Operations = append(plan.Operations, model.Operation{
			Kind: OpFeaturePatch, Method: "PATCH", Path: featPath, Automatic: true, Via: ViaAdminAPI,
			Description: fmt.Sprintf("Mark feature `%s` as Server-side only so client SDKs stop receiving it", flag),
			Body:        map[string]any{"is_server_key_only": true},
			Before:      map[string]any{"is_server_key_only": live["is_server_key_only"]},
		})
		plan.Impact = p.flagImpact(flag)
		plan.Title = fmt.Sprintf("Mark `%s` Server-side only on %s", flag, g.env.Name)
		if exp := runningExperiment(ctx, p.cfg.Admin, g.env.Key, feat.ID); exp != "" {
			plan.ExperimentWarning = fmt.Sprintf("Flag `%s` is under the running experiment %q; changing it contaminates experiment results. Gatecrasher will never stop the experiment: restart it after the fix.", flag, exp)
		}
		seen := map[string]bool{}
		for _, f := range g.partial {
			if !seen[f.ID] {
				seen[f.ID] = true
				plan.PartiallyMitigated = append(plan.PartiallyMitigated, f.ID)
			}
		}
	}
	plan.Operations = append(plan.Operations, p.guidanceOps(g, flag, plan.Impact)...)
	if len(plan.Operations) == 0 {
		return nil, nil
	}
	if plan.Title == "" {
		plan.Title = fmt.Sprintf("Guidance for `%s` on %s", flag, g.env.Name)
	}
	return p.finish(g, plan), nil
}

// rerollPlan builds the guidance-only plan for re-roll findings on one flag:
// a PR draft that assigns identifiers on the server, plus the manual steps.
// It never contains an automatic operation, because no Flagsmith setting
// stops a browser from choosing its own identifier.
func (p *Planner) rerollPlan(g *group) *model.Plan {
	flag := strings.TrimPrefix(g.target, identifiersPrefix)
	plan := model.Plan{Title: fmt.Sprintf("Assign identifiers on the server for `%s` on %s", flag, g.env.Name)}
	plan.Operations = append(plan.Operations,
		p.prDraft(g.findings[0], nil, prPurpose(g.findings[0].Type)),
		manual(fmt.Sprintf("Re-rolling `%s` closes only when identifiers are assigned on the server, or when the percentage rollout or variant split is removed. Marking the flag Server-side only hides it from client SDKs but does not stop re-rolling: a server that evaluates it for a browser-chosen identifier is still steered.", flag)))
	for _, f := range g.findings {
		if f.Type == model.FExperimentRigging {
			plan.Operations = append(plan.Operations, manual("After the fix is live, restart the experiment so its results are not biased by forged or re-rolled assignments. Gatecrasher never stops or restarts experiments itself."))
			break
		}
	}
	return p.finish(g, plan)
}

func (p *Planner) findFeature(ctx context.Context, name string) (flagsmith.Feature, error) {
	feats, err := getList[flagsmith.Feature](ctx, p.cfg.Admin, fmt.Sprintf("projects/%d/features/?page_size=999", p.cfg.ProjectID))
	if err != nil {
		return flagsmith.Feature{}, err
	}
	for _, f := range feats {
		if f.Name == name {
			return f, nil
		}
	}
	return flagsmith.Feature{}, fmt.Errorf("feature %q not found in project %d", name, p.cfg.ProjectID)
}

// flagImpact lists client code reading a flag that is about to become
// server-only.
func (p *Planner) flagImpact(flag string) []model.ImpactItem {
	var items []model.ImpactItem
	for _, u := range p.scan() {
		if u.Kind != UsageFlagRead || !contains(u.Names, flag) {
			continue
		}
		items = append(items, model.ImpactItem{
			File: u.File, Line: u.Line, Snippet: u.Snippet, Breaks: true,
			Message: fmt.Sprintf("This will break: %s:%d reads `%s` in client code. Server-side only flags are not sent to client SDKs; read it on your server (PR draft attached).",
				u.File, u.Line, flag),
		})
	}
	return items
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// guidanceOps returns the non-automatic operations for a flag plan.
func (p *Planner) guidanceOps(g *group, flag string, impact []model.ImpactItem) []model.Operation {
	var ops []model.Operation
	seen := map[model.FindingType]bool{}
	var draftFor *model.Finding
	for i, f := range g.findings {
		if seen[f.Type] {
			continue
		}
		seen[f.Type] = true
		switch f.Type {
		case model.FSecretExposed:
			ops = append(ops, manual(fmt.Sprintf("Rotate the secret exposed by `%s` at its issuer. Treat it as compromised: it was served to every browser. Gatecrasher cannot rotate secrets for you.", flag)))
			draftFor = firstNonNil(draftFor, &g.findings[i])
		case model.FInternalURL, model.FPricingLeak, model.FPIILeak:
			draftFor = firstNonNil(draftFor, &g.findings[i])
		case model.FUnreleasedProduct:
			ops = append(ops, manual(fmt.Sprintf("Consider renaming `%s` to a neutral name before release: flag names are visible to anyone holding the client key. Renaming is a code and Flagsmith change you make by hand.", flag)))
		}
	}
	if draftFor == nil && len(impact) > 0 {
		draftFor = &g.findings[0]
	}
	if draftFor != nil {
		ops = append([]model.Operation{p.prDraft(*draftFor, impact, prPurpose(draftFor.Type))}, ops...)
	}
	return ops
}

func firstNonNil(cur, f *model.Finding) *model.Finding {
	if cur != nil {
		return cur
	}
	return f
}

func prPurpose(t model.FindingType) string {
	switch t {
	case model.FPercentageReroll, model.FVariantReroll, model.FExperimentRigging:
		return "assign Flagsmith identifiers on the server"
	}
	return "move this value to server-side config and read the flag on your server"
}

func manual(desc string) model.Operation {
	return model.Operation{Kind: OpManual, Description: desc}
}
