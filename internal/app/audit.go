package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/ai"
	"github.com/yarrasatwik/gatecrasher/internal/attacks"
	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
	"github.com/yarrasatwik/gatecrasher/internal/mapper"
	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/parity"
	"github.com/yarrasatwik/gatecrasher/internal/recon"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
	"github.com/yarrasatwik/gatecrasher/internal/report"
	"github.com/yarrasatwik/gatecrasher/internal/secrets"
	"github.com/yarrasatwik/gatecrasher/internal/severity"
)

// Progress receives stage updates ("recon", "classify", "map", ...).
type Progress func(stage, msg string)

// AuditOptions selects what an audit run does.
type AuditOptions struct {
	// Target overrides cfg.TargetURL; empty with Outside=false skips recon.
	Target string
	// Environment is the environment mapped from the inside.
	Environment string
	// Outside runs recon + classification against the target site.
	Outside bool
	// Inside runs the settings audit and the engine map (needs an org key).
	Inside bool
	// ParitySamples cross-checks N random identities engine vs live (0 = skip).
	ParitySamples int
	// Explain asks the AI (or templates) for plain-English explanations.
	Explain bool
	// Fast skips AI calls (deterministic classification only); watch-mode
	// re-checks use it so an alert never waits on a model round-trip.
	Fast bool
	// Progress receives stage updates; may be nil.
	Progress Progress
}

// Audit runs the configured stages and returns the finalized report. It
// never writes to Flagsmith.
func (a *App) Audit(ctx context.Context, o AuditOptions) (*model.Report, error) {
	start := time.Now()
	say := o.Progress
	if say == nil {
		say = func(string, string) {}
	}
	if o.Target == "" {
		o.Target = a.Cfg.TargetURL
	}
	if o.Environment == "" {
		o.Environment = a.defaultEnv()
	}
	sentBefore := a.HTTP.Sent()
	r := &model.Report{
		SchemaVersion: model.SchemaVersion, ID: newReportID(), Tool: report.ToolName, Version: Version,
		CreatedAt: time.Now().UTC(), Target: o.Target, Project: a.Cfg.Flagsmith.Project,
		Environment: o.Environment, AIMode: string(a.AI.Mode()), Scope: a.Cfg.Lock().Entries(),
		Stats: model.Stats{StageMS: map[string]int64{}},
	}
	stage := func(name string, fn func() error) error {
		t := time.Now()
		err := fn()
		r.Stats.StageMS[name] = time.Since(t).Milliseconds()
		return err
	}
	cls := map[string]model.Category{}
	if o.Outside && o.Target != "" {
		if err := stage("recon", func() error { return a.outside(ctx, r, o.Target, cls, say) }); err != nil {
			return nil, err
		}
	}
	if o.Inside {
		if a.Admin == nil {
			r.Notes = append(r.Notes, "Inside view skipped: no organisation API key (GATECRASHER_ORG_API_KEY).")
		} else if err := stage("map", func() error { return a.inside(ctx, r, o, cls, say) }); err != nil {
			return nil, err
		}
	}
	say("severity", "applying deterministic severity rules")
	for i := range r.Findings {
		if r.Findings[i].Environment == "" {
			r.Findings[i].Environment = o.Environment
		}
	}
	dedupe(r)
	a.consolidate(r)
	severity.AssignAll(r.Findings)
	severity.Sort(r.Findings)
	if o.Explain {
		_ = stage("explain", func() error {
			say("explain", fmt.Sprintf("explaining %d findings · AI %s", len(r.Findings), a.AI.Mode()))
			sem := make(chan struct{}, 4)
			var wg sync.WaitGroup
			for i := range r.Findings {
				wg.Add(1)
				sem <- struct{}{}
				go func(i int) {
					defer func() { <-sem; wg.Done() }()
					r.Findings[i].Explanation = a.AI.Explain(ctx, r.Findings[i])
				}(i)
			}
			wg.Wait()
			return nil
		})
	}
	r.Stats.ProbesSent = a.HTTP.Sent() - sentBefore
	r.Stats.DurationMS = time.Since(start).Milliseconds()
	report.Finalize(r)
	say("done", fmt.Sprintf("%d ways in", report.WaysIn(r)))
	return r, nil
}

func (a *App) defaultEnv() string {
	for _, e := range a.Cfg.Flagsmith.Environments {
		if a.Cfg.IsProduction(e) {
			return e
		}
	}
	if len(a.Cfg.Flagsmith.Environments) > 0 {
		return a.Cfg.Flagsmith.Environments[0]
	}
	return "Production"
}

// outside runs recon and classification: what any visitor can see.
func (a *App) outside(ctx context.Context, r *model.Report, target string, cls map[string]model.Category, say Progress) error {
	say("recon", "fetching "+redact.String(target)+" and its scripts")
	res, err := recon.Run(ctx, a.HTTP, recon.ReconConfig{TargetURL: target, APIURL: a.Cfg.Flagsmith.APIURL})
	if err != nil {
		return fmt.Errorf("recon: %w", err)
	}
	r.Inventory = res.Inventory
	r.Notes = append(r.Notes, res.Notes...)
	for _, l := range res.Leaks {
		r.Findings = append(r.Findings, model.Finding{
			ID: model.MakeFindingID(model.FSecretExposed, "", "bundle-server-key", fmt.Sprint(l)), Type: model.FSecretExposed,
			Severity: model.SevCritical, Title: "Server-side Flagsmith key shipped in the JavaScript bundle",
			Subject: "bundle", Category: model.CatSecret, DetectedBy: []model.Method{model.MethodDeterministic},
			Confirmed: true, Status: model.StatusExploitable,
			Evidence: []model.Evidence{{Kind: "bundle", Note: redact.String(fmt.Sprint(l))}},
		})
	}
	say("recon", fmt.Sprintf("client key found at %s; %d flags visible", strings.Join(res.Inventory.KeySources, ", "), len(res.Inventory.Flags)))
	say("classify", "classifying flag names and values · AI "+string(a.AI.Mode()))
	classes, mode := a.AI.Classify(ctx, res.Inventory)
	r.AIMode = string(mode)
	r.Classifications = classes
	for _, c := range classes {
		cls[c.Flag] = c.Category
		if ai.Reportable(c) {
			r.Findings = append(r.Findings, configLeak(c, res.Inventory, r.Environment))
		}
	}
	if a.AI.Mode().On() {
		agree := 0
		for i, f := range res.Inventory.Flags {
			if i < len(classes) && secrets.Classify(f).Category == classes[i].Category {
				agree++
			}
		}
		if n := len(res.Inventory.Flags); n > 0 {
			v := float64(agree) / float64(n)
			r.Stats.AIHeuristicAgree = &v
		}
	}
	return a.outsideAttacks(ctx, r, cls, say)
}

// outsideAttacks consumes the classified public inventory using only the SDK.
func (a *App) outsideAttacks(ctx context.Context, r *model.Report, cls map[string]model.Category, say Progress) error {
	inv := r.Inventory
	sdk := flagsmith.NewSDK(a.HTTP, inv.APIURL, inv.Key)
	base, err := sdk.Identify(ctx, probeID(), nil)
	if err != nil {
		return fmt.Errorf("attack baseline: %w", err)
	}
	names := make([]string, 0, len(inv.Flags))
	for _, f := range inv.Flags {
		names = append(names, f.Name)
	}
	u, _ := url.Parse(inv.TargetURL)
	hs, mode := a.AI.Hypothesize(ctx, names, inv.TraitKeys, u.Hostname())
	if !mode.On() {
		r.AIMode = string(mode)
	}
	say("attack", fmt.Sprintf("testing %d trait hypotheses and configured test identities", len(hs)))
	clientIDs := a.Cfg.ClientSetsIdentifier == nil || *a.Cfg.ClientSetsIdentifier
	runner := attacks.New(sdk, attacks.Options{Environment: r.Environment, TestIdentities: a.Cfg.TestIdentities,
		MaxHypotheses: a.Cfg.Probes.MaxHypotheses, MaxCombos: a.Cfg.Probes.MaxCombos,
		RerollSamples: a.Cfg.Probes.RerollSamples, ClientSetsIdentifier: clientIDs})
	findings, err := runner.Run(ctx, base.Flags, hs)
	for i := range findings {
		if c, ok := cls[findings[i].Subject]; ok {
			findings[i].Category = c
		}
	}
	r.Findings = append(r.Findings, findings...)
	if err != nil {
		return fmt.Errorf("outside attacks: %w", err)
	}
	return nil
}

var leakTypes = map[model.Category]model.FindingType{
	model.CatSecret:            model.FSecretExposed,
	model.CatInternalURL:       model.FInternalURL,
	model.CatUnreleasedProduct: model.FUnreleasedProduct,
	model.CatPricing:           model.FPricingLeak,
	model.CatPII:               model.FPIILeak,
	model.CatPossibleSecret:    model.FPossibleSecret,
}

var leakTitles = map[model.FindingType]string{
	model.FSecretExposed:     "Secret in a client-visible flag value: %s",
	model.FInternalURL:       "Internal URL leaked to every browser: %s",
	model.FUnreleasedProduct: "Unreleased product leaked through flag: %s",
	model.FPricingLeak:       "Pricing data visible to every browser: %s",
	model.FPIILeak:           "Personal data in a client-visible flag: %s",
	model.FPossibleSecret:    "Possible secret in a client-visible flag (needs review): %s",
}

// configLeak turns a sensitive classification of a public flag into a finding.
func configLeak(c model.Classification, inv *model.PublicInventory, env string) model.Finding {
	t := leakTypes[c.Category]
	var view model.FlagView
	for _, f := range inv.Flags {
		if f.Name == c.Flag {
			view = f
		}
	}
	u := strings.TrimRight(inv.APIURL, "/") + "/flags/"
	return model.Finding{
		ID: model.MakeFindingID(t, env, c.Flag), Type: t, Title: fmt.Sprintf(leakTitles[t], c.Flag),
		Environment: env, Subject: c.Flag, Category: c.Category,
		DetectedBy: []model.Method{c.Method}, Confirmed: true, Status: model.StatusExploitable,
		Repro: flagsmith.Repro("GET", u, nil),
		Evidence: []model.Evidence{{Kind: "request", Request: flagsmith.Repro("GET", u, nil),
			Response: redact.String(fmt.Sprintf("%s = %s (%d bytes)", view.Name, view.Preview, view.Size)),
			Note:     redact.String(c.Rationale)}},
	}
}

// inside runs the read-only inside map: settings, segments, the official
// engine over the environment document, live cross-checks and parity.
func (a *App) inside(ctx context.Context, r *model.Report, o AuditOptions, cls map[string]model.Category, say Progress) error {
	proj, envMap, err := a.Project(ctx)
	if err != nil {
		return fmt.Errorf("inside view: %w", err)
	}
	env, err := a.Environment(ctx, o.Environment)
	if err != nil {
		return err
	}
	say("map", fmt.Sprintf("reading settings, features and segments of %s / %s", proj.Name, env.Name))
	features, err := a.Admin.Features(ctx, proj.ID)
	if err != nil {
		return fmt.Errorf("features: %w", err)
	}
	segs, err := a.Admin.Segments(ctx, proj.ID)
	if err != nil {
		return fmt.Errorf("segments: %w", err)
	}
	// Settings are security-relevant and change at runtime: always read them
	// fresh instead of trusting the cached environment list.
	fresh, err := a.Admin.Environment(ctx, env.APIKey)
	if err != nil {
		return fmt.Errorf("environment settings: %w", err)
	}
	env = *fresh
	_ = envMap
	envs := []flagsmith.Environment{env}
	if len(cls) == 0 {
		a.classifyFromAdmin(ctx, env, cls, o.Fast)
	}
	settings, setFindings := mapper.SettingsAudit(envs, features, cls)
	r.Settings = settings
	r.Findings = append(r.Findings, setFindings...)

	say("map", "loading the environment document into Flagsmith's evaluation engine")
	doc, err := a.envDocument(ctx, env)
	if err != nil {
		return fmt.Errorf("environment document: %w", err)
	}
	eng, err := flagsmith.NewEngine(doc)
	if err != nil {
		return err
	}
	opts := mapper.Options{Environment: env.Name, ServerOnlyTraits: a.Cfg.ServerOnlyTraits,
		ClientSetsIdentifier: *a.Cfg.ClientSetsIdentifier, Classifications: cls}
	reach := mapper.Map(eng, segs, features, settings, opts)
	say("map", fmt.Sprintf("engine found %d reachable flag states", len(reach)))

	running, expKnown := a.runningExperiments(ctx, env, features)
	if !expKnown {
		r.Notes = append(r.Notes, "Experiment status unknown: the Experimentation API could not be read in this environment.")
	}
	sdk := flagsmith.NewSDK(a.HTTP, a.Cfg.Flagsmith.APIURL, env.APIKey)
	say("verify", "cross-checking every engine result against the live Flags API (transient identities)")
	verified := a.crossCheck(ctx, sdk, reach)
	r.Reachability = reach
	findings := mapper.ForgeableFindings(reach, opts)
	findings = append(findings, variantFindings(eng, reach, env.Name)...)
	for i := range findings {
		if v, ok := verified[findingKey(findings[i])]; ok {
			markLive(&findings[i], v)
		}
		refine(&findings[i], eng, running, expKnown)
	}
	r.Findings = append(r.Findings, findings...)
	r.Findings = append(r.Findings, a.identityExposure(ctx, eng, env)...)

	if o.ParitySamples > 0 {
		say("parity", fmt.Sprintf("engine vs live parity over %d random identities", o.ParitySamples))
		pr, err := parity.RunLive(ctx, eng, sdk, o.ParitySamples, segs, parity.LiveFor(env, features))
		if err != nil && !errors.Is(err, context.Canceled) {
			r.Notes = append(r.Notes, "parity: "+redact.String(err.Error()))
		}
		r.Stats.ParityChecked, r.Stats.ParityAgreed = pr.Checked, pr.Agreed
	}
	return nil
}

// envDocument prefers a configured server-side key and falls back to the
// admin document endpoint.
func (a *App) envDocument(ctx context.Context, env flagsmith.Environment) (json.RawMessage, error) {
	if k := a.Cfg.ServerKeys[env.Name]; k != "" {
		if d, err := flagsmith.EnvironmentDocumentServerKey(ctx, a.HTTP, a.Cfg.Flagsmith.APIURL, k); err == nil {
			return d, nil
		}
	}
	return a.Admin.EnvironmentDocument(ctx, env.APIKey)
}

// classifyFromAdmin classifies flag values from the environment's own
// /flags/ response when the audit has no outside stage (CI mode).
func (a *App) classifyFromAdmin(ctx context.Context, env flagsmith.Environment, cls map[string]model.Category, fast bool) {
	sdk := flagsmith.NewSDK(a.HTTP, a.Cfg.Flagsmith.APIURL, env.APIKey)
	flags, _, err := sdk.EnvironmentFlags(ctx)
	if err != nil {
		return
	}
	inv := &model.PublicInventory{APIURL: a.Cfg.Flagsmith.APIURL}
	for _, n := range flags.Names() {
		f := flags[n]
		inv.Flags = append(inv.Flags, model.FlagView{Name: n, FeatureID: f.FeatureID, Enabled: f.Enabled, RawValue: f.Value,
			ValueType: valueType(f.Value), Preview: redact.String(trim(flagsmith.ValueString(f.Value), 80))})
	}
	if fast {
		for _, f := range inv.Flags {
			cls[f.Name] = secrets.Classify(f).Category
		}
		return
	}
	classes, _ := a.AI.Classify(ctx, inv)
	for _, c := range classes {
		cls[c.Flag] = c.Category
	}
}

// runningExperiments maps flag name → running experiment. known=false when
// the Experimentation API is unavailable.
func (a *App) runningExperiments(ctx context.Context, env flagsmith.Environment, features []flagsmith.Feature) (map[string]string, bool) {
	exps, err := a.Admin.Experiments(ctx, env.APIKey)
	if err != nil {
		return nil, false
	}
	byID := map[int]string{}
	for _, f := range features {
		byID[f.ID] = f.Name
	}
	out := map[string]string{}
	for _, e := range exps {
		if e.Running() {
			if n := byID[e.FeatureID()]; n != "" {
				out[n] = e.Name
			}
		}
	}
	return out, true
}

type liveResult struct {
	ok       bool
	evidence model.Evidence
	repro    string
}

func reachKey(env, flag, seg string, traits map[string]string, id string) string {
	keys := make([]string, 0, len(traits))
	for k, v := range traits {
		keys = append(keys, k+"="+v)
	}
	sort.Strings(keys)
	return env + "|" + flag + "|" + seg + "|" + strings.Join(keys, "&") + "|" + id
}

func traitString(t map[string]string) string {
	keys := make([]string, 0, len(t))
	for k := range t {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+t[k])
	}
	return strings.Join(parts, " + ")
}

func findingKey(f model.Finding) string {
	flag := ""
	if len(f.Unlocked) > 0 {
		flag = f.Unlocked[0].Flag
	}
	seg := f.Subject
	if f.Type == model.FVariantReroll || f.Type == model.FExperimentRigging {
		seg = ""
	}
	return reachKey(f.Environment, flag, seg, f.Traits, f.ProofID)
}

// crossCheck replays each engine-computed input against the live SDK API
// with a transient identity and records whether Flagsmith agrees.
func (a *App) crossCheck(ctx context.Context, sdk *flagsmith.SDK, reach []model.Reachable) map[string]liveResult {
	out := map[string]liveResult{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6) // bounded; the scoped client also rate-limits
	for i := range reach {
		wg.Add(1)
		sem <- struct{}{}
		go func(rc *model.Reachable) {
			defer func() { <-sem; wg.Done() }()
			id := rc.Identifier
			if id == "" {
				id = probeID()
			}
			res, err := sdk.Identify(ctx, id, rc.ForgedTraits)
			if err != nil {
				return
			}
			got, ok := res.Flags[rc.Flag]
			match := ok && got.Enabled == rc.Enabled && flagsmith.ValueString(got.Value) == rc.Value
			rc.LiveVerified = &match
			mu.Lock()
			out[reachKey(rc.Environment, rc.Flag, rc.Segment, rc.ForgedTraits, rc.Identifier)] = liveResult{ok: match, evidence: res.Evidence, repro: res.Evidence.Request}
			mu.Unlock()
		}(&reach[i])
	}
	wg.Wait()
	return out
}

func markLive(f *model.Finding, v liveResult) {
	f.Evidence = append(f.Evidence, v.evidence)
	f.Repro = v.repro
	if v.ok {
		f.DetectedBy = appendMethod(f.DetectedBy, model.MethodProbe)
		if f.Status == model.StatusExploitable {
			f.Confirmed = true
		}
		return
	}
	f.Notes = append(f.Notes, "Live Flags API did not reproduce the engine result; treated as unconfirmed.")
	f.Confirmed = false
	f.Status = model.StatusUnknown
}

// refine retypes identifier-only reachability as re-roll findings and
// escalates flags under a running experiment.
func refine(f *model.Finding, eng *flagsmith.Engine, running map[string]string, known bool) {
	if len(f.Unlocked) == 0 {
		return
	}
	flag := f.Unlocked[0].Flag
	if f.Type == model.FIdentifierForgery {
		// The mapper keeps the segment as subject for the live cross-check;
		// reports and fix plans are about the flag it unlocks.
		f.Subject = flag
	}
	if f.Type == model.FSegmentForgeable && len(f.Traits) > 0 && f.Status == model.StatusExploitable {
		f.Type = model.FTraitForgery
		f.ID = model.MakeFindingID(f.Type, f.Environment, flag, traitString(f.Traits))
		f.Title = fmt.Sprintf("Forging %s unlocks %s (segment %q)", traitString(f.Traits), flag, f.Subject)
	}
	if f.Type == model.FSegmentForgeable && len(f.Traits) == 0 && f.ProofID != "" {
		f.Type = model.FPercentageReroll
		f.Notes = append(f.Notes, fmt.Sprintf("Percentage-split segment %q; the browser chooses its own identifier.", f.Subject))
		f.Subject = flag
		f.HitRate = hitRate(eng, flag, f.Unlocked[0].After)
		if f.HitRate > 0 {
			f.Attempts = 1 / f.HitRate
		}
		f.Title = fmt.Sprintf("Re-rolling the identifier unlocks %s (≈%.0f%% rollout, ~%.0f tries)", flag, f.HitRate*100, f.Attempts)
		f.ID = model.MakeFindingID(f.Type, f.Environment, flag)
	}
	if f.Type == model.FVariantReroll || f.Type == model.FPercentageReroll {
		if name, ok := running[flag]; ok {
			f.Type = model.FExperimentRigging
			f.ID = model.MakeFindingID(f.Type, f.Environment, flag)
			f.Title = fmt.Sprintf("Users can pick their own group in experiment %q (%s)", name, flag)
			f.Notes = append(f.Notes,
				"Business impact: any user can choose the variant they prefer (for example the cheaper price).",
				"Data integrity: self-selected groups bias the results Flagsmith's Bayesian stats engine reports.")
		} else if !known && f.Type == model.FVariantReroll {
			f.Notes = append(f.Notes, "Experiment status unknown.")
		}
	}
}

// variantFindings builds VARIANT_REROLL findings from identifier-reachable
// multivariate values, with the spread measured by the engine.
func variantFindings(eng *flagsmith.Engine, reach []model.Reachable, env string) []model.Finding {
	byFlag := map[string][]model.Reachable{}
	for _, rc := range reach {
		if rc.Segment == "" && rc.Identifier != "" && len(rc.ForgedTraits) == 0 {
			byFlag[rc.Flag] = append(byFlag[rc.Flag], rc)
		}
	}
	var out []model.Finding
	for flag, rs := range byFlag {
		counts := variantSpread(eng, flag, 1000)
		var proofs []string
		for _, rc := range rs {
			proofs = append(proofs, fmt.Sprintf("identifier %s receives %q", rc.Identifier, rc.Value))
		}
		sort.Strings(proofs)
		f := model.Finding{
			ID: model.MakeFindingID(model.FVariantReroll, env, flag), Type: model.FVariantReroll,
			Title:       fmt.Sprintf("Users can choose their %s variant by re-rolling their identifier", flag),
			Environment: env, Subject: flag, DetectedBy: []model.Method{model.MethodEngine},
			Confirmed: true, Status: model.StatusExploitable, Variants: counts, ProofID: rs[0].Identifier,
			Unlocked: []model.FlagChange{{Flag: flag, Before: flagsmith.Flag{Enabled: rs[0].DefaultEnabled, Value: rs[0].DefaultValue}.State(),
				After: flagsmith.Flag{Enabled: rs[0].Enabled, Value: rs[0].Value}.State()}},
			Notes:    proofs,
			Evidence: []model.Evidence{{Kind: "engine", Note: fmt.Sprintf("Variant spread over 1000 identifiers: %v", counts)}},
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Subject < out[j].Subject })
	return out
}

func hitRate(eng *flagsmith.Engine, flag, wantState string) float64 {
	const n = 2000
	hits := 0
	for i := 0; i < n; i++ {
		fs := eng.Evaluate(fmt.Sprintf("gc-probe-rate-%d", i), nil)
		if f, ok := fs[flag]; ok && f.State() == wantState {
			hits++
		}
	}
	return float64(hits) / n
}

func variantSpread(eng *flagsmith.Engine, flag string, n int) map[string]int {
	out := map[string]int{}
	for i := 0; i < n; i++ {
		if f, ok := eng.Evaluate(fmt.Sprintf("gc-probe-spread-%d", i), nil)[flag]; ok {
			out[flagsmith.ValueString(f.Value)]++
		}
	}
	return out
}

func dedupe(r *model.Report) {
	seen := map[string]int{}
	out := r.Findings[:0]
	for _, f := range r.Findings {
		if i, ok := seen[f.ID]; ok {
			out[i] = merge(out[i], f)
			continue
		}
		seen[f.ID] = len(out)
		out = append(out, f)
	}
	r.Findings = out
}

func appendMethod(ms []model.Method, m model.Method) []model.Method {
	for _, x := range ms {
		if x == m {
			return ms
		}
	}
	return append(ms, m)
}

func mergeMethods(a, b []model.Method) []model.Method {
	for _, m := range b {
		a = appendMethod(a, m)
	}
	return a
}

func valueType(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case bool:
		return "bool"
	case float64:
		return "number"
	case string:
		s := strings.TrimSpace(t)
		if strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") {
			return "json"
		}
		return "string"
	default:
		return "json"
	}
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func newReportID() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return "r-" + time.Now().UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b)
}

func probeID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return "gc-probe-" + h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// SaveReport writes every format to the report dir.
func (a *App) SaveReport(r *model.Report) ([]string, error) {
	return report.WriteAll(a.Cfg.ReportDir, r)
}

// LoadReport reads a canonical JSON report ("" or "latest" for the newest).
func (a *App) LoadReport(id string) (*model.Report, error) {
	p, err := a.reportPath(id)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("report %s: %w", id, err)
	}
	var r model.Report
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("report %s: %w", id, err)
	}
	return &r, nil
}
