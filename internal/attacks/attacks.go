// Package attacks runs bounded, transient public SDK probes. Requests are
// deliberately sequential (including rechecks), below the eight request limit.
package attacks

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/yarrasatwik/gatecrasher/internal/ai"
	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
	"github.com/yarrasatwik/gatecrasher/internal/httpx"
	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

// Options bounds work and supplies the explicit identity lookup allowlist.
// RunningExperiments must come from a trusted experiment inventory; nil means unknown.
type Options struct {
	Environment                             string
	TestIdentities                          []string
	MaxHypotheses, MaxCombos, RerollSamples int
	ClientSetsIdentifier                    bool
	RunningExperiments                      map[string]bool
}

// Runner uses only the public SDK. Its mutex also bounds concurrent Run/Recheck calls.
type Runner struct {
	sdk  *flagsmith.SDK
	opts Options
	mu   sync.Mutex
}

func New(sdk *flagsmith.SDK, opts Options) *Runner {
	opts.TestIdentities = append([]string(nil), opts.TestIdentities...)
	opts.MaxHypotheses = bound(opts.MaxHypotheses, 40, 40)
	opts.MaxCombos = bound(opts.MaxCombos, 24, 24)
	opts.RerollSamples = bound(opts.RerollSamples, 200, 500)
	return &Runner{sdk: sdk, opts: opts}
}
func bound(n, def, max int) int {
	if n == 0 {
		return def
	}
	if n < 0 {
		return 0
	}
	if n > max {
		return max
	}
	return n
}
func freshID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "gc-probe-" + hex.EncodeToString(b)
}
func identityToken(id string) string {
	h := sha256.Sum256([]byte(id))
	return "test-" + hex.EncodeToString(h[:])
}
func safeError(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(redact.String(err.Error()))
}
func (r *Runner) finding(t model.FindingType, subject string) model.Finding {
	return model.Finding{ID: model.MakeFindingID(t, r.opts.Environment, subject), Type: t, Environment: r.opts.Environment, Subject: redact.String(subject), Title: redact.String(string(t) + ": " + subject), Confirmed: true, Status: model.StatusExploitable, DetectedBy: []model.Method{model.MethodProbe}}
}
func change(base, probe flagsmith.Flags, name string, mask bool) model.FlagChange {
	b, a := base[name].State(), probe[name].State()
	if mask {
		b, a = "[MASKED]", "[MASKED]"
	}
	return model.FlagChange{Flag: redact.String(name), Before: redact.String(b), After: redact.String(a)}
}
func evidence(res *flagsmith.IdentityResult) model.Evidence {
	return model.Evidence{Kind: "request", Request: res.Evidence.Request, Note: "Transient SDK evaluation; raw response omitted to protect trait and flag values."}
}

// Run consumes the baseline and ranked hypotheses from ai.Hypothesize.
// Errors return partial confirmed findings and must be surfaced by the caller.
func (r *Runner) Run(ctx context.Context, baseline flagsmith.Flags, hypotheses []ai.Hypothesis) ([]model.Finding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []model.Finding{}
	hs := []ai.Hypothesis{}
	seen := map[string]bool{}
	for _, h := range hypotheses {
		k := h.TraitKey + "\x00" + h.TraitValue
		if h.TraitKey == "" || h.TraitValue == "" || len(h.TraitKey) > 64 || len(h.TraitValue) > 128 || seen[k] {
			continue
		}
		seen[k] = true
		hs = append(hs, h)
		if len(hs) >= r.opts.MaxHypotheses {
			break
		}
	}
	if r.opts.MaxHypotheses == 0 {
		hs = nil
	}
	sets := []map[string]string{}
	for _, h := range hs {
		sets = append(sets, map[string]string{h.TraitKey: h.TraitValue})
	}
	combos := 0
	for i := 0; i < len(hs); i++ {
		for j := i + 1; j < len(hs) && combos < r.opts.MaxCombos; j++ {
			if hs[i].TraitKey == hs[j].TraitKey {
				continue
			}
			sets = append(sets, map[string]string{hs[i].TraitKey: hs[i].TraitValue, hs[j].TraitKey: hs[j].TraitValue})
			combos++
		}
	}
	for _, traits := range sets {
		first, control, err := r.pair(ctx, traits)
		if err != nil {
			return out, safeError(err)
		}
		candidates := flagsmith.Diff(baseline, first.Flags)
		if len(candidates) == 0 {
			continue
		}
		second, control2, err := r.pair(ctx, traits)
		if err != nil {
			return out, safeError(err)
		}
		for _, c := range candidates {
			p := first.Flags[c.Flag]
			q, ok := second.Flags[c.Flag]
			if !ok || p.State() != q.State() || p.State() == control.Flags[c.Flag].State() || q.State() == control2.Flags[c.Flag].State() {
				continue
			}
			f := r.finding(model.FTraitForgery, c.Flag)
			raw, _ := json.Marshal(traits)
			f.ID = model.MakeFindingID(f.Type, r.opts.Environment, c.Flag, string(raw))
			f.Traits = map[string]string{}
			for k, v := range traits {
				f.Traits[redact.String(k)] = redact.String(v)
			}
			f.Unlocked = []model.FlagChange{change(baseline, first.Flags, c.Flag, false)}
			f.ProofID = first.Identifier
			f.Evidence = []model.Evidence{evidence(first), evidence(second)}
			f.Repro = first.Evidence.Request
			r.experiment(&f)
			out = append(out, f)
		}
	}
	rolls, err := r.reroll(ctx, baseline)
	out = append(out, rolls...)
	if err != nil {
		return out, safeError(err)
	}
	for _, id := range r.opts.TestIdentities {
		res, err := r.sdk.LookupIdentity(ctx, id)
		if err != nil {
			return out, errors.New("test identity lookup failed (response omitted)")
		}
		if len(res.Traits) > 0 {
			f := r.finding(model.FIdentityTraitLeak, identityToken(id))
			f.Category = model.CatPII
			f.ProofID = identityToken(id)
			f.Repro = flagsmith.Repro("GET", httpx.JoinURL(r.sdk.APIURL(), "identities/")+"?identifier=<TEST_IDENTITY>", nil)
			f.Evidence = []model.Evidence{{Kind: "request", Request: f.Repro, Response: fmt.Sprintf("%d traits exposed; all values [MASKED]", len(res.Traits))}}
			out = append(out, f)
		}
		for _, c := range flagsmith.Diff(baseline, res.Flags) {
			// SDK responses may omit evaluation reasons. Without an explicit reason,
			// a difference could be a segment or rollout, so don't claim an override.
			if !identityOverride(res.Flags[c.Flag]) {
				continue
			}
			f := r.finding(model.FIdentityOverrideLeak, c.Flag)
			f.ID = model.MakeFindingID(f.Type, r.opts.Environment, c.Flag, identityToken(id))
			f.ProofID = identityToken(id)
			f.Unlocked = []model.FlagChange{change(baseline, res.Flags, c.Flag, true)}
			f.Repro = flagsmith.Repro("GET", httpx.JoinURL(r.sdk.APIURL(), "identities/")+"?identifier=<TEST_IDENTITY>", nil)
			f.Evidence = []model.Evidence{{Kind: "request", Request: f.Repro, Response: "Identity override differs from baseline; values [MASKED]"}}
			out = append(out, f)
		}
	}
	return out, nil
}
func identityOverride(f flagsmith.Flag) bool {
	return strings.Contains(strings.ToUpper(f.Reason), "IDENTITY_OVERRIDE")
}
func sortedStates(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
func (r *Runner) pair(ctx context.Context, traits map[string]string) (*flagsmith.IdentityResult, *flagsmith.IdentityResult, error) {
	id := freshID()
	control, err := r.sdk.Identify(ctx, id, nil)
	if err != nil {
		return nil, nil, err
	}
	probe, err := r.sdk.Identify(ctx, id, traits)
	return probe, control, err
}
func (r *Runner) experiment(f *model.Finding) {
	if r.opts.RunningExperiments == nil {
		f.Notes = append(f.Notes, "experiment status unknown")
		return
	}
	if r.opts.RunningExperiments[f.Subject] {
		f.Type = model.FExperimentRigging
		f.ID = model.MakeFindingID(f.Type, r.opts.Environment, f.Subject, f.ID)
		f.Notes = append(f.Notes, "Business impact: users can choose a flag state. Data integrity: self-selected groups bias experiment results.")
	}
}

func (r *Runner) reroll(ctx context.Context, baseline flagsmith.Flags) ([]model.Finding, error) {
	if !r.opts.ClientSetsIdentifier {
		return nil, nil
	}
	counts := map[string]map[string]int{}
	proofs := map[string]map[string]*flagsmith.IdentityResult{}
	for i := 0; i < r.opts.RerollSamples; i++ {
		res, err := r.sdk.Identify(ctx, freshID(), nil)
		if err != nil {
			return nil, err
		}
		for name, f := range res.Flags {
			if counts[name] == nil {
				counts[name] = map[string]int{}
				proofs[name] = map[string]*flagsmith.IdentityResult{}
			}
			counts[name][f.State()]++
			proofs[name][f.State()] = res
		}
	}
	out := []model.Finding{}
	for _, name := range baseline.Names() {
		states := counts[name]
		if len(states) < 2 {
			continue
		}
		base := baseline[name]
		t := model.FVariantReroll
		hits := 0
		var proof *flagsmith.IdentityResult
		for _, state := range sortedStates(states) {
			if state != base.State() {
				hits = states[state]
				proof = proofs[name][state]
				break
			}
		}
		if !base.Enabled {
			on := 0
			for _, state := range sortedStates(states) {
				if proofs[name][state].Flags[name].Enabled {
					on += states[state]
					proof = proofs[name][state]
				}
			}
			if on > 0 {
				hits = on
				t = model.FPercentageReroll
			}
		}
		if hits == 0 || hits == r.opts.RerollSamples || proof == nil {
			continue
		}
		// Value spreads (including always-enabled flags) are multivariate rerolls.
		f := r.finding(t, name)
		f.HitRate = float64(hits) / float64(r.opts.RerollSamples)
		f.Attempts = 1 / f.HitRate
		f.ProofID = proof.Identifier
		f.Variants = map[string]int{}
		for state, n := range states {
			f.Variants[redact.String(state)] += n
		}
		f.Unlocked = []model.FlagChange{change(baseline, proof.Flags, name, false)}
		f.Repro = proof.Evidence.Request
		f.Evidence = []model.Evidence{evidence(proof)}
		r.experiment(&f)
		out = append(out, f)
	}
	return out, nil
}

// Recheck reruns live SDK evidence; failed or ambiguous checks remain UNKNOWN.
func (r *Runner) Recheck(ctx context.Context, f model.Finding) (model.Status, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	unknown := func(err error) (model.Status, string, error) { return model.StatusUnknown, "", safeError(err) }
	result := func(ok bool, proof string) (model.Status, string, error) {
		if ok {
			return model.StatusExploitable, redact.String(proof), nil
		}
		return model.StatusBlocked, redact.String(proof), nil
	}
	if f.Type == model.FIdentityTraitLeak || f.Type == model.FIdentityOverrideLeak {
		id := ""
		for _, allowed := range r.opts.TestIdentities {
			if identityToken(allowed) == f.ProofID {
				id = allowed
				break
			}
		}
		if id == "" {
			return unknown(errors.New("identity finding does not match a configured test identity"))
		}
		res, err := r.sdk.LookupIdentity(ctx, id)
		if err != nil {
			return unknown(errors.New("test identity lookup failed (response omitted)"))
		}
		if f.Type == model.FIdentityTraitLeak {
			return result(len(res.Traits) > 0, fmt.Sprintf("Test identity returned %d traits; values [MASKED]", len(res.Traits)))
		}
		baseline, _, err := r.sdk.EnvironmentFlags(ctx)
		if err != nil {
			return unknown(err)
		}
		got, ok := res.Flags[f.Subject]
		return result(ok && identityOverride(got) && got.State() != baseline[f.Subject].State(), "Test identity override checked; values [MASKED]")
	}
	switch f.Type {
	case model.FTraitForgery, model.FPercentageReroll, model.FVariantReroll, model.FExperimentRigging:
	default:
		return unknown(fmt.Errorf("unsupported attack finding %s", f.Type))
	}
	if len(f.Unlocked) == 0 {
		return unknown(errors.New("finding has no flag change"))
	}
	want := f.Unlocked[0]
	if len(f.Traits) > 0 {
		for k, v := range f.Traits {
			if strings.Contains(k, "[") || strings.Contains(v, "[") {
				return unknown(errors.New("masked probe inputs cannot be replayed"))
			}
		}
		for i := 0; i < 2; i++ {
			probe, control, err := r.pair(ctx, f.Traits)
			if err != nil {
				return unknown(err)
			}
			got, ok := probe.Flags[want.Flag]
			if !ok || redact.String(got.State()) != want.After || got.State() == control.Flags[want.Flag].State() {
				return result(false, "Fresh transient trait probe no longer reproduces the flag change")
			}
		}
		return result(true, "Two fresh transient trait probes reproduce the flag change")
	}
	if !r.opts.ClientSetsIdentifier {
		return result(false, "Client does not control identifiers")
	}
	if !strings.HasPrefix(f.ProofID, "gc-probe-") {
		return unknown(errors.New("invalid transient proof identifier"))
	}
	res, err := r.sdk.Identify(ctx, f.ProofID, nil)
	if err != nil {
		return unknown(err)
	}
	got, ok := res.Flags[want.Flag]
	if !ok || redact.String(got.State()) != want.After {
		return result(false, "Transient proof identifier no longer reproduces the chosen state")
	}
	// An anonymous environment default can itself be one of the variants.
	// Verify that identifiers still select different states, rather than
	// comparing the proof against that unrelated default.
	for i := 0; i < r.opts.RerollSamples; i++ {
		other, err := r.sdk.Identify(ctx, freshID(), nil)
		if err != nil {
			return unknown(err)
		}
		flag, visible := other.Flags[want.Flag]
		if visible && flag.State() != got.State() && (f.Type != model.FPercentageReroll || !flag.Enabled) {
			return result(true, "Transient proof reproduced; another fresh identifier selected a different state")
		}
	}
	return result(false, "No identifier-dependent state difference reproduced within the sample limit")
}
