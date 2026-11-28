package app

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/yarrasatwik/gatecrasher/internal/ai"
	"github.com/yarrasatwik/gatecrasher/internal/attacks"
	"github.com/yarrasatwik/gatecrasher/internal/model"
)

// Assumptions used when no earlier report supplies a real count. They are
// printed with every estimate so the number is never a surprise.
const (
	assumedScripts   = 2  // JavaScript files recon fetches after the page
	assumedReachable = 10 // reachable flag states the live cross-check replays
	assumedForging   = 2  // trait sets that change a flag (2 more requests each)
	assumedOverrides = 1  // identity overrides the audit looks up
)

// StageEstimate is the estimated request count of one stage.
type StageEstimate struct {
	Stage    string `json:"stage"`
	Requests int    `json:"requests"`
}

// Estimate is the expected request count of an audit, by stage. It is built
// from the configuration and from counts remembered in the latest saved report;
// it never contacts Flagsmith or the target.
type Estimate struct {
	Profile       string          `json:"profile"`
	ParitySamples int             `json:"parity_samples"`
	RerollSamples int             `json:"reroll_samples"`
	Budget        int             `json:"budget,omitempty"`
	Stages        []StageEstimate `json:"stages"`
	Total         int             `json:"total"`
	// Source names the saved report whose counts were used ("" = none: the
	// defaults below were assumed).
	Source      string   `json:"source,omitempty"`
	Assumptions []string `json:"assumptions,omitempty"`
}

// effectiveBudget is the request cap an audit with o would run under.
func (a *App) effectiveBudget(o AuditOptions) int {
	if o.Budget > 0 {
		return o.Budget
	}
	return a.Cfg.Probes.MaxRequests
}

// Estimate predicts the requests an audit with o sends. It makes no network
// calls. Requests are counted as attempts on the wire: a retry after a 429 or
// 5xx is one more request and is not included here.
func (a *App) Estimate(o AuditOptions) Estimate {
	e := Estimate{Profile: a.Cfg.ProfileName(), ParitySamples: o.ParitySamples, RerollSamples: a.Cfg.RerollSamples(), Budget: a.effectiveBudget(o)}
	target := o.Target
	if target == "" {
		target = a.Cfg.TargetURL
	}
	var last *model.Report
	if r, err := a.LoadReport("latest"); err == nil && r != nil {
		last = r
		e.Source = r.ID
	}
	add := func(stage string, n int) {
		e.Stages = append(e.Stages, StageEstimate{Stage: stage, Requests: n})
		e.Total += n
	}
	assume := func(format string, args ...any) { e.Assumptions = append(e.Assumptions, fmt.Sprintf(format, args...)) }

	if o.Outside && target != "" {
		// The page, its scripts, then one GET flags/ per candidate key until
		// one is accepted.
		scripts := assumedScripts
		if last != nil && last.Stats.StageRequests["recon"] > 0 {
			scripts = max(0, int(last.Stats.StageRequests["recon"])-2)
		} else {
			assume("recon fetches the page, %d scripts and validates one key", assumedScripts)
		}
		add("recon", 1+scripts+1)

		var traitKeys []string
		forging := assumedForging
		if last != nil && last.Inventory != nil {
			traitKeys = last.Inventory.TraitKeys
			forging = forgingSets(last)
		} else {
			assume("%d trait set(s) change a flag and are re-probed (2 requests each)", assumedForging)
		}
		host := ""
		if u, err := url.Parse(target); err == nil {
			host = u.Hostname()
		}
		hyp := ai.HeuristicHypotheses(traitKeys, host)
		clientIDs := a.Cfg.ClientSetsIdentifier == nil || *a.Cfg.ClientSetsIdentifier
		est := attacks.EstimateRequests(attacks.Options{TestIdentities: a.Cfg.TestIdentities, MaxHypotheses: a.Cfg.Probes.MaxHypotheses,
			MaxCombos: a.Cfg.Probes.MaxCombos, RerollSamples: a.Cfg.RerollSamples(), ClientSetsIdentifier: clientIDs}, hyp)
		add("attack", 1+est.Total()+2*forging) // 1 = the baseline Identify
		if a.AI.Mode().On() {
			assume("attack counts the built-in trait guesses; the AI may propose others (capped at %d)", ai.MaxHypotheses)
		}
	}
	if o.Inside && a.Admin != nil {
		n := 6 // environment list, fresh settings, features, segments, document, experiments
		a.mu.Lock()
		cached := a.project != nil
		a.mu.Unlock()
		if !cached {
			n += 2 // project and environment lookups
		}
		if !(o.Outside && target != "") {
			n++ // flag values are read from the environment to classify them
		}
		overrides := assumedOverrides
		reach := assumedReachable
		if last != nil && len(last.Reachability) > 0 {
			reach = len(last.Reachability)
			overrides = max(0, int(last.Stats.StageRequests["map"])-n)
		} else {
			assume("%d reachable flag state(s) are cross-checked live (1 request each)", assumedReachable)
			assume("map assumes one page per list and %d identity override lookup(s)", assumedOverrides)
		}
		add("map", n+overrides)
		add("verify", reach)
		if o.ParitySamples > 0 {
			add("parity", o.ParitySamples)
		}
	} else if o.Inside {
		assume("inside view skipped: no organisation API key")
	}
	return e
}

// forgingSets counts the distinct trait sets of a report's trait findings.
func forgingSets(r *model.Report) int {
	seen := map[string]bool{}
	for _, f := range r.Findings {
		if len(f.Traits) > 0 && (f.Type == model.FTraitForgery || f.Type == model.FExperimentRigging) {
			seen[traitString(f.Traits)] = true
		}
	}
	return len(seen)
}

// Text renders the estimate for the terminal. With a budget it shows which
// stages the cap would stop.
func (e Estimate) Text() string {
	var b strings.Builder
	cap := "no budget"
	if e.Budget > 0 {
		cap = fmt.Sprintf("budget %d", e.Budget)
	}
	fmt.Fprintf(&b, "  estimated requests · profile %s · parity %d · re-roll %d · %s\n", e.Profile, e.ParitySamples, e.RerollSamples, cap)
	start := 0
	for _, s := range e.Stages {
		note := ""
		if e.Budget > 0 {
			switch {
			case start >= e.Budget:
				note = "   incomplete (budget): not started"
			case start+s.Requests > e.Budget:
				note = fmt.Sprintf("   incomplete (budget): stops after %d", e.Budget-start)
			}
		}
		fmt.Fprintf(&b, "    %-9s %6d%s\n", s.Stage, s.Requests, note)
		start += s.Requests
	}
	fmt.Fprintf(&b, "    %-9s %6d\n", "total", e.Total)
	if e.Source != "" {
		fmt.Fprintf(&b, "  counts from report %s; the rest assumed\n", e.Source)
	}
	for _, as := range e.Assumptions {
		fmt.Fprintf(&b, "  assumes: %s\n", as)
	}
	b.WriteString("  AI calls (classification, explanations) go to the model provider and are not counted.\n")
	return b.String()
}
