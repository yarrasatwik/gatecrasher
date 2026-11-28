package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/ai"
	"github.com/yarrasatwik/gatecrasher/internal/audit"
	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
	"github.com/yarrasatwik/gatecrasher/internal/report"
	"github.com/yarrasatwik/gatecrasher/internal/secrets"
	"github.com/yarrasatwik/gatecrasher/internal/severity"
	"github.com/yarrasatwik/gatecrasher/internal/unreleased"
)

// reviewSuffix marks the title of something only the AI suggested.
const reviewSuffix = " (suggested by Claude, needs review)"

// adjudicate decides what each classification is allowed to become. The AI
// never decides what is real:
//
//   - a classification where only the AI says "not harmless" becomes
//     NeedsReview, unless a deterministic rule agrees or a human already
//     confirmed that exact finding in env (confirmed: finding ID → who);
//   - UNRELEASED_PRODUCT is settled by the deterministic name rules in
//     package unreleased, with one rule against: a flag that is on by default
//     is already served to real users, so it is not unreleased. (Live
//     percentage rollouts are only known after the attack and map stages;
//     dropLiveUnreleased applies the same rule to them.)
//
// It returns a new slice; classes is not modified.
func adjudicate(classes []model.Classification, inv *model.PublicInventory, env string, auditDate time.Time, confirmed map[string]string) []model.Classification {
	views := map[string]model.FlagView{}
	for _, f := range inv.Flags {
		views[f.Name] = f
	}
	out := make([]model.Classification, len(classes))
	for i, c := range classes {
		view := views[c.Flag]
		rule := unreleased.Check(c.Flag, auditDate)
		switch {
		case c.Method == model.MethodAI && ai.Reportable(c):
			out[i] = adjudicateAI(c, view, rule, confirmed[model.MakeFindingID(leakTypes[c.Category], env, c.Flag)])
		case c.Category == model.CatUnreleasedProduct:
			out[i] = adjudicateUnreleased(c, view, rule)
		case c.Category == model.CatHarmless && rule.Match && !view.Enabled:
			c.Category, c.Confidence, c.Method = model.CatUnreleasedProduct, 0.9, model.MethodDeterministic
			c.Rationale = "unreleased product: flag name matches " + strings.Join(rule.Signals, ", ")
			c.Signals = append(append([]string{}, c.Signals...), rule.Signals...)
			out[i] = c
		default:
			out[i] = c
		}
	}
	return out
}

// adjudicateAI handles a classification only the AI made.
// confirmedBy names the person who already confirmed this exact finding, or "".
func adjudicateAI(c model.Classification, view model.FlagView, rule unreleased.Result, confirmedBy string) model.Classification {
	det := secrets.Classify(view)
	det.Flag = c.Flag
	if c.Category == model.CatUnreleasedProduct {
		if view.Enabled {
			det.Rationale = "on by default, so already served to real users: not an unreleased product (the AI suggested one)"
			return det
		}
		if rule.Match {
			c.Method, c.Confidence = model.MethodDeterministic, 0.9
			c.Rationale = "unreleased product: flag name matches " + strings.Join(rule.Signals, ", ") + " (the AI agreed)"
			c.Signals = append([]string{}, rule.Signals...)
			return c
		}
	}
	if confirmedBy != "" {
		c.Method = model.MethodHuman
		c.Rationale = redact.String(fmt.Sprintf("%s (suggested by the AI, confirmed by %s)", c.Rationale, confirmedBy))
		return c
	}
	c.NeedsReview = true
	return c
}

// adjudicateUnreleased re-checks a deterministic UNRELEASED_PRODUCT result
// against the rule against (on by default) and the audit date.
func adjudicateUnreleased(c model.Classification, view model.FlagView, rule unreleased.Result) model.Classification {
	harmless := func(why string) model.Classification {
		return model.Classification{Flag: c.Flag, Category: model.CatHarmless, Confidence: 0.9, Method: model.MethodDeterministic, Rationale: why}
	}
	if view.Enabled {
		return harmless("on by default, so already served to real users: not an unreleased product")
	}
	if !rule.Match && onlyDatedName(c.Signals) {
		return harmless("the date in the flag name is not in the future: not an unreleased product")
	}
	return c
}

// onlyDatedName reports whether the only unreleased-product signal is a bare
// date in the flag name.
func onlyDatedName(signals []string) bool {
	n := 0
	for _, s := range signals {
		if s == "dated_name@name" {
			n++
		} else if !strings.HasPrefix(s, "admin_gate@") {
			return false
		}
	}
	return n > 0
}

// trustedCategories maps each flag to the category the deterministic stages
// may use (severity rules, the settings audit). A category only the AI
// suggested is never in it.
func trustedCategories(classes []model.Classification) map[string]model.Category {
	out := map[string]model.Category{}
	for _, c := range classes {
		if !c.NeedsReview {
			out[c.Flag] = c.Category
		}
	}
	return out
}

// leakFindings turns adjudicated classifications into findings: confirmed
// ones are EXPLOITABLE, AI-only ones are NEEDS_REVIEW items.
func leakFindings(classes []model.Classification, inv *model.PublicInventory, env string) []model.Finding {
	var out []model.Finding
	for _, c := range classes {
		if !ai.Reportable(c) {
			continue
		}
		f := configLeak(c, inv, env)
		if c.NeedsReview {
			f.Status, f.Confirmed = model.StatusNeedsReview, false
			f.Title += reviewSuffix
			f.Notes = append(f.Notes, "Only the AI suggests this. No deterministic rule or probe agrees, so it is not counted as a finding until a person confirms it in the web UI.")
		}
		out = append(out, f)
	}
	return out
}

// liveFlags returns the flags a share of real users currently receives
// switched on through a rollout, with the reason. The evidence is a
// percentage re-roll that was reproduced, or an identifier-only reachable
// "on" state in the engine map.
func liveFlags(r *model.Report) map[string]string {
	out := map[string]string{}
	for _, f := range r.Findings {
		if len(f.Unlocked) == 0 {
			continue
		}
		u := f.Unlocked[0]
		on := u.After == "on" || strings.HasPrefix(u.After, "on:")
		off := u.Before == "off" || strings.HasPrefix(u.Before, "off:")
		switch f.Type {
		case model.FPercentageReroll:
			out[u.Flag] = "a live percentage rollout"
		case model.FExperimentRigging, model.FVariantReroll:
			if on && off {
				out[u.Flag] = "a live percentage rollout"
			}
		}
	}
	for _, rc := range r.Reachability {
		if rc.Identifier != "" && len(rc.ForgedTraits) == 0 && rc.Segment != "" && rc.Enabled && !rc.DefaultEnabled {
			out[rc.Flag] = "a live percentage rollout"
		}
	}
	return out
}

// dropLiveUnreleased applies the rule against "unreleased product" to flags
// behind a live rollout: real users already receive them, so they are not
// reported as unreleased (neither as a finding, nor as a review item, nor as
// a "sensitive flag is not Server-side only" finding). It is idempotent.
func dropLiveUnreleased(r *model.Report, cls map[string]model.Category) {
	live := liveFlags(r)
	if len(live) == 0 {
		return
	}
	dropped := map[string]bool{}
	kept := r.Findings[:0]
	for _, f := range r.Findings {
		_, isLive := live[f.Subject]
		unreleasedLeak := f.Type == model.FUnreleasedProduct ||
			(f.Type == model.FFlagNotServerOnly && f.Category == model.CatUnreleasedProduct)
		if isLive && unreleasedLeak {
			dropped[f.Subject] = true
			continue
		}
		kept = append(kept, f)
	}
	r.Findings = kept
	for i := range r.Findings {
		f := &r.Findings[i]
		flag := f.Subject
		if len(f.Unlocked) > 0 {
			flag = f.Unlocked[0].Flag
		}
		if _, isLive := live[flag]; isLive && f.Category == model.CatUnreleasedProduct {
			f.Category = ""
		}
	}
	for i := range r.Classifications {
		c := &r.Classifications[i]
		if reason, isLive := live[c.Flag]; isLive && c.Category == model.CatUnreleasedProduct {
			dropped[c.Flag] = true
			*c = model.Classification{Flag: c.Flag, Category: model.CatHarmless, Confidence: 0.9, Method: model.MethodDeterministic,
				Rationale: "behind " + reason + ", so already served to real users: not an unreleased product"}
		}
	}
	names := make([]string, 0, len(dropped))
	for flag := range live {
		if cls[flag] == model.CatUnreleasedProduct {
			delete(cls, flag)
			dropped[flag] = true
		}
	}
	for flag := range dropped {
		names = append(names, flag)
	}
	sort.Strings(names)
	for _, flag := range names {
		r.Notes = append(r.Notes, fmt.Sprintf("%s is behind %s, so real users already receive it: it is not reported as an unreleased product.", flag, live[flag]))
	}
}

// confirmFinding promotes one NEEDS_REVIEW item of r to a confirmed finding
// on a human's say-so. The caller records the decision in the audit log.
func confirmFinding(r *model.Report, findingID, by string) error {
	for i := range r.Findings {
		f := &r.Findings[i]
		if f.ID != findingID {
			continue
		}
		if f.Status != model.StatusNeedsReview {
			return fmt.Errorf("finding %s is %s, not awaiting review", findingID, f.Status)
		}
		f.Status, f.Confirmed = model.StatusExploitable, true
		f.Title = strings.TrimSuffix(f.Title, reviewSuffix)
		f.DetectedBy = appendMethod(f.DetectedBy, model.MethodHuman)
		f.Notes = append(f.Notes[:0:0], redact.String(fmt.Sprintf("Suggested by the AI and confirmed by %s in the web UI.", by)))
		for j := range r.Classifications {
			if c := &r.Classifications[j]; c.Flag == f.Subject && c.NeedsReview {
				c.NeedsReview, c.Method = false, model.MethodHuman
			}
		}
		return nil
	}
	return fmt.Errorf("finding %s not found in report %s", findingID, r.ID)
}

// ErrNotReviewable is returned when a finding cannot be confirmed.
var ErrNotReviewable = errors.New("finding is not awaiting review")

// ConfirmFinding records that a human confirmed a NEEDS_REVIEW item of a
// report: first in the hash-chained audit log, then in the report, which is
// re-rated by the deterministic severity rules and saved in every format.
func (a *App) ConfirmFinding(_ context.Context, reportID, findingID, by string) (*model.Report, error) {
	r, err := a.LoadReport(reportID)
	if err != nil {
		return nil, err
	}
	var target *model.Finding
	for i := range r.Findings {
		if r.Findings[i].ID == findingID {
			target = &r.Findings[i]
		}
	}
	if target == nil || target.Status != model.StatusNeedsReview {
		return nil, fmt.Errorf("%w: %s in report %s", ErrNotReviewable, findingID, r.ID)
	}
	if _, err := a.Log.Append(by, audit.ActionConfirmFinding, "", map[string]any{
		"report": r.ID, "finding": target.ID,
		"type": string(target.Type), "subject": target.Subject, "category": string(target.Category), "channel": "web",
	}); err != nil {
		return nil, fmt.Errorf("not confirming: %w", err)
	}
	if err := confirmFinding(r, findingID, by); err != nil {
		return nil, err
	}
	severity.AssignAll(r.Findings)
	AssignRootCauses(r)
	report.Finalize(r)
	if _, err := a.SaveReport(r); err != nil {
		return r, err
	}
	return r, nil
}

// confirmedFindings reads the human confirmations from the audit log
// (finding ID → who), so a later audit does not ask about the same
// suggestion again. Finding IDs are stable across audits.
func (a *App) confirmedFindings() map[string]string {
	out := map[string]string{}
	if a.Log == nil {
		return out
	}
	entries, err := a.Log.Entries()
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.Action != audit.ActionConfirmFinding {
			continue
		}
		var d struct {
			Finding string `json:"finding"`
		}
		if e.Decode(&d) == nil && d.Finding != "" {
			out[d.Finding] = e.Actor
		}
	}
	return out
}
