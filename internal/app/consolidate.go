package app

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

// consolidate merges what the outside view (live probes) and the inside view
// (engine map) found about the same hole into one finding, keeps only
// minimal forged-trait sets, and gives every finding a readable title. One
// hole, one finding, with every method that independently confirmed it.
// Finally every finding is linked to its root cause (AssignRootCauses).
func (a *App) consolidate(r *model.Report) {
	tokens := map[string]string{} // identity token -> masked identifier
	for _, id := range a.Cfg.TestIdentities {
		h := sha256.Sum256([]byte(id))
		tokens["test-"+hex.EncodeToString(h[:])] = maskIdentifier(id)
	}
	var out []model.Finding
	groups := map[string]int{}
	supersets := map[string]int{}
	fs := append([]model.Finding(nil), r.Findings...)
	// Minimal trait sets first, so supersets can be recognised and dropped.
	sort.SliceStable(fs, func(i, j int) bool { return len(fs[i].Traits) < len(fs[j].Traits) })
	minimal := map[string][]map[string]string{} // env|flag -> kept trait sets
	for _, f := range fs {
		switch f.Type {
		case model.FIdentityTraitLeak:
			if m, ok := tokens[f.Subject]; ok {
				f.Subject = m
				f.Title = fmt.Sprintf("Traits of %s are readable by anyone with the public client key", m)
			}
		case model.FIdentityOverrideLeak:
			if len(f.Unlocked) > 0 {
				f.Subject = f.Unlocked[0].Flag
				f.Title = fmt.Sprintf("Identity override on %s is readable by anyone who knows the identifier", f.Subject)
			}
		case model.FTraitForgery:
			flag := firstFlag(f)
			k := f.Environment + "|" + flag
			if isSuperset(f.Traits, minimal[k]) {
				supersets[k]++
				continue
			}
			minimal[k] = append(minimal[k], f.Traits)
		case model.FVariantReroll:
			if hasType(fs, model.FExperimentRigging, f.Environment, firstFlag(f)) {
				f.Type = model.FExperimentRigging // merged into the experiment finding below
			}
		}
		key := groupKey(f)
		if i, ok := groups[key]; ok {
			out[i] = merge(out[i], f)
			continue
		}
		groups[key] = len(out)
		out = append(out, f)
	}
	for i := range out {
		f := &out[i]
		if strings.HasPrefix(f.Title, string(f.Type)+":") {
			f.Title = genericTitle(*f)
		}
		if f.Type == model.FTraitForgery {
			if n := supersets[f.Environment+"|"+firstFlag(*f)]; n > 0 {
				f.Notes = append(f.Notes, fmt.Sprintf("%d larger trait combinations also unlock it; only the minimal input is reported.", n))
			}
			f.Title = forgeryTitle(*f)
			f.ID = model.MakeFindingID(f.Type, f.Environment, firstFlag(*f), traitString(f.Traits))
		}
	}
	r.Findings = out
	AssignRootCauses(r)
}

// groupKey identifies "the same hole" across outside and inside findings.
func groupKey(f model.Finding) string {
	switch f.Type {
	case model.FTraitForgery:
		return "forge|" + f.Environment + "|" + firstFlag(f) + "|" + traitString(f.Traits)
	case model.FPercentageReroll, model.FVariantReroll, model.FExperimentRigging, model.FIdentityOverrideLeak:
		return string(f.Type) + "|" + f.Environment + "|" + firstFlag(f)
	default:
		return string(f.Type) + "|" + f.Environment + "|" + f.Subject
	}
}

// merge folds b into a: union of methods, evidence and notes; the inside
// view's segment name and the experiment escalation win.
func merge(a, b model.Finding) model.Finding {
	// The inside view carries the segment, rollout rate, experiment name and
	// a readable title, so it is the base; the outside view adds its proof.
	if hasMethod(b, model.MethodEngine) && !hasMethod(a, model.MethodEngine) {
		a, b = b, a
	}
	if b.Type == model.FExperimentRigging {
		a.Type = model.FExperimentRigging
	}
	a.DetectedBy = mergeMethods(a.DetectedBy, b.DetectedBy)
	a.Evidence = append(a.Evidence, b.Evidence...)
	a.Notes = dedupeStrings(append(a.Notes, b.Notes...))
	a.Confirmed = a.Confirmed || b.Confirmed
	if a.Status != model.StatusExploitable && b.Status == model.StatusExploitable {
		a.Status = model.StatusExploitable
	}
	if a.Repro == "" {
		a.Repro = b.Repro
	}
	if a.ProofID == "" {
		a.ProofID = b.ProofID
	}
	if a.Category == "" {
		a.Category = b.Category
	}
	if seg := segmentOf(b); seg != "" && segmentOf(a) == "" {
		a.Subject = b.Subject
	}
	if a.Variants == nil {
		a.Variants = b.Variants
	}
	if a.HitRate == 0 {
		a.HitRate, a.Attempts = b.HitRate, b.Attempts
	}
	return a
}

// segmentOf returns the segment name an inside-view forgery carries.
func segmentOf(f model.Finding) string {
	if f.Type == model.FTraitForgery && f.Subject != firstFlag(f) {
		return f.Subject
	}
	return ""
}

func hasMethod(f model.Finding, m model.Method) bool {
	for _, x := range f.DetectedBy {
		if x == m {
			return true
		}
	}
	return false
}

func forgeryTitle(f model.Finding) string {
	t := fmt.Sprintf("Forging %s unlocks %s", traitString(f.Traits), firstFlag(f))
	if seg := segmentOf(f); seg != "" {
		t += fmt.Sprintf(" (segment %q)", seg)
	}
	return t
}

// genericTitle replaces "TYPE: subject" titles with plain English.
func genericTitle(f model.Finding) string {
	flag := firstFlag(f)
	switch f.Type {
	case model.FPercentageReroll:
		return fmt.Sprintf("Re-rolling the identifier unlocks %s", flag)
	case model.FVariantReroll:
		return fmt.Sprintf("Users can choose their %s variant by re-rolling their identifier", flag)
	case model.FExperimentRigging:
		return fmt.Sprintf("Users can pick their own group in the %s experiment", flag)
	}
	return f.Title
}

func firstFlag(f model.Finding) string {
	if len(f.Unlocked) > 0 {
		return f.Unlocked[0].Flag
	}
	return f.Subject
}

// isSuperset reports whether t strictly contains any kept trait set.
func isSuperset(t map[string]string, kept []map[string]string) bool {
	for _, k := range kept {
		if len(k) >= len(t) {
			continue
		}
		all := true
		for key, v := range k {
			if t[key] != v {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

func hasType(fs []model.Finding, t model.FindingType, env, flag string) bool {
	for _, f := range fs {
		if f.Type == t && f.Environment == env && firstFlag(f) == flag {
			return true
		}
	}
	return false
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// Root-cause mechanisms. A root cause is one fixable thing: every finding
// that the same single fix would close shares it.
const (
	// MechClientTraits: the environment accepts traits written by clients.
	MechClientTraits = "client-traits"
	// MechSensitiveData: the environment returns stored identity data to client keys.
	MechSensitiveData = "identity-data"
	// MechClientVisible: a flag with sensitive content is served to browsers.
	MechClientVisible = "client-visible-flag"
	// MechIdentifier: the browser chooses the identifier that decides a flag.
	MechIdentifier = "client-chosen-identifier"
	// MechBundleKey: a server-side key ships in the JavaScript bundle.
	MechBundleKey = "bundle-server-key"
	// MechControl: a control that held (never a way in).
	MechControl = "control"
)

// AssignRootCauses links every finding of r to exactly one root cause and
// rebuilds r.RootCauses. It is deterministic and idempotent, so it can also
// upgrade a report written before root causes existed.
//
// Settings findings are causes, not separate ways in: "client traits are
// allowed" shares its root cause with every forgery it enables, and "sensitive
// data is visible" with every identity leak. A setting with nothing exploiting
// it is the only member of its root cause, which report.Summarize then counts
// as hardening instead of a way in.
func AssignRootCauses(r *model.Report) {
	type group struct {
		cause   model.RootCause
		members []model.Finding
	}
	byID := map[string]*group{}
	var order []string
	for i := range r.Findings {
		f := &r.Findings[i]
		mech, env, subject := rootCauseKey(*f)
		id := model.MakeRootCauseID(mech, env, subject)
		f.RootCause = id
		g := byID[id]
		if g == nil {
			g = &group{cause: model.RootCause{ID: id, Mechanism: mech, Environment: env, Subject: subject}}
			byID[id] = g
			order = append(order, id)
		}
		g.members = append(g.members, *f)
		g.cause.FindingIDs = append(g.cause.FindingIDs, f.ID)
	}
	r.RootCauses = make([]model.RootCause, 0, len(order))
	for _, id := range order {
		g := byID[id]
		g.cause.Title = rootCauseTitle(g.cause, g.members)
		r.RootCauses = append(r.RootCauses, g.cause)
	}
}

// rootCauseKey names the one fixable thing behind a finding.
func rootCauseKey(f model.Finding) (mechanism, env, subject string) {
	env = f.Environment
	switch f.Type {
	case model.FSettingClientTraitsOn:
		return MechClientTraits, env, ""
	case model.FTraitForgery, model.FSegmentForgeable:
		if len(f.Traits) > 0 {
			return MechClientTraits, env, ""
		}
		if f.ProofID != "" {
			return MechIdentifier, env, firstFlag(f)
		}
	case model.FIdentityTraitLeak, model.FIdentityOverrideLeak, model.FSettingSensitiveData:
		return MechSensitiveData, env, ""
	case model.FSecretExposed, model.FInternalURL, model.FUnreleasedProduct, model.FPricingLeak, model.FPIILeak, model.FFlagNotServerOnly:
		if f.Type == model.FSecretExposed && f.Subject == "bundle" {
			return MechBundleKey, env, ""
		}
		return MechClientVisible, env, f.Subject
	case model.FPercentageReroll, model.FVariantReroll, model.FExperimentRigging:
		return MechIdentifier, env, firstFlag(f)
	case model.FControlOK:
		return MechControl, env, f.ID
	}
	// Anything else is its own root cause.
	return strings.ToLower(string(f.Type)), env, f.Subject + "|" + f.ID
}

// leakWords says what a client-visible flag contains, worst first.
var leakWords = []struct {
	t    model.FindingType
	cat  model.Category
	what string
}{
	{model.FSecretExposed, model.CatSecret, "a live secret"},
	{model.FPIILeak, model.CatPII, "personal data"},
	{model.FInternalURL, model.CatInternalURL, "an internal URL"},
	{model.FPricingLeak, model.CatPricing, "pricing data"},
	{model.FUnreleasedProduct, model.CatUnreleasedProduct, "an unreleased product name"},
}

func rootCauseTitle(c model.RootCause, members []model.Finding) string {
	env := nonEmpty(c.Environment, "The environment")
	switch c.Mechanism {
	case MechClientTraits:
		return env + " lets clients set traits"
	case MechSensitiveData:
		return env + " returns stored identity data to anyone holding the client key"
	case MechBundleKey:
		return "A server-side Flagsmith key ships in the JavaScript bundle"
	case MechIdentifier:
		for _, f := range members {
			if f.Type == model.FExperimentRigging {
				return fmt.Sprintf("Browsers choose the identifier that decides their group in the %s experiment", c.Subject)
			}
		}
		return fmt.Sprintf("Browsers choose the identifier that decides %s", c.Subject)
	case MechClientVisible:
		confirmed := false
		for _, f := range members {
			confirmed = confirmed || f.Status != model.StatusNeedsReview
		}
		for _, w := range leakWords {
			for _, f := range members {
				if f.Type == w.t || (f.Type == model.FFlagNotServerOnly && f.Category == w.cat) {
					if !confirmed {
						return fmt.Sprintf("%s is served to browsers and may contain %s (unconfirmed)", c.Subject, w.what)
					}
					return fmt.Sprintf("%s is served to browsers and contains %s", c.Subject, w.what)
				}
			}
		}
		return fmt.Sprintf("%s is served to browsers and looks sensitive", c.Subject)
	}
	if len(members) > 0 {
		return members[0].Title
	}
	return c.Subject
}
