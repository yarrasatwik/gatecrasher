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
