package mapper

import (
	"fmt"
	"sort"

	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

// ForgeableFindings turns reachable segment overrides into SEGMENT_FORGEABLE
// findings. Overrides that are forgeable are EXPLOITABLE; those whose
// forgeability is unknown are reported as UNKNOWN, never as safe. Overrides
// that are not forgeable, and environment-level variants, produce nothing.
func ForgeableFindings(reach []model.Reachable, opts Options) []model.Finding {
	var out []model.Finding
	for _, r := range reach {
		if r.Segment == "" || r.Forgeable == "no" {
			continue
		}
		out = append(out, forgeableFinding(r, opts))
	}
	return out
}

func forgeableFinding(r model.Reachable, opts Options) model.Finding {
	cat := opts.Classifications[r.Flag]
	status, confirmed := model.StatusExploitable, true
	if r.Forgeable != "yes" {
		status, confirmed = model.StatusUnknown, false
	}
	sev := model.SevMedium
	if cat == model.CatSecret || cat == model.CatSecurityControl || cat == model.CatPricing {
		sev = model.SevHigh
	}
	before := flagsmith.Flag{Enabled: r.DefaultEnabled, Value: r.DefaultValue}.State()
	after := flagsmith.Flag{Enabled: r.Enabled, Value: r.Value}.State()
	note := redact.String(fmt.Sprintf("Flagsmith's engine serves %s instead of %s for flag %q to an identity with %s (segment %q; forgeable: %s).",
		after, before, r.Flag, describeInput(r), r.Segment, r.Forgeable))
	return model.Finding{
		ID:   model.MakeFindingID(model.FSegmentForgeable, r.Environment, r.Segment, r.Flag, after),
		Type: model.FSegmentForgeable, Severity: sev,
		Title:       fmt.Sprintf("Segment %q can be forged to change flag %q", r.Segment, r.Flag),
		Environment: r.Environment, Subject: r.Segment, Category: cat,
		DetectedBy: []model.Method{model.MethodEngine}, Confirmed: confirmed, Status: status,
		Traits: r.ForgedTraits, ProofID: r.Identifier,
		Unlocked: []model.FlagChange{{Flag: r.Flag, Before: before, After: after}},
		Evidence: []model.Evidence{{Kind: "engine", Note: note}},
	}
}

func describeInput(r model.Reachable) string {
	keys := make([]string, 0, len(r.ForgedTraits))
	for k := range r.ForgedTraits {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	s := ""
	for _, k := range keys {
		s += fmt.Sprintf("%s=%q ", k, r.ForgedTraits[k])
	}
	if r.Identifier != "" {
		s += fmt.Sprintf("identifier=%q ", r.Identifier)
	}
	if s == "" {
		return "no forged input"
	}
	return "trait/identifier " + s[:len(s)-1]
}
