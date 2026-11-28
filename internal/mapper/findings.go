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
// An override reached purely by choosing an identifier a segment rule accepts
// is reported as IDENTIFIER_FORGERY instead: no trait is forged, so turning
// off client traits does not close it.
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
	if identifierOnly(r) {
		return identifierFinding(r, opts)
	}
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

// identifierOnly reports whether r is reached by choosing an identifier that
// a segment rule accepts, with no forged trait at all.
func identifierOnly(r model.Reachable) bool {
	return r.IdentifierExample != "" && len(r.ForgedTraits) == 0 && r.Forgeable == "yes"
}

// IdentifierForgeryTitle is the headline of an IDENTIFIER_FORGERY finding.
func IdentifierForgeryTitle(identifier, flag string) string {
	return fmt.Sprintf("Choosing identifier %s unlocks %s — this survives turning off client traits.", identifier, flag)
}

// IdentifierSurvivesNote explains why the client-traits setting does not
// close an identifier forgery.
const IdentifierSurvivesNote = "Choosing an identifier is not affected by the \"Allow client SDKs to set user traits\" setting: " +
	"the segment tests the identifier itself, and the client still picks its own identifier after that setting is turned off."

// identifierFinding reports a segment that targets the identifier's own
// value (for example a REGEX on $.identity.identifier). No trait is forged,
// so the client-traits setting has no effect on it.
func identifierFinding(r model.Reachable, opts Options) model.Finding {
	before := flagsmith.Flag{Enabled: r.DefaultEnabled, Value: r.DefaultValue}.State()
	after := flagsmith.Flag{Enabled: r.Enabled, Value: r.Value}.State()
	note := redact.String(fmt.Sprintf("Flagsmith's engine serves %s instead of %s for flag %q to any identity whose identifier matches segment %q, for example %q. No trait is involved.",
		after, before, r.Flag, r.Segment, r.IdentifierExample))
	notes := []string{
		fmt.Sprintf("Segment %q targets the identifier itself; the browser chooses its own identifier.", r.Segment),
		IdentifierSurvivesNote,
	}
	if r.Identifier != r.IdentifierExample {
		notes = append(notes, fmt.Sprintf("Live probes use the transient identifier %s, which matches the same rule, so no real user's identity is touched.", r.Identifier))
	}
	return model.Finding{
		ID:   model.MakeFindingID(model.FIdentifierForgery, r.Environment, r.Flag, r.Segment),
		Type: model.FIdentifierForgery, Severity: model.SevHigh,
		Title:       redact.String(IdentifierForgeryTitle(r.IdentifierExample, r.Flag)),
		Environment: r.Environment, Subject: r.Segment, Category: opts.Classifications[r.Flag],
		DetectedBy: []model.Method{model.MethodEngine}, Confirmed: true, Status: model.StatusExploitable,
		ProofID:  r.Identifier,
		Unlocked: []model.FlagChange{{Flag: r.Flag, Before: before, After: after}},
		Evidence: []model.Evidence{{Kind: "engine", Note: note}},
		Notes:    notes,
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
