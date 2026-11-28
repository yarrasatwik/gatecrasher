package app

import (
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/report"
)

// Identifier forgery is a way in under the "browser chooses the identifier"
// root cause. A possible secret (a value that only looks random) is a LOW
// finding that needs review: it has a root cause but is never a way in.
func TestIdentifierForgeryAndPossibleSecretRootCauses(t *testing.T) {
	r := &model.Report{ID: "r", Findings: []model.Finding{
		{ID: "GC-IDF", Type: model.FIdentifierForgery, Environment: "Production", Subject: "internal_tools", Severity: model.SevCritical,
			Status: model.StatusExploitable, ProofID: "x@acmeshop.dev", DetectedBy: []model.Method{model.MethodEngine, model.MethodProbe},
			Unlocked: []model.FlagChange{{Flag: "internal_tools", Before: "off", After: "on"}}},
		{ID: "GC-ROLL", Type: model.FPercentageReroll, Environment: "Production", Subject: "internal_tools", Severity: model.SevMedium,
			Status: model.StatusExploitable, Unlocked: []model.FlagChange{{Flag: "internal_tools", Before: "off", After: "on"}}},
		{ID: "GC-PS", Type: model.FPossibleSecret, Environment: "Production", Subject: "build_token", Severity: model.SevLow,
			Category: model.CatPossibleSecret, Status: model.StatusExploitable, DetectedBy: []model.Method{model.MethodDeterministic}},
		{ID: "GC-PS2", Type: model.FPossibleSecret, Environment: "Production", Subject: "payment_config", Severity: model.SevLow,
			Category: model.CatPossibleSecret, Status: model.StatusExploitable},
		{ID: "GC-SEC", Type: model.FSecretExposed, Environment: "Production", Subject: "payment_config", Severity: model.SevCritical,
			Category: model.CatSecret, Status: model.StatusExploitable},
	}}
	AssignRootCauses(r)
	report.Finalize(r)
	byFinding := map[string]model.RootCause{}
	for _, c := range r.RootCauses {
		for _, id := range c.FindingIDs {
			byFinding[id] = c
		}
	}
	for _, f := range r.Findings {
		if f.RootCause == "" || byFinding[f.ID].ID != f.RootCause {
			t.Fatalf("%s has no root cause", f.ID)
		}
	}
	idf := byFinding["GC-IDF"]
	if idf.Mechanism != MechIdentifier || !idf.Exploitable || byFinding["GC-ROLL"].ID != idf.ID {
		t.Fatalf("identifier forgery root cause = %+v", idf)
	}
	ps := byFinding["GC-PS"]
	if ps.Exploitable || ps.Title != "build_token is served to browsers and may contain a secret (needs review)" {
		t.Fatalf("possible-secret root cause = %+v", ps)
	}
	if c := byFinding["GC-PS2"]; c.ID != byFinding["GC-SEC"].ID || !c.Exploitable || c.Title != "payment_config is served to browsers and contains a live secret" {
		t.Fatalf("possible secret next to a real one = %+v", c)
	}
	if r.WaysIn != 2 || r.FindingCount != 5 {
		t.Fatalf("%s, want 2 ways in · 5 findings", report.Headline(r))
	}
	kinds := map[string]string{}
	for _, g := range report.GroupByRootCause(r) {
		kinds[g.Cause.ID] = g.Kind
	}
	if kinds[ps.ID] != "needs review" || kinds[idf.ID] != "way in" {
		t.Fatalf("kinds = %v", kinds)
	}
}
