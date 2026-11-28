package app

import (
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/mapper"
	"github.com/yarrasatwik/gatecrasher/internal/model"
)

// An identifier forgery found by the engine must be matched to its live
// cross-check result, marked as reproduced, and keep its own type and title
// instead of being retyped as a percentage re-roll.
func TestIdentifierForgeryIsCrossCheckedAndKeepsItsType(t *testing.T) {
	reach := []model.Reachable{{
		Environment: "Production", Flag: "internal_tools", Enabled: true, Segment: "staff_by_identifier",
		Identifier: "gc-probe-a@acmeshop.dev", IdentifierExample: "a@acmeshop.dev", Forgeable: "yes", EngineVerified: true,
	}}
	fs := mapper.ForgeableFindings(reach, mapper.Options{Environment: "Production", ClientSetsIdentifier: true})
	if len(fs) != 1 {
		t.Fatalf("findings = %+v", fs)
	}
	f := fs[0]
	rc := reach[0]
	if got, want := findingKey(f), reachKey(rc.Environment, rc.Flag, rc.Segment, rc.ForgedTraits, rc.Identifier); got != want {
		t.Fatalf("finding key %q does not match the cross-check key %q", got, want)
	}
	title := f.Title
	live := liveResult{ok: true, repro: "curl -X POST .../identities/", evidence: model.Evidence{Kind: "request", Request: "POST identities/"}}
	markLive(&f, live)
	refine(&f, nil, map[string]string{}, true)
	if f.Type != model.FIdentifierForgery || f.Title != title {
		t.Fatalf("retyped or retitled: %s %q", f.Type, f.Title)
	}
	if f.Subject != "internal_tools" {
		t.Errorf("subject = %q, want the unlocked flag", f.Subject)
	}
	if !hasMethod(f, model.MethodProbe) || !hasMethod(f, model.MethodEngine) || !f.Confirmed || f.Status != model.StatusExploitable || f.Repro != live.repro {
		t.Errorf("not marked as reproduced live: %+v", f)
	}
	if autoFixable(f) {
		t.Error("no Flagsmith change closes an identifier forgery; apply must not wait for it to be blocked")
	}

	// A live API that disagrees with the engine downgrades it, as for any
	// other engine result.
	g := fs[0]
	markLive(&g, liveResult{ok: false})
	if g.Status != model.StatusUnknown || g.Confirmed {
		t.Errorf("unreproduced finding must be UNKNOWN and unconfirmed: %+v", g)
	}
}
