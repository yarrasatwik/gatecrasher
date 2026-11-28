package verify

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

func TestRerun(t *testing.T) {
	secret := "ser." + strings.Repeat("ab", 12)
	findings := []model.Finding{
		{ID: "GC-1", Title: "forge plan", Status: model.StatusExploitable},
		{ID: "GC-2", Title: "leak", Status: model.StatusExploitable},
		{ID: "GC-3", Title: "still open", Status: model.StatusExploitable},
		{ID: "GC-9", Title: "not addressed", Status: model.StatusExploitable},
	}
	rec := &model.PlanRecord{Plan: model.Plan{FindingsAddressed: []string{"GC-1", "GC-2", "GC-3", "GC-404"}}}
	recheck := func(_ context.Context, f model.Finding) (model.Status, string, error) {
		switch f.ID {
		case "GC-1":
			return model.StatusBlocked, "POST identities -> plan unchanged " + secret, nil
		case "GC-2":
			return "", "", errors.New("connection refused " + secret)
		}
		return model.StatusExploitable, "still forgeable", nil
	}
	rows := Rerun(context.Background(), rec, findings, recheck)
	if len(rows) != 4 {
		t.Fatalf("rows = %d", len(rows))
	}
	if rows[0].Before != model.StatusExploitable || rows[0].After != model.StatusBlocked {
		t.Fatalf("row0 = %+v", rows[0])
	}
	if rows[1].After != model.StatusUnknown || !strings.Contains(rows[1].Proof, "re-check failed") {
		t.Fatalf("row1 = %+v", rows[1])
	}
	if rows[2].After != model.StatusExploitable {
		t.Fatalf("row2 = %+v", rows[2])
	}
	if rows[3].FindingID != "GC-404" || rows[3].After != model.StatusUnknown {
		t.Fatalf("row3 = %+v", rows[3])
	}
	for _, r := range rows {
		if strings.Contains(r.Proof, secret) {
			t.Fatalf("proof leaks a secret: %q", r.Proof)
		}
	}
	if AllBlocked(rows) || AllBlocked(nil) || !AllBlocked(rows[:1]) {
		t.Fatal("AllBlocked wrong")
	}
}

func TestRerunCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec := &model.PlanRecord{Plan: model.Plan{FindingsAddressed: []string{"GC-1"}}}
	rows := Rerun(ctx, rec, []model.Finding{{ID: "GC-1"}}, func(context.Context, model.Finding) (model.Status, string, error) {
		t.Fatal("recheck must not run after cancellation")
		return "", "", nil
	})
	if rows[0].After != model.StatusUnknown {
		t.Fatalf("got %+v", rows[0])
	}
}

// An identifier forgery re-checked after the client-traits fix still
// reproduces, and the row must say why that fix did not close it.
func TestRerunIdentifierForgeryStaysExploitableAfterClientTraitsOff(t *testing.T) {
	allowClientTraits := false // the client-traits fix has been applied
	findings := []model.Finding{
		{ID: "GC-TRAIT", Type: model.FTraitForgery, Title: "Forging role=admin unlocks admin_panel", Status: model.StatusExploitable,
			Traits: map[string]string{"role": "admin"}},
		{ID: "GC-IDF", Type: model.FIdentifierForgery, Status: model.StatusExploitable, ProofID: "gc-probe-a@acmeshop.dev",
			Title: "Choosing identifier a@acmeshop.dev unlocks internal_tools — this survives turning off client traits."},
	}
	rec := &model.PlanRecord{Plan: model.Plan{FindingsAddressed: []string{"GC-TRAIT", "GC-IDF"}}}
	// Stub of the live API: traits are ignored once the setting is off, the
	// identifier is still whatever the client sends.
	recheck := func(_ context.Context, f model.Finding) (model.Status, string, error) {
		if len(f.Traits) > 0 && !allowClientTraits {
			return model.StatusBlocked, "POST identities/ -> admin_panel is off", nil
		}
		return model.StatusExploitable, "POST identities/ -> internal_tools is on (exploited state on)", nil
	}
	rows := Rerun(context.Background(), rec, findings, recheck)
	if len(rows) != 2 {
		t.Fatalf("rows = %+v", rows)
	}
	if rows[0].After != model.StatusBlocked || strings.Contains(rows[0].Proof, "identifier") {
		t.Fatalf("trait forgery row = %+v", rows[0])
	}
	idf := rows[1]
	if idf.Before != model.StatusExploitable || idf.After != model.StatusExploitable {
		t.Fatalf("identifier forgery must stay EXPLOITABLE: %+v", idf)
	}
	if !strings.Contains(idf.Proof, "internal_tools is on") || !strings.Contains(idf.Proof, "not affected by the client-traits setting") || !strings.HasSuffix(idf.Proof, IdentifierStillOpen) {
		t.Fatalf("proof must keep the evidence and explain why it is still open: %q", idf.Proof)
	}
	if AllBlocked(rows) {
		t.Fatal("a surviving identifier forgery must keep the plan from counting as verified")
	}
}

func TestIdentifierProofOnlyExplainsOpenIdentifierForgeries(t *testing.T) {
	idf := model.Finding{Type: model.FIdentifierForgery}
	if got := identifierProof(idf, model.StatusBlocked, "flag is off"); got != "flag is off" {
		t.Errorf("blocked identifier forgery: %q", got)
	}
	if got := identifierProof(model.Finding{Type: model.FPercentageReroll}, model.StatusExploitable, "p"); got != "p" {
		t.Errorf("other types must be untouched: %q", got)
	}
	if got := identifierProof(idf, model.StatusExploitable, ""); got != IdentifierStillOpen {
		t.Errorf("empty proof: %q", got)
	}
}
