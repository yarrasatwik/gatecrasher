package fixes

import (
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

func TestDraftDetailStoresDiffOnPRDraftStep(t *testing.T) {
	h := newHarness(t)
	pl := h.planner(shopApp(t))
	pl.detail = func(f model.Finding, impact []model.ImpactItem) Draft {
		return Draft{Text: "Title\n\nBody", Diff: "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n", Note: ""}
	}
	plans, err := pl.Plan(t.Context(), []model.Finding{traitFinding()})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, o := range plans[0].Operations {
		if o.Kind != OpPRDraft {
			if o.Diff != "" {
				t.Fatalf("diff on a %s step", o.Kind)
			}
			continue
		}
		found = true
		if o.Draft != "Title\n\nBody" || o.Diff != "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n" || o.DiffNote != "" {
			t.Fatalf("%+v", o)
		}
	}
	if !found {
		t.Fatal("no pr.draft operation")
	}
}

func TestDraftDetailNoteIsStored(t *testing.T) {
	h := newHarness(t)
	pl := h.planner(shopApp(t))
	pl.detail = func(model.Finding, []model.ImpactItem) Draft {
		return Draft{Text: "prose", Note: "diff did not apply; not shown"}
	}
	plans, err := pl.Plan(t.Context(), []model.Finding{traitFinding()})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range plans[0].Operations {
		if o.Kind == OpPRDraft && (o.Diff != "" || o.DiffNote != "diff did not apply; not shown") {
			t.Fatalf("%+v", o)
		}
	}
}
