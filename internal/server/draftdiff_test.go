package server

import (
	"strings"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

func draftPlan(diff, note string) model.PlanRecord {
	rec := samplePlan("PD", false, false, model.PlanPending)
	for i := range rec.Plan.Operations {
		if rec.Plan.Operations[i].Kind == "pr.draft" {
			rec.Plan.Operations[i].Draft = "Send plan from the server\n\nMoves the trait."
			rec.Plan.Operations[i].Diff = diff
			rec.Plan.Operations[i].DiffNote = note
		}
	}
	return rec
}

func TestPlanCardShowsDiffEscapedAndColoured(t *testing.T) {
	diff := "--- a/app.js\n+++ b/app.js\n@@ -1,3 +1,3 @@\n const a = 1;\n-flagsmith.setTrait(\"plan\", v);\n+el.innerHTML = '<b>x</b>'; // key acme_live_0123456789abcdef0123\n const b = 2;\n"
	h := newHarness(t, nil)
	h.fb.addPlan(draftPlan(diff, ""))
	_, page, _ := h.get("/plans")
	contains(t, page,
		"<details><summary>PR draft</summary>",
		`class="dl d-del"`, `class="dl d-add"`, `class="dl d-hunk"`, `class="dl d-file"`, `class="dl d-ctx"`,
		`-flagsmith.setTrait(&#34;plan&#34;, v);`,
		`+el.innerHTML = &#39;&lt;b&gt;x&lt;/b&gt;&#39;`,
		"Guidance only, never executed")
	notContains(t, page, "<b>x</b>", "acme_live_0123456789abcdef0123")
}

func TestPlanCardShowsDiffNoteInsteadOfBrokenDiff(t *testing.T) {
	h := newHarness(t, nil)
	h.fb.addPlan(draftPlan("", "diff did not apply; not shown"))
	_, page, _ := h.get("/plans")
	contains(t, page, "<details><summary>PR draft</summary>", "diff did not apply; not shown", "Moves the trait.")
	if strings.Contains(page, `class="dl `) {
		t.Fatal("no diff lines expected")
	}
}
