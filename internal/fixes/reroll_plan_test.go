package fixes

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

// A flag that both leaks a value and sits behind a re-rollable rollout gets
// two plans: Server-side only closes the leak, and the re-roll finding has
// its own guidance plan. The Server-side only plan may only say it partially
// mitigates the re-roll; it never claims to close it.
func TestPlannerNeverBundlesRerollIntoServerSideOnlyPlan(t *testing.T) {
	h := newHarness(t)
	leak := secretFinding()
	roll := model.Finding{ID: "GC-ROLL0001", Type: model.FPercentageReroll, Environment: "Production", Subject: "payment_config",
		Status: model.StatusExploitable, Title: "re-roll payment_config",
		Unlocked: []model.FlagChange{{Flag: "payment_config", Before: "off", After: "on"}}}
	plans, err := h.planner("").Plan(t.Context(), []model.Finding{leak, roll})
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 2 {
		t.Fatalf("want a Server-side only plan and a separate re-roll plan, got %d: %+v", len(plans), plans)
	}
	var serverOnly, guidance *model.Plan
	for i := range plans {
		if strings.HasPrefix(plans[i].TargetObject, "feature:") {
			serverOnly = &plans[i]
		} else {
			guidance = &plans[i]
		}
	}
	if serverOnly == nil || guidance == nil {
		t.Fatalf("plans = %+v", plans)
	}
	if got := strings.Join(serverOnly.FindingsAddressed, ","); got != leak.ID {
		t.Fatalf("Server-side only plan claims to fix %q; it may only close the leak", got)
	}
	if got := strings.Join(serverOnly.PartiallyMitigated, ","); got != roll.ID {
		t.Fatalf("Server-side only plan partially mitigates %q, want the re-roll finding", got)
	}
	for _, op := range serverOnly.Operations {
		if strings.Contains(op.Description, "assign Flagsmith identifiers") {
			t.Fatalf("re-roll guidance leaked into the Server-side only plan: %s", op.Description)
		}
	}
	if serverOnly.Hash != serverOnly.ComputeHash() || guidance.Hash != guidance.ComputeHash() {
		t.Fatal("plan hash does not cover the plan")
	}

	if guidance.TargetObject != "identifiers:payment_config" || !strings.Contains(guidance.Title, "identifiers on the server") {
		t.Fatalf("re-roll plan identity wrong: %q %q", guidance.TargetObject, guidance.Title)
	}
	if got := strings.Join(guidance.FindingsAddressed, ","); got != roll.ID {
		t.Fatalf("re-roll plan addresses %q", got)
	}
	if len(guidance.PartiallyMitigated) != 0 {
		t.Fatalf("guidance plan mitigates nothing by itself: %v", guidance.PartiallyMitigated)
	}
	kinds := strings.Join(opKinds(*guidance), ",")
	if !strings.HasPrefix(kinds, "pr.draft,manual") {
		t.Fatalf("re-roll plan = guidance + PR draft, got operations %s", kinds)
	}
	for _, op := range guidance.Operations {
		if op.Automatic {
			t.Fatalf("re-roll plan must change nothing in Flagsmith: %+v", op)
		}
	}
	joined, _ := json.Marshal(guidance.Operations)
	for _, want := range []string{"assign Flagsmith identifiers on the server", "does not stop re-rolling"} {
		if !strings.Contains(string(joined), want) {
			t.Fatalf("re-roll guidance misses %q: %s", want, joined)
		}
	}
}

// A HIDDEN re-roll finding is still open, so it still gets its guidance plan,
// and a flag that is already Server-side only gets no second feature plan.
func TestPlannerStillPlansHiddenReroll(t *testing.T) {
	h := newHarness(t)
	h.stub.features[5]["is_server_key_only"] = true
	roll := model.Finding{ID: "GC-ROLL0001", Type: model.FExperimentRigging, Environment: "Production", Subject: "payment_config", Status: model.StatusHidden}
	plans, err := h.planner("").Plan(t.Context(), []model.Finding{roll})
	if err != nil || len(plans) != 1 {
		t.Fatalf("plans=%d err=%v", len(plans), err)
	}
	if plans[0].TargetObject != "identifiers:payment_config" || len(plans[0].FindingsAddressed) != 1 {
		t.Fatalf("plan = %+v", plans[0])
	}
}
