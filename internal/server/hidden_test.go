package server

import (
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

// A HIDDEN finding is shown as open in the report view and the plan card,
// and a Server-side only plan lists a re-roll finding only as partially
// mitigated.
func TestHiddenIsShownAsOpenInTheWebUI(t *testing.T) {
	h := newHarness(t, nil)
	rep := sampleReport("R1")
	rep.Findings[1].Status = model.StatusHidden
	h.fb.reports["R1"] = rep
	if got := WaysIn(rep); got != 2 {
		t.Fatalf("WaysIn = %d, want 2 (HIDDEN is still open)", got)
	}
	_, page, _ := h.get("/report/R1")
	contains(t, page, "status-hidden", "HIDDEN (still open)", "2 ways in")

	rec := samplePlan("P1", false, false, model.PlanApplied)
	rec.Plan.PartiallyMitigated = []string{"GC-BBBB2222"}
	rec.Verify = []model.VerifyRow{
		{FindingID: "GC-AAAA1111", Title: "Forgeable segment", Before: model.StatusExploitable, After: model.StatusBlocked, Proof: "gone"},
		{FindingID: "GC-BBBB2222", Title: "Re-roll", Before: model.StatusExploitable, After: model.StatusHidden, Proof: "still split", PartiallyMitigated: true},
	}
	h.fb.addPlan(rec)
	_, page, _ = h.get("/plans")
	contains(t, page, "Partially mitigated, not closed", `href="/report/R1#f-GC-BBBB2222"`, "status-hidden", "HIDDEN (still open)")
	_, page, _ = h.get("/plans?finding=GC-BBBB2222")
	contains(t, page, "Showing plans for finding")
}
