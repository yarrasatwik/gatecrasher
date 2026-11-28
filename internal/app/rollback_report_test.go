package app

import (
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

// After a rollback, findings the plan had blocked are open again in the report.
func TestRevertVerifiedRestoresStatuses(t *testing.T) {
	r := &model.Report{
		Findings: []model.Finding{{ID: "GC-1", Status: model.StatusBlocked}, {ID: "GC-2", Status: model.StatusBlocked}},
		BeforeAfter: []model.VerifyRow{
			{FindingID: "GC-1", Before: model.StatusExploitable, After: model.StatusBlocked},
			{FindingID: "GC-2", Before: model.StatusExploitable, After: model.StatusBlocked},
		},
	}
	if !revertVerified(r, []string{"GC-1"}) {
		t.Fatal("nothing reverted")
	}
	if r.Findings[0].Status != model.StatusExploitable || r.Findings[1].Status != model.StatusBlocked {
		t.Fatalf("statuses %s %s", r.Findings[0].Status, r.Findings[1].Status)
	}
	if len(r.BeforeAfter) != 1 || r.BeforeAfter[0].FindingID != "GC-2" {
		t.Fatalf("rows %+v", r.BeforeAfter)
	}
}
