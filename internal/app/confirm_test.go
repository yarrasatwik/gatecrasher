package app

import (
	"context"
	"errors"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/audit"
	"github.com/yarrasatwik/gatecrasher/internal/config"
	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/report"
	"github.com/yarrasatwik/gatecrasher/internal/severity"
)

// A human confirmation is the only way (besides a deterministic rule) for an
// AI-only suggestion to become a finding, and it is written to the
// hash-chained audit log before the report changes.
func TestConfirmFindingIsRecordedInTheAuditLog(t *testing.T) {
	dir := t.TempDir()
	lg, err := audit.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := &App{Cfg: &config.Config{ReportDir: dir, StateDir: dir}, Log: lg}

	inv, classes := labInventory()
	out := adjudicate(classes, inv, "Production", labAuditDay, a.confirmedFindings())
	r := &model.Report{ID: "r-20261128-090000-abcdef", Environment: "Production", Classifications: out,
		Findings: leakFindings(out, inv, "Production")}
	severity.AssignAll(r.Findings)
	report.Finalize(r)
	before := report.WaysIn(r)
	if _, err := a.SaveReport(r); err != nil {
		t.Fatal(err)
	}
	id := model.MakeFindingID(model.FPricingLeak, "Production", "partner_portal")

	got, err := a.ConfirmFinding(context.Background(), r.ID, id, "dana")
	if err != nil {
		t.Fatal(err)
	}
	if report.WaysIn(got) != before+1 {
		t.Fatalf("ways in %d → %d, want +1 after a human confirmed", before, report.WaysIn(got))
	}
	saved, err := a.LoadReport(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	f := findingFor(saved.Findings, "partner_portal")
	if f == nil || f.Status != model.StatusExploitable || f.Severity != model.SevMedium {
		t.Fatalf("saved finding = %+v", f)
	}

	entries, err := lg.Entries()
	if err != nil || len(entries) != 1 {
		t.Fatalf("audit entries = %d, %v", len(entries), err)
	}
	e := entries[0]
	var d map[string]any
	if err := e.Decode(&d); err != nil {
		t.Fatal(err)
	}
	if e.Action != audit.ActionConfirmFinding || e.Actor != "dana" || d["finding"] != id || d["report"] != r.ID || d["channel"] != "web" {
		t.Fatalf("audit entry = %+v %v", e, d)
	}
	if ok, at, err := lg.Verify(); !ok || err != nil {
		t.Fatalf("audit chain broken at %d: %v", at, err)
	}

	// The same item cannot be confirmed twice, and nothing else can be at all.
	if _, err := a.ConfirmFinding(context.Background(), r.ID, id, "dana"); !errors.Is(err, ErrNotReviewable) {
		t.Fatalf("second confirm: %v", err)
	}
	nightjar := model.MakeFindingID(model.FUnreleasedProduct, "Production", "project_nightjar_launch_2026_12_15")
	if _, err := a.ConfirmFinding(context.Background(), r.ID, nightjar, "dana"); !errors.Is(err, ErrNotReviewable) {
		t.Fatalf("confirming a deterministic finding: %v", err)
	}
	if entries, _ := lg.Entries(); len(entries) != 1 {
		t.Fatalf("refused confirmations must not be logged as confirmations: %d entries", len(entries))
	}

	// The next audit remembers the decision from the audit log.
	_, classes = labInventory()
	again := adjudicate(classes, inv, "Production", labAuditDay, a.confirmedFindings())
	if c := classOf(again, "partner_portal"); c.NeedsReview || c.Method != model.MethodHuman {
		t.Fatalf("next audit forgot the confirmation: %+v", c)
	}
}
