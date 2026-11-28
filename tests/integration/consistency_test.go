//go:build lab

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/report"
)

// TestFixAllStatusesMatchNextAudit applies every automatic plan the way
// fix-all does, then additionally marks the re-rollable flag Server-side
// only (the "fix" that used to be reported as BLOCKED). Every finding's
// status after the re-attack must equal its status in the next audit:
// BLOCKED findings are gone, and the re-roll finding is HIDDEN in both.
func TestFixAllStatusesMatchNextAudit(t *testing.T) {
	reset(t)
	defer reset(t)
	a := newApp(t)
	ctx := context.Background()
	before := fullAudit(t, a, 0)
	roll := find(before, expectation{[]model.FindingType{model.FPercentageReroll}, "early_access_ai"})
	if roll == nil {
		t.Fatal("re-roll finding on early_access_ai not found")
	}
	recs, err := a.MakePlans(ctx, "latest", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range recs {
		for _, id := range rec.Plan.FindingsAddressed {
			if id == roll.ID && hasAuto(rec.Plan) {
				t.Fatalf("plan %q claims to fix the re-roll finding with an automatic change", rec.Plan.Title)
			}
		}
		if !hasAuto(rec.Plan) {
			continue
		}
		if _, err := a.Approve(rec.Plan.ID, "it", "cli", rec.Plan.Environment, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := a.Apply(ctx, rec.Plan.ID); err != nil {
			t.Fatalf("apply %s: %v", rec.Plan.ID, err)
		}
		if _, err := a.Verify(ctx, rec.Plan.ID, "it"); err != nil {
			t.Fatal(err)
		}
	}

	// Hide the rollout flag without removing the rollout.
	p, _, err := a.Project(ctx)
	if err != nil {
		t.Fatal(err)
	}
	feats, err := a.Admin.Features(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	featID := 0
	for _, f := range feats {
		if f.Name == "early_access_ai" {
			featID = f.ID
		}
	}
	if err := a.Admin.Do(ctx, "PATCH", fmt.Sprintf("projects/%d/features/%d/", p.ID, featID), map[string]any{"is_server_key_only": true}, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(25 * time.Second) // SDK environment cache

	afterFix, err := a.LoadReport("latest")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]model.Status{}
	for _, f := range afterFix.Findings {
		want[f.ID] = f.Status
	}
	st, proof, err := a.Recheck(ctx, *roll)
	if err != nil {
		t.Fatal(err)
	}
	if st != model.StatusHidden {
		t.Fatalf("re-roll fixed only by Server-side only = %s, want HIDDEN (%s)", st, proof)
	}
	want[roll.ID] = st

	next := fullAudit(t, a, 0)
	if err := report.CheckTally(next); err != nil {
		t.Fatal(err)
	}
	got := map[string]model.Status{}
	for _, f := range next.Findings {
		got[f.ID] = f.Status
	}
	for id, w := range want {
		g, present := got[id]
		switch {
		case w == model.StatusBlocked && present && g != model.StatusBlocked:
			t.Errorf("%s: BLOCKED after the fix but %s in the next audit", id, g)
		case w != model.StatusBlocked && !present:
			t.Errorf("%s: %s after the fix but missing from the next audit", id, w)
		case w != model.StatusBlocked && g != w:
			t.Errorf("%s: %s after the fix but %s in the next audit", id, w, g)
		}
	}
	for id, g := range got {
		if _, known := want[id]; !known && g != model.StatusBlocked {
			t.Errorf("%s: open in the next audit (%s) but not in the report after the fix", id, g)
		}
	}
}
