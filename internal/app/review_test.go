package app

import (
	"strings"
	"testing"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/report"
	"github.com/yarrasatwik/gatecrasher/internal/secrets"
	"github.com/yarrasatwik/gatecrasher/internal/severity"
)

var labAuditDay = time.Date(2026, 11, 28, 9, 0, 0, 0, time.UTC)

// labInventory is the public flag list of the lab, with what the AI said in
// the recorded run: early_access_ai "looks unreleased" (confidence 0.7).
func labInventory() (*model.PublicInventory, []model.Classification) {
	inv := &model.PublicInventory{APIURL: "http://localhost:8000/api/v1", Flags: []model.FlagView{
		{Name: "early_access_ai"},
		{Name: "project_nightjar_launch_2026_12_15"},
		{Name: "banner_text", Enabled: true, RawValue: "Free shipping this week"},
		{Name: "partner_portal", RawValue: "v2"},
		{Name: "stealth_checkout"},
	}}
	classes := make([]model.Classification, len(inv.Flags))
	for i, f := range inv.Flags {
		classes[i] = secrets.Classify(f)
	}
	ai := func(i int, cat model.Category, why string) {
		classes[i] = model.Classification{Flag: inv.Flags[i].Name, Category: cat, Confidence: 0.7, Rationale: why, Method: model.MethodAI}
	}
	ai(0, model.CatUnreleasedProduct, "Name reveals an early-access AI feature that is likely unreleased.")
	ai(3, model.CatPricing, "Looks like a partner pricing tier.")
	return inv, classes
}

func classOf(cs []model.Classification, flag string) model.Classification {
	for _, c := range cs {
		if c.Flag == flag {
			return c
		}
	}
	return model.Classification{}
}

func findingFor(fs []model.Finding, flag string) *model.Finding {
	for i := range fs {
		if fs[i].Subject == flag {
			return &fs[i]
		}
	}
	return nil
}

func TestNightjarIsConfirmedByADeterministicRule(t *testing.T) {
	inv, classes := labInventory()
	out := adjudicate(classes, inv, "Production", labAuditDay, nil)
	c := classOf(out, "project_nightjar_launch_2026_12_15")
	if c.Category != model.CatUnreleasedProduct || c.Method != model.MethodDeterministic || c.NeedsReview {
		t.Fatalf("nightjar classification = %+v", c)
	}
	fs := leakFindings(out, inv, "Production")
	f := findingFor(fs, "project_nightjar_launch_2026_12_15")
	if f == nil || f.Type != model.FUnreleasedProduct || f.Status != model.StatusExploitable || !f.Confirmed {
		t.Fatalf("nightjar finding = %+v", f)
	}
	// The new word rules find what the value scanner does not.
	if c := classOf(out, "stealth_checkout"); c.Category != model.CatUnreleasedProduct || c.Method != model.MethodDeterministic || c.NeedsReview {
		t.Fatalf("stealth_checkout = %+v", c)
	}
}

func TestAIOnlyClassificationNeedsReview(t *testing.T) {
	inv, classes := labInventory()
	out := adjudicate(classes, inv, "Production", labAuditDay, nil)
	for _, flag := range []string{"early_access_ai", "partner_portal"} {
		c := classOf(out, flag)
		if !c.NeedsReview || c.Method != model.MethodAI {
			t.Fatalf("%s: AI-only classification must need review: %+v", flag, c)
		}
	}
	fs := leakFindings(out, inv, "Production")
	f := findingFor(fs, "partner_portal")
	if f == nil || f.Status != model.StatusNeedsReview || f.Confirmed || f.Type != model.FPricingLeak {
		t.Fatalf("partner_portal finding = %+v", f)
	}
	if len(f.DetectedBy) != 1 || f.DetectedBy[0] != model.MethodAI {
		t.Fatalf("detected_by = %v", f.DetectedBy)
	}
	// AI-only categories never steer the deterministic stages.
	cls := trustedCategories(out)
	if _, ok := cls["partner_portal"]; ok {
		t.Fatalf("an unconfirmed AI category leaked into the deterministic stages: %v", cls)
	}
	if cls["project_nightjar_launch_2026_12_15"] != model.CatUnreleasedProduct {
		t.Fatalf("trusted categories = %v", cls)
	}
}

// The lab's early_access_ai is a live 10% rollout: real users already get
// it, so it is not an unreleased product, whatever the AI thinks of the name.
func TestEarlyAccessAIIsNotReportedUnreleased(t *testing.T) {
	inv, classes := labInventory()
	out := adjudicate(classes, inv, "Production", labAuditDay, nil)
	r := &model.Report{Environment: "Production", Classifications: out, Findings: leakFindings(out, inv, "Production")}
	cls := trustedCategories(out)
	// What the attack and map stages add: the rollout, proven live.
	r.Findings = append(r.Findings,
		model.Finding{ID: "GC-ROLL", Type: model.FPercentageReroll, Subject: "early_access_ai", Environment: "Production",
			Status: model.StatusExploitable, Category: model.CatUnreleasedProduct,
			Unlocked: []model.FlagChange{{Flag: "early_access_ai", Before: "off", After: "on"}}},
		model.Finding{ID: "GC-NSO", Type: model.FFlagNotServerOnly, Subject: "early_access_ai", Environment: "Production",
			Status: model.StatusExploitable, Category: model.CatUnreleasedProduct})
	cls["early_access_ai"] = model.CatUnreleasedProduct
	dropLiveUnreleased(r, cls)

	for _, f := range r.Findings {
		if f.Subject != "early_access_ai" {
			continue
		}
		if f.Type == model.FUnreleasedProduct || f.Type == model.FFlagNotServerOnly {
			t.Fatalf("early_access_ai still reported as unreleased: %s %s", f.Type, f.Status)
		}
		if f.Category == model.CatUnreleasedProduct {
			t.Fatalf("%s still carries the unreleased category", f.Type)
		}
	}
	if findingFor(r.Findings, "early_access_ai") == nil {
		t.Fatal("the re-roll finding itself must stay")
	}
	if _, ok := cls["early_access_ai"]; ok {
		t.Fatal("category map still says unreleased")
	}
	c := classOf(r.Classifications, "early_access_ai")
	if c.Category != model.CatHarmless || c.NeedsReview || !strings.Contains(c.Rationale, "live") {
		t.Fatalf("classification = %+v", c)
	}
	if len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "early_access_ai") {
		t.Fatalf("notes = %v", r.Notes)
	}
	if findingFor(r.Findings, "project_nightjar_launch_2026_12_15") == nil {
		t.Fatal("nightjar is not live and must still be reported")
	}
	dropLiveUnreleased(r, cls)
	if len(r.Notes) != 1 {
		t.Fatalf("second pass must change nothing: %v", r.Notes)
	}
}

func TestOnByDefaultFlagIsNotUnreleased(t *testing.T) {
	inv := &model.PublicInventory{Flags: []model.FlagView{{Name: "project_atlas", Enabled: true}, {Name: "project_borealis"}}}
	classes := []model.Classification{secrets.Classify(inv.Flags[0]), secrets.Classify(inv.Flags[1])}
	out := adjudicate(classes, inv, "Production", labAuditDay, nil)
	if c := classOf(out, "project_atlas"); c.Category != model.CatHarmless || c.NeedsReview {
		t.Fatalf("a flag that is on for everyone is released: %+v", c)
	}
	if c := classOf(out, "project_borealis"); c.Category != model.CatUnreleasedProduct {
		t.Fatalf("project_borealis = %+v", c)
	}
}

func TestStaleDateAloneIsNotUnreleased(t *testing.T) {
	inv := &model.PublicInventory{Flags: []model.FlagView{{Name: "sale_2024_11_25"}, {Name: "sale_2027_11_25"}}}
	classes := []model.Classification{secrets.Classify(inv.Flags[0]), secrets.Classify(inv.Flags[1])}
	out := adjudicate(classes, inv, "Production", labAuditDay, nil)
	if c := classOf(out, "sale_2024_11_25"); c.Category != model.CatHarmless {
		t.Fatalf("a past date is not a launch: %+v", c)
	}
	if c := classOf(out, "sale_2027_11_25"); c.Category != model.CatUnreleasedProduct || c.Method != model.MethodDeterministic {
		t.Fatalf("a future date is: %+v", c)
	}
}

func TestHumanConfirmationPromotesAReviewItem(t *testing.T) {
	inv, classes := labInventory()
	id := model.MakeFindingID(model.FPricingLeak, "Production", "partner_portal")
	out := adjudicate(classes, inv, "Production", labAuditDay, nil)
	fs := leakFindings(out, inv, "Production")
	f := findingFor(fs, "partner_portal")
	if f.ID != id {
		t.Fatalf("review finding id %s, want the stable %s", f.ID, id)
	}
	r := &model.Report{Environment: "Production", Classifications: out, Findings: fs}
	if err := confirmFinding(r, id, "dana"); err != nil {
		t.Fatal(err)
	}
	f = findingFor(r.Findings, "partner_portal")
	if f.Status != model.StatusExploitable || !f.Confirmed || f.DetectedBy[len(f.DetectedBy)-1] != model.MethodHuman {
		t.Fatalf("confirmed finding = %+v", f)
	}
	if strings.Contains(f.Title, "needs review") || classOf(r.Classifications, "partner_portal").NeedsReview {
		t.Fatalf("still marked for review: %q", f.Title)
	}
	if err := confirmFinding(r, id, "dana"); err == nil {
		t.Fatal("confirming twice must fail")
	}
	if err := confirmFinding(r, "GC-NOPE", "dana"); err == nil {
		t.Fatal("confirming an unknown finding must fail")
	}
	// A later audit remembers the human decision.
	_, classes = labInventory()
	again := adjudicate(classes, inv, "Production", labAuditDay, map[string]string{id: "dana"})
	if c := classOf(again, "partner_portal"); c.NeedsReview || c.Method != model.MethodHuman {
		t.Fatalf("remembered confirmation = %+v", c)
	}
	if c := classOf(again, "early_access_ai"); !c.NeedsReview {
		t.Fatalf("other review items stay in review: %+v", c)
	}
}

func TestCountsExcludeNeedsReview(t *testing.T) {
	inv, classes := labInventory()
	out := adjudicate(classes, inv, "Production", labAuditDay, nil)
	r := &model.Report{ID: "r-test", Environment: "Production", Classifications: out, Findings: leakFindings(out, inv, "Production")}
	severity.AssignAll(r.Findings)
	report.Finalize(r)
	review, confirmed := 0, 0
	for _, f := range r.Findings {
		if f.Status == model.StatusNeedsReview {
			review++
			if f.Severity != model.SevInfo {
				t.Fatalf("review item %s rated %s; the AI must not set a severity", f.ID, f.Severity)
			}
		} else {
			confirmed++
		}
	}
	if review != 2 || confirmed != 2 {
		t.Fatalf("review=%d confirmed=%d, want 2 and 2", review, confirmed)
	}
	if got := report.WaysIn(r); got != confirmed {
		t.Fatalf("ways in = %d, want %d (review items are not ways in)", got, confirmed)
	}
	tl := report.Count(r)
	if tl.Found != confirmed || tl.Review != review {
		t.Fatalf("tally = %+v", tl)
	}
	total := 0
	for _, n := range r.Stats.BySeverity {
		total += n
	}
	if total != confirmed {
		t.Fatalf("severity totals count %d findings, want %d", total, confirmed)
	}
	if r.CountAtOrAbove(model.SevInfo) != confirmed {
		t.Fatalf("CountAtOrAbove counts review items")
	}
}
