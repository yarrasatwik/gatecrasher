package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/report/reporttest"
	"github.com/yarrasatwik/gatecrasher/internal/severity"
)

const reviewID = "GC-REVIEW01"

// reviewReport is the sample report plus one thing only the AI suggested.
func reviewReport() *model.Report {
	r := reporttest.SampleReport()
	r.Findings = append(r.Findings, model.Finding{
		ID: reviewID, Type: model.FPricingLeak, Environment: reporttest.Env, Subject: "partner_portal",
		Title: "Pricing data visible to every browser: partner_portal (suggested by Claude, needs review)", Category: model.CatPricing,
		DetectedBy: []model.Method{model.MethodAI}, Status: model.StatusNeedsReview,
		Evidence: []model.Evidence{{Kind: "request", Note: "Looks like a partner pricing tier."}},
	})
	severity.AssignAll(r.Findings)
	return r
}

func TestCountsExcludeNeedsReviewInEveryFormat(t *testing.T) {
	base, with := reporttest.SampleReport(), reviewReport()
	severity.AssignAll(base.Findings)
	Finalize(base)
	Finalize(with)
	if WaysIn(with) != WaysIn(base) {
		t.Fatalf("ways in changed from %d to %d by an AI-only suggestion", WaysIn(base), WaysIn(with))
	}
	for sev, n := range base.Stats.BySeverity {
		if with.Stats.BySeverity[sev] != n {
			t.Fatalf("severity total %s changed from %d to %d", sev, n, with.Stats.BySeverity[sev])
		}
	}
	if tl := Count(with); tl.Review != 1 || tl.Found != Count(base).Found {
		t.Fatalf("tally = %+v", tl)
	}
	with.BeforeAfter = nil // the sample's before/after rows are illustrative and not tied to its statuses
	if err := CheckTally(with); err != nil {
		t.Fatal(err)
	}

	var compact compactReport
	if err := json.Unmarshal([]byte(render(t, func(b *bytes.Buffer) error { return WriteCompactJSON(b, with) })), &compact); err != nil {
		t.Fatal(err)
	}
	if compact.WaysIn != WaysIn(base) || compact.Review != 1 {
		t.Fatalf("compact ways_in=%d needs_review=%d", compact.WaysIn, compact.Review)
	}
	status := ""
	for _, f := range compact.Findings {
		if f.ID == reviewID {
			status = f.Status
		}
	}
	if status != "NEEDS_REVIEW" {
		t.Fatalf("review item status in JSON = %q, want NEEDS_REVIEW", status)
	}
}

func TestReviewSectionIsSeparate(t *testing.T) {
	r := reviewReport()
	md := render(t, func(b *bytes.Buffer) error { return WriteMarkdown(b, r) })
	i, j := strings.Index(md, "## Claude suggests reviewing"), strings.Index(md, "partner_portal")
	if i < 0 || j < i {
		t.Fatalf("markdown lacks the review section before the suggestion (section %d, item %d)", i, j)
	}
	if !strings.Contains(md, "Not counted") || !strings.Contains(md, "Looks like a partner pricing tier.") {
		t.Error("markdown review section lacks the not-counted note or the AI's reason")
	}
	if k := strings.Index(md, "## Findings"); k < 0 || k > i {
		t.Error("review section must come after the findings")
	}

	page := render(t, func(b *bytes.Buffer) error { return WriteHTML(b, r) })
	for _, want := range []string{`id="review"`, "Claude suggests reviewing", "Not counted", "NEEDS REVIEW", "Looks like a partner pricing tier."} {
		if !strings.Contains(page, want) {
			t.Errorf("html lacks %q", want)
		}
	}
	findings := page[strings.Index(page, `<section id="findings"`):strings.Index(page, `<section id="review"`)]
	if strings.Contains(findings, "partner_portal") {
		t.Error("the suggestion is rendered among the findings")
	}
}

func TestSARIFReportsReviewItemsAsNotes(t *testing.T) {
	var log sarifLog
	if err := json.Unmarshal([]byte(render(t, func(b *bytes.Buffer) error { return WriteSARIF(b, reviewReport()) })), &log); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, res := range log.Runs[0].Results {
		if res.PartialFingerprints[fingerprintKey] != reviewID {
			continue
		}
		found = true
		if res.Level != "note" || res.Properties["status"] != "NEEDS_REVIEW" || res.Properties["security-severity"] != "0.0" {
			t.Fatalf("review result = level %q props %v", res.Level, res.Properties)
		}
		if !strings.Contains(res.Message.Text, "needs review") {
			t.Fatalf("message = %q", res.Message.Text)
		}
	}
	if !found {
		t.Fatal("review item missing from SARIF")
	}
	// A review item alone never raises a rule's default level.
	r := &model.Report{ID: "r-only-review", Findings: []model.Finding{reviewReport().Findings[0]}}
	for i := range r.Findings {
		r.Findings[i] = model.Finding{ID: reviewID, Type: model.FSecretExposed, Subject: "x", Status: model.StatusNeedsReview, Category: model.CatSecret}
	}
	severity.AssignAll(r.Findings)
	if err := json.Unmarshal([]byte(render(t, func(b *bytes.Buffer) error { return WriteSARIF(b, r) })), &log); err != nil {
		t.Fatal(err)
	}
	if lvl := log.Runs[0].Results[0].Level; lvl != "note" {
		t.Fatalf("AI-only secret suggestion level = %q, want note", lvl)
	}
}
