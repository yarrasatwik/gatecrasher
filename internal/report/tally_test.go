package report

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/report/reporttest"
)

// hiddenReport is the sample report after a "Server-side only" fix: the
// secret is BLOCKED and the re-roll finding on the same flag is only HIDDEN.
func hiddenReport() (*model.Report, string) {
	r := reporttest.SampleReport()
	var rollID string
	for i := range r.Findings {
		switch r.Findings[i].Type {
		case model.FSecretExposed:
			r.Findings[i].Status = model.StatusBlocked
		case model.FPercentageReroll:
			r.Findings[i].Status = model.StatusHidden
			rollID = r.Findings[i].ID
		}
	}
	r.BeforeAfter = []model.VerifyRow{
		{FindingID: r.Findings[0].ID, Title: "secret", Before: model.StatusExploitable, After: model.StatusBlocked, Proof: "not visible"},
		{FindingID: rollID, Title: "re-roll", Before: model.StatusExploitable, After: model.StatusHidden, Proof: "still split", PartiallyMitigated: true},
	}
	return r, rollID
}

func TestTallyFoundMinusBlockedIsRemaining(t *testing.T) {
	r, _ := hiddenReport()
	tl := Count(r)
	if tl.Found-tl.Blocked != tl.Remaining {
		t.Fatalf("found %d − blocked %d != remaining %d", tl.Found, tl.Blocked, tl.Remaining)
	}
	if tl.Blocked != 1 || tl.Hidden != 1 {
		t.Fatalf("tally = %+v, want 1 blocked and 1 hidden", tl)
	}
	if err := CheckTally(r); err != nil {
		t.Fatal(err)
	}
	// A status nobody accounts for must break the arithmetic, not vanish.
	r.Findings[3].Status = "FIXED_PROBABLY"
	if err := CheckTally(r); err == nil {
		t.Fatal("an unaccounted status must fail the tally")
	}
}

func TestTallyRejectsAReportThatDisagreesWithItsVerifyRows(t *testing.T) {
	r, rollID := hiddenReport()
	for i := range r.Findings {
		if r.Findings[i].ID == rollID {
			r.Findings[i].Status = model.StatusBlocked // the A1 bug: hidden reported as closed
		}
	}
	err := CheckTally(r)
	if err == nil || !strings.Contains(err.Error(), rollID) {
		t.Fatalf("a finding marked BLOCKED whose re-attack said HIDDEN must fail: %v", err)
	}
}

// The recorded lab report must satisfy the same arithmetic exactly, both as
// parsed by the tool and as raw JSON another tool would read.
func TestRecordedReportTally(t *testing.T) {
	raw, err := os.ReadFile("../../examples/acme-shop/report.json")
	if err != nil {
		t.Fatal(err)
	}
	var r model.Report
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	if err := CheckTally(&r); err != nil {
		t.Fatal(err)
	}
	var generic struct {
		Findings []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	found, blocked, remaining := 0, 0, 0
	for _, f := range generic.Findings {
		if f.Type == "CONTROL_OK" {
			continue
		}
		found++
		switch f.Status {
		case "BLOCKED":
			blocked++
		case "EXPLOITABLE", "HIDDEN", "UNKNOWN":
			remaining++
		}
	}
	tl := Count(&r)
	if found-blocked != remaining || found != tl.Found || blocked != tl.Blocked || remaining != tl.Remaining {
		t.Fatalf("recorded report: raw %d − %d = %d, tool says %+v", found, blocked, remaining, tl)
	}
}

func TestHiddenIsShownAndStaysOpenInEveryFormat(t *testing.T) {
	r, rollID := hiddenReport()
	Finalize(r)
	if r.OpenCount != Count(r).Remaining || r.OpenCount != r.FindingCount-1 {
		t.Fatalf("open = %d of %d, want everything but the one BLOCKED finding", r.OpenCount, r.FindingCount)
	}
	for _, c := range r.RootCauses {
		for _, id := range c.FindingIDs {
			if id == rollID && !c.Exploitable {
				t.Fatal("a HIDDEN finding must keep its root cause a way in")
			}
		}
	}

	md := render(t, func(b *bytes.Buffer) error { return WriteMarkdown(b, r) })
	if !strings.Contains(md, "HIDDEN (still open)") {
		t.Error("markdown does not show HIDDEN")
	}
	page := render(t, func(b *bytes.Buffer) error { return WriteHTML(b, r) })
	if !strings.Contains(page, "HIDDEN (still open)") {
		t.Error("html does not show HIDDEN")
	}

	var full model.Report
	if err := json.Unmarshal([]byte(render(t, func(b *bytes.Buffer) error { return WriteJSON(b, r) })), &full); err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, f := range full.Findings {
		seen = seen || (f.ID == rollID && f.Status == model.StatusHidden)
	}
	if !seen || !strings.Contains(render(t, func(b *bytes.Buffer) error { return WriteCompactJSON(b, r) }), `"status":"HIDDEN"`) {
		t.Error("json does not carry status HIDDEN")
	}

	var log sarifLog
	if err := json.Unmarshal([]byte(render(t, func(b *bytes.Buffer) error { return WriteSARIF(b, r) })), &log); err != nil {
		t.Fatal(err)
	}
	level := ""
	for _, res := range log.Runs[0].Results {
		if res.PartialFingerprints[fingerprintKey] == rollID {
			level = res.Level
			if res.Properties["status"] != "HIDDEN" {
				t.Errorf("sarif status property = %v", res.Properties["status"])
			}
		}
	}
	if level != "warning" {
		t.Fatalf("sarif level for a HIDDEN finding = %q, want warning (present, not passed)", level)
	}
}
