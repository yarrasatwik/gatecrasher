package app

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/report"
)

func recordedReport(t *testing.T) *model.Report {
	t.Helper()
	raw, err := os.ReadFile("../../examples/acme-shop/report.json")
	if err != nil {
		t.Fatal(err)
	}
	var r model.Report
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return &r
}

// On the recorded lab report every finding has exactly one root cause, and no
// two root causes describe the same flag and mechanism.
func TestRecordedReportRootCauses(t *testing.T) {
	r := recordedReport(t)
	AssignRootCauses(r)
	report.Finalize(r)

	causes := map[string]model.RootCause{}
	keys := map[string]string{}
	for _, c := range r.RootCauses {
		if _, dup := causes[c.ID]; dup {
			t.Fatalf("root cause %s listed twice", c.ID)
		}
		causes[c.ID] = c
		key := c.Mechanism + "|" + c.Environment + "|" + c.Subject
		if other, dup := keys[key]; dup {
			t.Fatalf("root causes %s and %s both describe %s", other, c.ID, key)
		}
		keys[key] = c.ID
		if c.Title == "" || len(c.FindingIDs) == 0 {
			t.Fatalf("root cause %+v is empty", c)
		}
	}
	member := map[string]int{}
	for _, c := range r.RootCauses {
		for _, id := range c.FindingIDs {
			member[id]++
		}
	}
	for _, f := range r.Findings {
		if _, ok := causes[f.RootCause]; !ok {
			t.Errorf("finding %s links to unknown root cause %q", f.ID, f.RootCause)
		}
		if member[f.ID] != 1 {
			t.Errorf("finding %s is in %d root causes, want exactly 1", f.ID, member[f.ID])
		}
	}

	title := func(findingID string) string {
		for _, f := range r.Findings {
			if f.ID == findingID {
				return causes[f.RootCause].Title
			}
		}
		return ""
	}
	// The three forgeries and the setting that enables them are one way in.
	traits := title("GC-A60CCA1A")
	if traits != "Production lets clients set traits" {
		t.Fatalf("client-traits root cause title = %q", traits)
	}
	for _, id := range []string{"GC-70850605", "GC-1A45D85C", "GC-688647D2"} {
		if title(id) != traits {
			t.Errorf("forgery %s is not under the client-traits root cause", id)
		}
	}
	// The secret and "not Server-side only" on the same flag are one thing to fix.
	if got := title("GC-8B6A1273"); got != "payment_config is served to browsers and contains a live secret" || title("GC-0B5C5F67") != got {
		t.Fatalf("payment_config root cause = %q / %q", got, title("GC-0B5C5F67"))
	}
	// Identity leaks share the "sensitive data visible" setting as their cause.
	if title("GC-914405C1") != title("GC-9FE52BC7") || title("GC-58B8A822") != title("GC-9FE52BC7") {
		t.Error("identity leaks are not grouped with the hide_sensitive_data setting")
	}

	if r.FindingCount != 18 || r.WaysIn != 8 {
		t.Fatalf("recorded report: %d ways in · %d findings, want 8 · 18", r.WaysIn, r.FindingCount)
	}
	exploitable := 0
	for _, c := range r.RootCauses {
		if c.Exploitable {
			exploitable++
		}
	}
	if exploitable != r.WaysIn {
		t.Fatalf("ways_in %d != exploitable root causes %d", r.WaysIn, exploitable)
	}
	for i := 1; i < len(r.RootCauses); i++ {
		if r.RootCauses[i-1].Severity < r.RootCauses[i].Severity {
			t.Fatalf("root causes not sorted by severity at %d", i)
		}
	}
	if err := report.CheckTally(r); err != nil {
		t.Fatal(err)
	}

	// Idempotent, and stable through a JSON round trip.
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	var back model.Report
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	AssignRootCauses(&back)
	report.Finalize(&back)
	if back.WaysIn != r.WaysIn || len(back.RootCauses) != len(r.RootCauses) || back.RootCauses[0].ID != r.RootCauses[0].ID {
		t.Fatal("root causes changed on a second pass")
	}
	var raw map[string]any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if raw["ways_in"] != float64(8) || raw["finding_count"] != float64(18) || raw["open_count"] != float64(18) || raw["blocked_count"] != float64(0) {
		t.Fatalf("JSON contract: ways_in=%v finding_count=%v open=%v blocked=%v", raw["ways_in"], raw["finding_count"], raw["open_count"], raw["blocked_count"])
	}
	rc := raw["root_causes"].([]any)[0].(map[string]any)
	for _, k := range []string{"id", "title", "severity", "finding_ids", "exploitable"} {
		if _, ok := rc[k]; !ok {
			t.Errorf("root_causes[0] lacks %q", k)
		}
	}
	if f := raw["findings"].([]any)[0].(map[string]any); f["root_cause"] == "" || f["root_cause"] == nil {
		t.Error("findings[0] lacks root_cause")
	}
}

// A setting nothing exploits is hardening, not a way in; once an exploit it
// enables is reproduced it is the cause of that way in, not a second one.
func TestSettingIsHardeningUntilSomethingExploitsIt(t *testing.T) {
	setting := model.Finding{ID: "GC-SET", Type: model.FSettingClientTraitsOn, Environment: "Production", Subject: "allow_client_traits",
		Status: model.StatusExploitable, Severity: model.SevLow, DetectedBy: []model.Method{model.MethodSettings}}
	r := &model.Report{ID: "r1", Findings: []model.Finding{setting}}
	AssignRootCauses(r)
	report.Finalize(r)
	if r.WaysIn != 0 || r.FindingCount != 1 || len(r.RootCauses) != 1 || r.RootCauses[0].Exploitable {
		t.Fatalf("lone setting: %d ways in, causes %+v", r.WaysIn, r.RootCauses)
	}
	if got := report.Headline(r); got != "0 ways in · 1 finding" {
		t.Fatalf("headline = %q", got)
	}

	forge := model.Finding{ID: "GC-FORGE", Type: model.FTraitForgery, Environment: "Production", Subject: "admins",
		Status: model.StatusExploitable, Severity: model.SevCritical, Traits: map[string]string{"role": "admin"},
		DetectedBy: []model.Method{model.MethodEngine, model.MethodProbe}, Unlocked: []model.FlagChange{{Flag: "admin_panel"}}}
	r = &model.Report{ID: "r2", Findings: []model.Finding{setting, forge}}
	AssignRootCauses(r)
	report.Finalize(r)
	if r.WaysIn != 1 || r.FindingCount != 2 || len(r.RootCauses) != 1 || r.RootCauses[0].Severity != model.SevCritical {
		t.Fatalf("setting + exploit: %d ways in · %d findings, causes %+v", r.WaysIn, r.FindingCount, r.RootCauses)
	}
	if got := report.Headline(r); got != "1 way in · 2 findings" {
		t.Fatalf("headline = %q", got)
	}

	// Blocking every finding closes the way in; HIDDEN keeps it open.
	r.Findings[0].Status, r.Findings[1].Status = model.StatusBlocked, model.StatusHidden
	report.Finalize(r)
	if r.WaysIn != 1 {
		t.Fatalf("HIDDEN must keep the root cause open, ways in = %d", r.WaysIn)
	}
	r.Findings[0].Status, r.Findings[1].Status = model.StatusBlocked, model.StatusBlocked
	report.Finalize(r)
	if r.WaysIn != 0 || r.OpenCount != 0 || r.BlockedCount != 2 {
		t.Fatalf("all blocked: ways in %d open %d blocked %d", r.WaysIn, r.OpenCount, r.BlockedCount)
	}
}

func TestReviewItemsAndControlsAreNeverWaysIn(t *testing.T) {
	r := &model.Report{ID: "r3", Findings: []model.Finding{
		{ID: "GC-REV", Type: model.FPricingLeak, Environment: "Production", Subject: "partner_portal", Status: model.StatusNeedsReview},
		{ID: "GC-OK", Type: model.FControlOK, Environment: "Production", Subject: "Staging", Status: model.StatusBlocked},
	}}
	AssignRootCauses(r)
	report.Finalize(r)
	if r.WaysIn != 0 || r.FindingCount != 0 || r.ReviewCount != 1 {
		t.Fatalf("ways in %d findings %d review %d", r.WaysIn, r.FindingCount, r.ReviewCount)
	}
	for _, f := range r.Findings {
		if f.RootCause == "" {
			t.Fatalf("%s has no root cause", f.ID)
		}
	}
	for _, c := range r.RootCauses {
		if c.Exploitable {
			t.Fatalf("%q must not be exploitable", c.Title)
		}
		if c.Mechanism == MechClientVisible && !strings.Contains(c.Title, "unconfirmed") {
			t.Fatalf("review-only root cause title = %q", c.Title)
		}
	}
}
