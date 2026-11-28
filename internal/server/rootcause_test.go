package server

import (
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

// The web UI shows the same "N ways in · M findings" headline as every other
// surface and lists findings under their root cause.
func TestWebUIGroupsFindingsUnderRootCauses(t *testing.T) {
	h := newHarness(t, nil)
	rep := sampleReport("R1")
	// A setting and the forgery it enables share one root cause.
	rep.Findings = append(rep.Findings, model.Finding{ID: "GC-EEEE5555", Type: model.FSettingClientTraitsOn, Severity: model.SevMedium,
		Title: "Client traits are allowed", Environment: "Production", Status: model.StatusExploitable, RootCause: "RC-TRAITS"})
	rep.Findings[0].RootCause = "RC-TRAITS"
	rep.RootCauses = []model.RootCause{{ID: "RC-TRAITS", Title: "Production lets clients set traits"}}
	h.fb.reports["R1"] = rep

	sum := SummarizeReport(rep)
	if sum.WaysIn != 2 || sum.Findings != 3 || sum.Headline != "2 ways in · 3 findings" {
		t.Fatalf("summary = %+v", sum)
	}
	_, page, _ := h.get("/report/R1")
	contains(t, page, "2 ways in · 3 findings", `id="rc-RC-TRAITS"`, "Production lets clients set traits",
		"way in", "2 findings", "root cause <code>RC-TRAITS</code>", "Client traits are allowed", "Controls that held")
	_, page, _ = h.get("/")
	contains(t, page, "2 ways in · 3 findings")
	_, page, _ = h.get("/plans")
	contains(t, page, "R1 - 2 ways in · 3 findings")
}
