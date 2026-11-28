package report

import (
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

// A "sensitive flag is not Server-side only" finding is hardening when it is
// only a setting, and a way in once a live read with the client key showed
// the flag is really served.
func TestSettingFindingIsAWayInOnlyWhenReproduced(t *testing.T) {
	f := model.Finding{ID: "GC-NSO", Type: model.FFlagNotServerOnly, Subject: "payment_config", Severity: model.SevHigh,
		Status: model.StatusExploitable, DetectedBy: []model.Method{model.MethodSettings}}
	r := &model.Report{ID: "r", Findings: []model.Finding{f}}
	if s := Summarize(r); s.WaysIn != 0 || s.Findings != 1 || s.RootCauses[0].Exploitable {
		t.Fatalf("setting only: %+v", s)
	}
	if g := GroupByRootCause(r); len(g) != 1 || g[0].Kind != "hardening" {
		t.Fatalf("groups = %+v", g)
	}
	r.Findings[0].DetectedBy = append(r.Findings[0].DetectedBy, model.MethodProbe)
	if s := Summarize(r); s.WaysIn != 1 {
		t.Fatalf("reproduced live: %+v", s)
	}
	if r.Findings[0].RootCause != "" || len(r.RootCauses) != 0 {
		t.Fatal("Summarize must not change the report")
	}
	if got := HeadlineOf(1, 1); got != "1 way in · 1 finding" {
		t.Fatalf("singular headline = %q", got)
	}
}
