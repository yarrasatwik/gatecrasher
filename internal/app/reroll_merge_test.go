package app

import (
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/config"
	"github.com/yarrasatwik/gatecrasher/internal/model"
)

// A boolean rollout reached by re-rolling is one hole: the "choose the
// variant" view must not survive as a second finding.
func TestVariantRerollFoldsIntoPercentageReroll(t *testing.T) {
	a := &App{Cfg: &config.Config{}}
	unlocked := []model.FlagChange{{Flag: "early_access_ai", Before: "off", After: "on"}}
	r := &model.Report{Findings: []model.Finding{
		{ID: "GC-AAAAAAAA", Type: model.FPercentageReroll, Environment: "Production", Subject: "early_access_ai", Unlocked: unlocked,
			Status: model.StatusExploitable, Severity: model.SevMedium, DetectedBy: []model.Method{model.MethodEngine}},
		{ID: "GC-BBBBBBBB", Type: model.FVariantReroll, Environment: "Production", Subject: "early_access_ai", Unlocked: unlocked,
			Status: model.StatusExploitable, Severity: model.SevMedium, DetectedBy: []model.Method{model.MethodEngine}},
	}}
	a.consolidate(r)
	n := 0
	for _, f := range r.Findings {
		if f.Subject == "early_access_ai" {
			n++
			if f.Type != model.FPercentageReroll {
				t.Errorf("kept type %s", f.Type)
			}
		}
	}
	if n != 1 {
		t.Fatalf("want one re-roll finding, got %d", n)
	}
}
