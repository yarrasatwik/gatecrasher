package app

import (
	"strings"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/ai"
	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/secrets"
	"github.com/yarrasatwik/gatecrasher/internal/severity"
)

// Every category that creates a finding must map to a finding type with a title.
func TestEveryReportableCategoryHasALeakType(t *testing.T) {
	for _, cat := range model.AllCategories {
		if !ai.Reportable(model.Classification{Category: cat}) {
			continue
		}
		ft, ok := leakTypes[cat]
		if !ok || leakTitles[ft] == "" {
			t.Errorf("category %s has no finding type or title", cat)
		}
	}
}

// A value that is only random-looking becomes a LOW "needs review" finding,
// while a real credential stays CRITICAL.
func TestConfigLeakSeverityFromDetector(t *testing.T) {
	flags := []model.FlagView{
		{Name: "correlation_seed", RawValue: "q8Zx3Lk9PwR2tYv7NmB4cJd1"},
		{Name: "payment_config", RawValue: `{"provider":"acmepay","api_secret":"acme_live_9e107d9d372bb6826bd81d3542a419d6","webhook":"https://internal.acmeshop.dev/pay"}`},
		{Name: "build_commit", RawValue: "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"},
		{Name: "stripe_key", RawValue: "pk_live_51H8xYzAbCdEfGhIjKlMnOpQr"},
	}
	inv := &model.PublicInventory{APIURL: "http://flags.test/api/v1/", Flags: flags}
	var findings []model.Finding
	for _, f := range flags {
		if c := secrets.Classify(f); ai.Reportable(c) {
			findings = append(findings, configLeak(c, inv, "Production"))
		}
	}
	severity.AssignAll(findings)
	if len(findings) != 2 {
		t.Fatalf("want 2 findings (possible secret + payment_config), got %d: %+v", len(findings), findings)
	}
	possible, secret := findings[0], findings[1]
	if possible.Type != model.FPossibleSecret || possible.Severity != model.SevLow || !strings.Contains(possible.Title, "needs review") {
		t.Fatalf("possible secret finding = %s %s %q", possible.Type, possible.Severity, possible.Title)
	}
	if secret.Type != model.FSecretExposed || secret.Severity != model.SevCritical {
		t.Fatalf("payment_config finding = %s %s", secret.Type, secret.Severity)
	}
}
