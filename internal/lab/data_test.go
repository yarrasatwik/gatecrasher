package lab

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func repoSeedData(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "lab", "seed_data.yaml")
}

func TestShippedSeedDataMatchesSpec(t *testing.T) {
	d, err := LoadData(repoSeedData(t))
	if err != nil {
		t.Fatal(err)
	}
	if d.Organisation != "Acme Labs" || d.Project != "Acme Shop" {
		t.Fatalf("org/project = %q/%q", d.Organisation, d.Project)
	}
	if !d.EnvironmentSettings.AllowClientTraits || d.EnvironmentSettings.HideSensitiveData {
		t.Fatalf("environment settings must be the vulnerable defaults: %+v", d.EnvironmentSettings)
	}
	if got := strings.Join(d.Environments, ","); got != "Development,Production" {
		t.Fatalf("environments = %s", got)
	}
	features := map[string]FeatureData{}
	for _, f := range d.Features {
		features[f.Name] = f
	}
	for _, name := range []string{"premium_export", "admin_panel", "staff_preview", "early_access_ai", "internal_tools", "pricing_page",
		"payment_config", "internal_api_url", "project_nightjar_launch_2026_12_15", "beta_dashboard", "maintenance_mode", "banner_text"} {
		if _, ok := features[name]; !ok {
			t.Errorf("feature %s missing", name)
		}
	}
	if len(d.Features) != 12 {
		t.Errorf("want 12 features, got %d", len(d.Features))
	}
	if o := features["internal_tools"]; o.DefaultEnabled || len(o.SegmentOverrides) != 1 || o.SegmentOverrides[0].Segment != "staff_by_identifier" || !o.SegmentOverrides[0].Enabled {
		t.Errorf("internal_tools = %+v", o)
	}
	var byID *SegmentData
	for i := range d.Segments {
		if d.Segments[i].Name == "staff_by_identifier" {
			byID = &d.Segments[i]
		}
	}
	want := ConditionData{Property: "$.identity.identifier", Operator: "REGEX", Value: `.*@acmeshop\.dev$`}
	if byID == nil || len(byID.Conditions) != 1 || byID.Conditions[0] != want {
		t.Errorf("staff_by_identifier = %+v, want one condition %+v", byID, want)
	}
	if !strings.Contains(features["payment_config"].Value, SecretPlaceholder) {
		t.Error("payment_config must use the secret placeholder, never a literal secret")
	}
	if p := features["pricing_page"]; !p.Multivariate || p.Experiment == nil || p.Value != "price_high" {
		t.Errorf("pricing_page = %+v", p)
	}
	if o := features["beta_dashboard"].IdentityOverrides; len(o) != 1 || o[0].Identifier != "ceo@acmeshop.dev" {
		t.Errorf("beta_dashboard overrides = %+v", o)
	}
	if tags := features["maintenance_mode"].Tags; len(tags) != 1 || tags[0] != "kill-switch" {
		t.Errorf("maintenance_mode tags = %v", tags)
	}
}

func TestSeedDataHasNoLiteralSecret(t *testing.T) {
	d, err := LoadData(repoSeedData(t))
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`acme_live_[0-9a-f]{8,}`)
	for _, f := range d.Features {
		if re.MatchString(f.Value) {
			t.Errorf("feature %s embeds a literal secret", f.Name)
		}
	}
}

func TestNewPaymentSecretFormat(t *testing.T) {
	re := regexp.MustCompile(`^acme_live_[0-9a-f]{32}$`)
	a, b := newPaymentSecret(), newPaymentSecret()
	if !re.MatchString(a) || a == b {
		t.Fatalf("secrets %q %q are malformed or equal", a, b)
	}
}

func TestRenderValue(t *testing.T) {
	got := RenderValue(`{"k":"`+SecretPlaceholder+`"}`, "acme_live_x")
	if got != `{"k":"acme_live_x"}` {
		t.Fatalf("got %s", got)
	}
}

func TestParseDataValidation(t *testing.T) {
	base := `organisation: O
project: P
admin_email: a@b.c
environments: [Dev]
`
	tests := []struct {
		name, extra, wantErr string
	}{
		{"minimal valid", "", ""},
		{"unknown field", "bogus: 1\n", "bogus"},
		{"missing org", "organisation: \"\"\n", "organisation"},
		{"bad email", "admin_email: nope\n", "admin_email"},
		{"segment without conditions", "segments: [{name: s}]\n", "segment"},
		{"override of unknown segment", "features:\n  - {name: f, segment_overrides: [{segment: ghost, enabled: true}]}\n", "unknown segment"},
		{"override of unknown identity", "features:\n  - {name: f, identity_overrides: [{identifier: ghost, enabled: true}]}\n", "unknown identity"},
		{"undeclared tag", "features:\n  - {name: f, tags: [t]}\n", "undeclared tag"},
		{"upper-case feature", "features:\n  - {name: Foo}\n", "lower case"},
		{"duplicate feature", "features:\n  - {name: f}\n  - {name: f}\n", "twice"},
		{"variants must sum to 100", "features:\n  - {name: f, multivariate: true, value: a, variants: [{value: a, percentage: 60}, {value: b, percentage: 60}]}\n", "100"},
		{"default must be a variant", "features:\n  - {name: f, multivariate: true, value: z, variants: [{value: a, percentage: 50}, {value: b, percentage: 50}]}\n", "not one of the variants"},
		{"variants without multivariate", "features:\n  - {name: f, variants: [{value: a, percentage: 100}]}\n", "multivariate"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := base
			if strings.HasPrefix(tc.extra, "organisation") || strings.HasPrefix(tc.extra, "admin_email") {
				key := strings.SplitN(tc.extra, ":", 2)[0]
				raw = regexp.MustCompile(`(?m)^`+key+`:.*\n`).ReplaceAllString(base, "")
			}
			_, err := ParseData([]byte(raw + tc.extra))
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("error %v does not contain %q", err, tc.wantErr)
			}
		})
	}
}
