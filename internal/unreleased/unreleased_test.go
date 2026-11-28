package unreleased

import (
	"strings"
	"testing"
	"time"
)

var auditDay = time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)

func TestNightjarIsFoundDeterministically(t *testing.T) {
	r := Check("project_nightjar_launch_2026_12_15", auditDay)
	if !r.Match {
		t.Fatal("project_nightjar_launch_2026_12_15 must match the deterministic rules")
	}
	got := strings.Join(r.Signals, ",")
	for _, want := range []string{"codename:project_*", "codename:*_launch_*", "future_date:2026-12-15"} {
		if !strings.Contains(got, want) {
			t.Errorf("signals %q lack %q", got, want)
		}
	}
	// After the launch date the date is no longer a signal, the codename still is.
	later := Check("project_nightjar_launch_2026_12_15", time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC))
	if !later.Match || strings.Contains(strings.Join(later.Signals, ","), "future_date") {
		t.Fatalf("after launch: %+v", later)
	}
}

func TestEarlyAccessAIHasNoDeterministicSignal(t *testing.T) {
	if r := Check("early_access_ai", auditDay); r.Match {
		t.Fatalf("early_access_ai matched %v; only the AI thinks it is unreleased", r.Signals)
	}
}

func TestRules(t *testing.T) {
	cases := []struct {
		name string
		want string // one expected signal, "" for no match
	}{
		{"project_atlas", "codename:project_*"},
		{"checkout_launch_banner", "codename:*_launch_*"},
		{"new_codename_falcon", "codename:*_codename_*"},
		{"unreleased_pricing_table", "word:unreleased"},
		{"stealth_mode_ui", "word:stealth"},
		{"secret_santa_promo", "word:secret"},
		{"dashboard_internal_only", "word:internal_only"},
		{"spring_sale_2027_03_01", "future_date:2027-03-01"},
		{"roadmap_2027q1", "future_date:2027-01-01"},
		{"winter_sale_20270115", "future_date:2027-01-15"},

		{"spring_sale_2026_03_01", ""}, // the date has passed
		{"report_2026q3", ""},
		{"launch_checklist", ""},     // launch_* is not *_launch_*
		{"projector_mode", ""},       // not the word project
		{"api_secret", ""},           // a credential name, not a product
		{"stripe_secret_key", ""},    // same
		{"internal_tools", ""},       // internal alone is not internal_only
		{"maintenance_mode", ""},     // control flag
		{"banner_text", ""},          // control flag
		{"premium_export", ""},       // paid feature
		{"build_2031", ""},           // a number, not a date
		{"order_id_20991340", ""},    // month 13 is not a date
		{"feature_2026_11_28_x", ""}, // the audit day itself is not in the future
	}
	for _, c := range cases {
		r := Check(c.name, auditDay)
		if c.want == "" {
			if r.Match {
				t.Errorf("%s: unexpected match %v", c.name, r.Signals)
			}
			continue
		}
		if !r.Match || !strings.Contains(strings.Join(r.Signals, ","), c.want) {
			t.Errorf("%s: signals %v, want %s", c.name, r.Signals, c.want)
		}
	}
}
