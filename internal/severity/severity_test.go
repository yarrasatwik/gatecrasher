package severity

import (
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

func TestRate(t *testing.T) {
	tests := []struct {
		name string
		f    model.Finding
		ctx  Context
		want model.Severity
	}{
		{"secret", model.Finding{Type: model.FSecretExposed}, Context{}, model.SevCritical},
		{"forgery security control category", model.Finding{Type: model.FTraitForgery, Subject: "kill_switch", Category: model.CatSecurityControl}, Context{}, model.SevCritical},
		{"forgery admin name", model.Finding{Type: model.FTraitForgery, Subject: "Admin_Panel"}, Context{}, model.SevCritical},
		{"forgery staff name", model.Finding{Type: model.FTraitForgery, Subject: "staff_tools"}, Context{}, model.SevCritical},
		{"forgery internal name", model.Finding{Type: model.FTraitForgery, Subject: "internal_dashboard"}, Context{}, model.SevCritical},
		{"forgery superuser name", model.Finding{Type: model.FTraitForgery, Subject: "superuser_mode"}, Context{}, model.SevCritical},
		{"forgery root name", model.Finding{Type: model.FTraitForgery, Subject: "root_access"}, Context{}, model.SevCritical},
		{"forgery admin tag", model.Finding{Type: model.FTraitForgery, Subject: "tools", Tags: []string{"admin"}}, Context{}, model.SevCritical},
		{"forgery unlocks admin flag", model.Finding{Type: model.FTraitForgery, Subject: "vip", Unlocked: []model.FlagChange{{Flag: "admin_console"}}}, Context{}, model.SevCritical},
		{"forgery paid feature", model.Finding{Type: model.FTraitForgery, Subject: "premium_export"}, Context{}, model.SevHigh},
		{"identity trait leak", model.Finding{Type: model.FIdentityTraitLeak}, Context{}, model.SevHigh},
		{"pii", model.Finding{Type: model.FPIILeak}, Context{}, model.SevHigh},
		{"rigging price", model.Finding{Type: model.FExperimentRigging, Subject: "pricing_test"}, Context{}, model.SevHigh},
		{"rigging checkout", model.Finding{Type: model.FExperimentRigging, Subject: "new_checkout"}, Context{}, model.SevHigh},
		{"rigging discount", model.Finding{Type: model.FExperimentRigging, Subject: "discount_banner"}, Context{}, model.SevHigh},
		{"rigging plan", model.Finding{Type: model.FExperimentRigging, Subject: "plan_picker"}, Context{}, model.SevHigh},
		{"rigging pricing category", model.Finding{Type: model.FExperimentRigging, Subject: "offer", Category: model.CatPricing}, Context{}, model.SevHigh},
		{"rigging other", model.Finding{Type: model.FExperimentRigging, Subject: "button_color"}, Context{}, model.SevMedium},
		{"internal url", model.Finding{Type: model.FInternalURL}, Context{}, model.SevMedium},
		{"unreleased", model.Finding{Type: model.FUnreleasedProduct}, Context{}, model.SevMedium},
		{"percentage reroll", model.Finding{Type: model.FPercentageReroll}, Context{}, model.SevMedium},
		{"variant reroll", model.Finding{Type: model.FVariantReroll}, Context{}, model.SevMedium},
		{"identity override", model.Finding{Type: model.FIdentityOverrideLeak}, Context{}, model.SevMedium},
		{"segment forgeable", model.Finding{Type: model.FSegmentForgeable}, Context{}, model.SevMedium},
		{"pricing leak", model.Finding{Type: model.FPricingLeak}, Context{}, model.SevMedium},
		{"possible secret", model.Finding{Type: model.FPossibleSecret, Category: model.CatPossibleSecret}, Context{}, model.SevLow},
		{"possible secret never raised", model.Finding{Type: model.FPossibleSecret, Category: model.CatPossibleSecret}, Context{HoldsSecret: true, ForgeableSegments: true, LookupPossible: true}, model.SevLow},
		{"traits on, forgeable", model.Finding{Type: model.FSettingClientTraitsOn}, Context{ForgeableSegments: true}, model.SevMedium},
		{"traits on, none", model.Finding{Type: model.FSettingClientTraitsOn}, Context{}, model.SevLow},
		{"sensitive visible, no lookup", model.Finding{Type: model.FSettingSensitiveData}, Context{}, model.SevLow},
		{"sensitive visible, lookup", model.Finding{Type: model.FSettingSensitiveData}, Context{LookupPossible: true}, model.SevMedium},
		{"not server only, low", model.Finding{Type: model.FFlagNotServerOnly}, Context{}, model.SevLow},
		{"not server only, secret", model.Finding{Type: model.FFlagNotServerOnly}, Context{HoldsSecret: true}, model.SevHigh},
		{"control ok", model.Finding{Type: model.FControlOK}, Context{}, model.SevInfo},
		{"unknown type", model.Finding{Type: "SOMETHING_NEW"}, Context{}, model.SevMedium},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Rate(tc.f, tc.ctx); got != tc.want {
				t.Fatalf("Rate = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestAssignUsesTagsAndCategory(t *testing.T) {
	tests := []struct {
		name string
		f    model.Finding
		want model.Severity
	}{
		{"forgeable tag", model.Finding{Type: model.FSettingClientTraitsOn, Tags: []string{TagForgeableSegments}}, model.SevMedium},
		{"no tag", model.Finding{Type: model.FSettingClientTraitsOn}, model.SevLow},
		{"lookup tag", model.Finding{Type: model.FSettingSensitiveData, Tags: []string{TagLookupPossible}}, model.SevMedium},
		{"secret tag", model.Finding{Type: model.FFlagNotServerOnly, Tags: []string{TagHoldsSecret}}, model.SevHigh},
		{"secret category", model.Finding{Type: model.FFlagNotServerOnly, Category: model.CatSecret}, model.SevHigh},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.f
			Assign(&f)
			if f.Severity != tc.want {
				t.Fatalf("severity = %s, want %s", f.Severity, tc.want)
			}
		})
	}
}

func TestAssignAllContext(t *testing.T) {
	fs := []model.Finding{
		{ID: "1", Type: model.FSettingClientTraitsOn, Environment: "prod", Subject: "prod"},
		{ID: "2", Type: model.FSegmentForgeable, Environment: "prod", Subject: "beta"},
		{ID: "3", Type: model.FSettingSensitiveData, Environment: "prod", Subject: "prod"},
		{ID: "4", Type: model.FIdentityTraitLeak, Environment: "prod", Subject: "lookup"},
		{ID: "5", Type: model.FFlagNotServerOnly, Environment: "prod", Subject: "stripe_key"},
		{ID: "6", Type: model.FSecretExposed, Environment: "prod", Subject: "stripe_key"},
		{ID: "7", Type: model.FFlagNotServerOnly, Environment: "prod", Subject: "banner"},
		{ID: "8", Type: model.FSettingClientTraitsOn, Environment: "staging", Subject: "staging"},
		{ID: "9", Type: model.FSettingSensitiveData, Environment: "staging", Subject: "staging"},
	}
	AssignAll(fs)
	want := map[string]model.Severity{
		"1": model.SevMedium, "2": model.SevMedium, "3": model.SevMedium, "4": model.SevHigh,
		"5": model.SevHigh, "6": model.SevCritical, "7": model.SevLow,
		"8": model.SevLow, "9": model.SevLow,
	}
	for _, f := range fs {
		if f.Severity != want[f.ID] {
			t.Errorf("finding %s (%s) = %s, want %s", f.ID, f.Type, f.Severity, want[f.ID])
		}
	}
}

func TestSort(t *testing.T) {
	fs := []model.Finding{
		{ID: "d", Type: "B", Subject: "z", Severity: model.SevLow},
		{ID: "c", Type: "A", Subject: "z", Severity: model.SevHigh},
		{ID: "b", Type: "A", Subject: "b", Severity: model.SevHigh},
		{ID: "a", Type: "A", Subject: "a", Severity: model.SevCritical},
		{ID: "e", Type: "B", Subject: "z", Severity: model.SevInfo},
	}
	Sort(fs)
	got := ""
	for _, f := range fs {
		got += f.ID
	}
	if got != "abcde" {
		t.Fatalf("order = %s, want abcde", got)
	}
}

func TestIdentifierForgeryRatedLikeTraitForgery(t *testing.T) {
	staff := model.Finding{Type: model.FIdentifierForgery, Subject: "internal_tools"}
	if got := Rate(staff, Context{}); got != model.SevCritical {
		t.Errorf("staff-only flag: %s, want critical", got)
	}
	paid := model.Finding{Type: model.FIdentifierForgery, Subject: "premium_export"}
	if got := Rate(paid, Context{}); got != model.SevHigh {
		t.Errorf("paid feature: %s, want high", got)
	}
}
