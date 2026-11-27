package mapper

import (
	"fmt"
	"sort"

	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

// Dashboard labels of the settings the audit reports on, exactly as shown in
// the Flagsmith UI.
const (
	labelClientTraits  = "Allow client SDKs to set user traits"
	labelHideSensitive = "Hide sensitive data"
	labelServerOnly    = "Server-side only"
)

// SettingsAudit records the security settings of every environment and flags
// each risky value (spec §8.7): client-set traits allowed, sensitive data not
// hidden, and sensitive flags that are not "Server-side only". cls maps flag
// names to their sensitivity class; flags absent from it are not judged.
// Setting findings start at low severity; the severity stage raises
// SETTING_CLIENT_TRAITS_ON once forgeable segments are known.
func SettingsAudit(envs []flagsmith.Environment, features []flagsmith.Feature, cls map[string]model.Category) ([]model.EnvSettings, []model.Finding) {
	var serverOnly, visible []string
	live := make([]flagsmith.Feature, 0, len(features))
	for _, f := range features {
		if f.IsArchived {
			continue
		}
		live = append(live, f)
		if f.IsServerKeyOnly {
			serverOnly = append(serverOnly, f.Name)
		} else {
			visible = append(visible, f.Name)
		}
	}
	sort.Strings(serverOnly)
	sort.Strings(visible)

	var settings []model.EnvSettings
	var findings []model.Finding
	for _, e := range envs {
		allow, hide := e.AllowClientTraits, e.HideSensitiveData
		settings = append(settings, model.EnvSettings{
			Environment: e.Name, AllowClientTraits: &allow, HideSensitiveData: &hide,
			UseV2Versioning: e.UseV2FeatureVersioning,
			ServerOnlyFlags: append([]string{}, serverOnly...), ClientVisible: append([]string{}, visible...),
		})
		if allow {
			findings = append(findings, settingFinding(model.FSettingClientTraitsOn, e.Name, "allow_client_traits", labelClientTraits, "ON",
				"Anyone holding the public client key can set their own traits, so any segment keyed on a trait can be forged. Turn this setting off for every environment that uses segments for access control."))
		}
		if !hide {
			findings = append(findings, settingFinding(model.FSettingSensitiveData, e.Name, "hide_sensitive_data", labelHideSensitive, "OFF",
				"Sensitive data is not hidden in this environment. Turn this setting on."))
		}
	}
	findings = append(findings, notServerOnlyFindings(live, cls)...)
	return settings, findings
}

func settingFinding(t model.FindingType, env, subject, label, state, advice string) model.Finding {
	note := redact.String(fmt.Sprintf("Environment %q: dashboard setting %q is %s (%s). %s", env, label, state, subject, advice))
	return model.Finding{
		ID: model.MakeFindingID(t, env, subject), Type: t, Severity: model.SevLow,
		Title:       fmt.Sprintf("%s: %q is %s", env, label, state),
		Environment: env, Subject: subject, DetectedBy: []model.Method{model.MethodSettings},
		Confirmed: true, Status: model.StatusExploitable,
		Evidence: []model.Evidence{{Kind: "setting", Note: note}},
	}
}

func isSensitive(c model.Category) bool {
	switch c {
	case model.CatSecret, model.CatInternalURL, model.CatPricing, model.CatPII, model.CatUnreleasedProduct:
		return true
	}
	return false
}

func notServerOnlyFindings(features []flagsmith.Feature, cls map[string]model.Category) []model.Finding {
	var out []model.Finding
	for _, f := range features {
		c := cls[f.Name]
		if f.IsServerKeyOnly || !isSensitive(c) {
			continue
		}
		sev := model.SevMedium
		if c == model.CatSecret {
			sev = model.SevHigh
		}
		note := redact.String(fmt.Sprintf("Feature %q is classified %s but the dashboard setting %q is off, so client SDKs receive it.", f.Name, c, labelServerOnly))
		out = append(out, model.Finding{
			ID: model.MakeFindingID(model.FFlagNotServerOnly, "", f.Name), Type: model.FFlagNotServerOnly, Severity: sev,
			Title:   fmt.Sprintf("Sensitive flag %q is not %q", f.Name, labelServerOnly),
			Subject: f.Name, Category: c, DetectedBy: []model.Method{model.MethodSettings},
			Confirmed: true, Status: model.StatusExploitable,
			Evidence: []model.Evidence{{Kind: "setting", Note: note}},
		})
	}
	return out
}
