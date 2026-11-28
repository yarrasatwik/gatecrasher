// Package reporttest builds a realistic sample report that other packages can
// reuse in tests and demos. It contains no real keys: client keys appear only
// as the <CLIENT_KEY> placeholder and secrets only as redacted fingerprints.
package reporttest

import (
	"fmt"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/severity"
)

// Env is the environment name used by the sample report.
const Env = "Production"

// SampleReport returns a deterministic report with one finding of every
// finding type, plus settings, reachability, before/after rows and stats.
// Severities are already assigned and findings sorted.
func SampleReport() *model.Report {
	findings := SampleFindings()
	severity.AssignAll(findings)
	severity.Sort(findings)
	live := true
	notLive := false
	agree := 0.92
	return &model.Report{
		SchemaVersion: model.SchemaVersion,
		ID:            "audit-20261127-acme",
		Tool:          "Gatecrasher",
		Version:       "0.1.0",
		CreatedAt:     time.Date(2026, 11, 27, 9, 30, 0, 0, time.UTC),
		Target:        "http://localhost:3000",
		Project:       "Acme Shop",
		Environment:   Env,
		AIMode:        "off (heuristics)",
		Scope:         []string{"http://localhost:3000", "http://localhost:8000"},
		Inventory: &model.PublicInventory{
			TargetURL:      "http://localhost:3000",
			APIURL:         "http://localhost:8000/api/v1/",
			KeyFingerprint: "[CLIENT_KEY len=22 prefix=Xk3m…]",
			KeySources:     []string{"static/app.js:12 environmentID"},
			TraitKeys:      []string{"plan", "is_staff"},
			Flags: []model.FlagView{
				{Name: "admin_console", FeatureID: 1, Enabled: false, ValueType: "null", Preview: "", Size: 0},
				{Name: "premium_export", FeatureID: 2, Enabled: false, ValueType: "null", Preview: "", Size: 0},
			},
			FetchedAt: time.Date(2026, 11, 27, 9, 30, 1, 0, time.UTC),
		},
		Findings: findings,
		Settings: []model.EnvSettings{
			{Environment: Env, AllowClientTraits: boolPtr(true), HideSensitiveData: boolPtr(false), ServerOnlyFlags: []string{"stripe_secret"}, ClientVisible: []string{"admin_console", "premium_export", "banner_text"}},
			{Environment: "Staging", AllowClientTraits: boolPtr(false), HideSensitiveData: boolPtr(true), UseV2Versioning: true},
			{Environment: "Development"},
		},
		Reachability: []model.Reachable{
			{Environment: Env, Flag: "admin_console", Enabled: true, Value: "on", DefaultValue: "off", Segment: "staff", ForgedTraits: map[string]string{"is_staff": "true"}, Forgeable: "yes", EngineVerified: true, LiveVerified: &live},
			{Environment: Env, Flag: "new_checkout_rollout", Enabled: true, Value: "on", DefaultValue: "off", Identifier: "gc-probe-0417", Forgeable: "yes", EngineVerified: true, LiveVerified: &notLive},
			{Environment: Env, Flag: "homepage_hero", Enabled: true, Value: "variant_b", DefaultValue: "variant_a", Identifier: "gc-probe-0088", Forgeable: "unknown", EngineVerified: true},
		},
		BeforeAfter: []model.VerifyRow{
			{FindingID: findings[0].ID, Title: "Secret exposed in client value", Before: model.StatusExploitable, After: model.StatusBlocked, Proof: "server-only flag no longer returned by /flags/"},
			{FindingID: findings[1].ID, Title: "Admin console reachable by forged trait", Before: model.StatusExploitable, After: model.StatusExploitable, Proof: "still unlocked with is_staff=true"},
		},
		Stats: model.Stats{
			ProbesSent:       142,
			DurationMS:       18450,
			StageMS:          map[string]int64{"recon": 900, "attack": 14200, "map": 3350},
			ParityChecked:    12,
			ParityAgreed:     12,
			AIHeuristicAgree: &agree,
		},
		Notes: []string{"Run against the local lab; no data was modified."},
	}
}

func boolPtr(b bool) *bool { return &b }

// SampleFindings returns one finding per finding type, unsorted and with
// severities unset.
func SampleFindings() []model.Finding {
	all := []model.Finding{
		finding(model.FSecretExposed, "payments_config", model.CatSecret, "A live payment key is served to every browser.",
			ev("bundle", "GET /api/v1/flags/", "value: [SECRET len=40 prefix=acme…]"), "Rotate the key and mark the flag server-side only."),
		finding(model.FTraitForgery, "admin_console", model.CatSecurityControl, "Setting is_staff=true unlocks the admin console.",
			ev("request", "POST /api/v1/identities/ traits=is_staff:true", "admin_console enabled=true"), "Stop trusting client-set traits for access control."),
		finding(model.FTraitForgery, "premium_export", model.CatHarmless, "Setting plan=enterprise unlocks premium export for free.",
			ev("request", "POST /api/v1/identities/ traits=plan:enterprise", "premium_export enabled=true"), "Gate premium features on server-side entitlement."),
		finding(model.FIdentityTraitLeak, "identity-lookup", "", "Any identifier returns that user's stored traits.",
			ev("request", "POST /api/v1/identities/ identifier=alice", "traits: plan, email"), "Enable hide_sensitive_data."),
		finding(model.FPIILeak, "support_contact", model.CatPII, "A flag value holds a personal email address.",
			ev("bundle", "", "value: ops@example.com"), "Move contact data out of flag values."),
		finding(model.FExperimentRigging, "pricing_experiment", model.CatPricing, "An attacker can pick the cheapest pricing variant.",
			ev("request", "POST /api/v1/identities/ identifier=gc-probe-9", "variant=annual_50_off"), "Assign experiment buckets server-side."),
		finding(model.FInternalURL, "debug_endpoint", model.CatInternalURL, "An internal admin hostname is exposed.",
			ev("bundle", "", "value: https://admin.internal.acme.test/debug"), "Remove internal URLs from client flags."),
		finding(model.FUnreleasedProduct, "ai_assistant_beta", model.CatUnreleasedProduct, "An unreleased product name is visible in the flag list.",
			ev("bundle", "", "flag name: ai_assistant_beta"), "Rename or hide pre-launch flags."),
		finding(model.FPercentageReroll, "new_checkout_rollout", "", "Changing the identifier lands the attacker in the 10% rollout.",
			ev("engine", "", "gc-probe-0417 -> enabled in 3 of 20 tries"), "Use a server-assigned identifier."),
		finding(model.FVariantReroll, "homepage_hero", "", "Variant assignment can be re-rolled at will.",
			ev("engine", "", "variant_b reached with gc-probe-0088"), "Use a server-assigned identifier."),
		finding(model.FIdentityOverrideLeak, "vip_banner", "", "Identity overrides reveal which users are special.",
			ev("request", "POST /api/v1/identities/ identifier=vip-1", "vip_banner enabled=true"), "Do not expose per-user overrides to clients."),
		finding(model.FSegmentForgeable, "beta-testers", "", "Segment membership depends only on client traits.",
			ev("engine", "", "segment beta-testers matched with beta=true"), "Base segments on server-controlled traits."),
		finding(model.FIdentifierForgery, "partner_portal", "", "Choosing identifier a@acme.test unlocks partner_portal — this survives turning off client traits.",
			ev("engine", "", "segment staff_by_identifier matched identifier a@acme.test"), "Assign identifiers on the server and stop targeting on identifier patterns."),
		finding(model.FPricingLeak, "enterprise_price", model.CatPricing, "Unannounced enterprise pricing is public.",
			ev("bundle", "", "value: {\"seat\": 49}"), "Keep price tables out of client flags."),
		finding(model.FSettingClientTraitsOn, Env, "", "The environment accepts traits written by clients.",
			ev("setting", "", "allow_client_traits=true"), "Disable allow_client_traits."),
		finding(model.FSettingSensitiveData, Env, "", "The environment returns sensitive data to client keys.",
			ev("setting", "", "hide_sensitive_data=false"), "Enable hide_sensitive_data."),
		finding(model.FFlagNotServerOnly, "banner_text", model.CatHarmless, "A flag with an internal note is client-visible.",
			ev("setting", "", "is_server_key_only=false"), "Mark the flag server-side only."),
		finding(model.FControlOK, "Staging", "", "Staging blocks client trait writes.",
			ev("setting", "", "allow_client_traits=false"), "None needed."),
	}
	all[1].Notes = []string{"impact: web/src/features/admin.js:42"}
	all[2].Notes = []string{"impact: ./web/src/export.js:7"}
	all[1].FixPlanID = "plan-0001"
	all[0].FixPlanID = "plan-0002"
	all[0].Explanation = &model.Explanation{
		Title:          "A live payment key is public",
		WhatHappened:   "The payments_config flag carries a live API key in its value.",
		WhyItMatters:   "Anyone with the public client key can read it.",
		BusinessImpact: "Attackers can make charges and refunds in your name.",
		FixSummary:     "Rotate the key and mark the flag server-side only.",
		Source:         "template",
	}
	all[1].Traits = map[string]string{"is_staff": "true"}
	all[1].Unlocked = []model.FlagChange{{Flag: "admin_console", Before: "off", After: "on"}}
	all[1].ProofID = "gc-probe-admin-1"
	all[8].HitRate = 0.1
	all[8].Attempts = 10
	all[9].Variants = map[string]int{"variant_a": 51, "variant_b": 49}
	return all
}

func finding(t model.FindingType, subject string, cat model.Category, title string, e model.Evidence, fix string) model.Finding {
	status := model.StatusExploitable
	method := []model.Method{model.MethodProbe, model.MethodEngine}
	switch t {
	case model.FControlOK:
		status = model.StatusBlocked
		method = []model.Method{model.MethodSettings}
	case model.FSettingClientTraitsOn, model.FSettingSensitiveData, model.FFlagNotServerOnly:
		method = []model.Method{model.MethodSettings, model.MethodDeterministic}
	case model.FInternalURL, model.FUnreleasedProduct, model.FPricingLeak, model.FPIILeak, model.FSecretExposed:
		method = []model.Method{model.MethodDeterministic, model.MethodAI}
	}
	return model.Finding{
		ID:          model.MakeFindingID(t, Env, subject),
		Type:        t,
		Title:       title,
		Environment: Env,
		Subject:     subject,
		Category:    cat,
		DetectedBy:  method,
		Confirmed:   status != model.StatusUnknown,
		Status:      status,
		Repro:       reproFor(t, subject),
		Evidence:    []model.Evidence{e},
		Notes:       []string{"fix: " + fix},
	}
}

func ev(kind, req, resp string) model.Evidence {
	return model.Evidence{Kind: kind, Request: req, Response: resp, Note: fmt.Sprintf("captured as %s evidence", kind)}
}

func reproFor(t model.FindingType, subject string) string {
	switch t {
	case model.FControlOK, model.FSettingClientTraitsOn, model.FSettingSensitiveData:
		return ""
	}
	return "curl -s -H 'X-Environment-Key: <CLIENT_KEY>' http://localhost:8000/api/v1/flags/ | jq '.[] | select(.feature.name==\"" + subject + "\")'"
}
