package report

import "github.com/yarrasatwik/gatecrasher/internal/model"

// ruleInfo documents one finding type: it feeds SARIF rules and the generic
// fix text shown when a finding carries no specific fix summary.
type ruleInfo struct {
	Type  model.FindingType
	Name  string
	Short string
	Full  string
	Fix   string
}

// catalog lists every finding type in a stable order. SARIF rule indexes
// refer to positions in this slice.
var catalog = []ruleInfo{
	{model.FTraitForgery, "ClientTraitForgery", "A client-supplied trait unlocks a protected flag.",
		"Anyone holding the public client key can send arbitrary identity traits. A segment that trusts those traits can be satisfied by an attacker, unlocking features or controls they should not reach.",
		"Do not use client-writable traits for entitlement or access control. Turn off allow_client_traits, or decide segments from server-verified data only."},
	{model.FIdentifierForgery, "IdentifierForgery", "A client-chosen identifier matches a segment rule and unlocks a protected flag.",
		"A segment rule tests the identity's identifier (for example with a regular expression). When the client chooses its own identifier it can pick one that matches. No trait is involved, so turning off allow_client_traits does not close it.",
		"Assign identifiers on the server and stop targeting on identifier patterns."},
	{model.FPercentageReroll, "PercentageRolloutReroll", "An attacker can pick an identifier that lands inside a percentage rollout.",
		"Percentage splits hash the identifier. When the client chooses its own identifier it can try values until it falls inside the rollout.",
		"Assign identifiers on the server and evaluate flags server-side for gated features."},
	{model.FVariantReroll, "VariantReroll", "An attacker can re-roll a multivariate variant.",
		"Variant assignment is derived from a client-chosen identifier, so an attacker can search for the variant they want.",
		"Assign identifiers on the server and evaluate experiment flags server-side."},
	{model.FExperimentRigging, "ExperimentRigging", "An experiment on a revenue flag can be steered by the client.",
		"The client can choose the variant of a pricing or checkout experiment, which skews results and can unlock cheaper offers.",
		"Bucket users on the server and do not expose experiment assignment to client-controlled input."},
	{model.FIdentityTraitLeak, "IdentityTraitLeak", "Identity lookups return stored traits.",
		"Requesting an identity with any identifier returns the traits stored for it, which can disclose other users' data.",
		"Enable hide_sensitive_data for the environment and stop storing sensitive traits in Flagsmith."},
	{model.FIdentityOverrideLeak, "IdentityOverrideLeak", "Per-identity overrides are visible to clients.",
		"Flag values targeted at specific identities can be read by anyone who can guess the identifier.",
		"Avoid identity overrides for sensitive flags, or serve them to servers only."},
	{model.FSecretExposed, "SecretInClientValue", "A secret is served in a client-visible flag value.",
		"A flag value contains credential material that every holder of the public client key can read.",
		"Rotate the secret immediately, remove it from the flag and keep secrets out of Flagsmith."},
	{model.FInternalURL, "InternalUrlLeak", "An internal URL is served in a client-visible flag.",
		"The flag value reveals internal hostnames or admin endpoints, which helps attackers map the infrastructure.",
		"Remove internal URLs from client-visible flags or mark the flag server-side only."},
	{model.FUnreleasedProduct, "UnreleasedProductLeak", "Unreleased product details are visible in client flags.",
		"Flag names or values reveal products or features that have not been announced.",
		"Rename pre-launch flags to neutral names and mark them server-side only."},
	{model.FPricingLeak, "PricingLeak", "Pricing data is served in a client-visible flag.",
		"The flag value exposes price tables or discount rules that were meant to stay private.",
		"Move pricing data to a server-only flag or your backend."},
	{model.FPIILeak, "PiiInClientValue", "Personal data is served in a client-visible flag.",
		"A flag value contains personal data such as an email address or phone number.",
		"Remove personal data from flag values and mark the flag server-side only."},
	{model.FSettingClientTraitsOn, "ClientTraitsEnabled", "The environment accepts traits written by client keys.",
		"allow_client_traits is on, so any holder of the public client key can write identity traits.",
		"Disable allow_client_traits for the environment."},
	{model.FSettingSensitiveData, "SensitiveDataVisible", "Sensitive data is visible to client keys.",
		"hide_sensitive_data is off, so client keys can read data that should be restricted to servers.",
		"Enable hide_sensitive_data for the environment."},
	{model.FFlagNotServerOnly, "FlagNotServerOnly", "A sensitive flag is not restricted to server-side keys.",
		"The flag is returned to client keys although it does not need to be.",
		"Mark the flag as server-side only."},
	{model.FSegmentForgeable, "SegmentForgeable", "A segment can be matched using client-supplied traits.",
		"The segment rules depend only on traits a client can set, so an attacker can join the segment on demand.",
		"Base segment rules on server-controlled traits or identifiers."},
	{model.FControlOK, "ControlOk", "A control is correctly configured.",
		"This is informational: the control was tested and behaves as intended.",
		"No action needed."},
}

// lookupRule returns the catalog entry for t and its index.
func lookupRule(t model.FindingType) (ruleInfo, int, bool) {
	for i, c := range catalog {
		if c.Type == t {
			return c, i, true
		}
	}
	return ruleInfo{}, -1, false
}

// fixText returns the best available fix guidance for a finding: the
// explanation's fix summary, then the generic catalog fix.
func fixText(f model.Finding) string {
	if f.Explanation != nil && f.Explanation.FixSummary != "" {
		return f.Explanation.FixSummary
	}
	if c, _, ok := lookupRule(f.Type); ok {
		return c.Fix
	}
	return ""
}
