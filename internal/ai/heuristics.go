package ai

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

// dictionary is the built-in trait guess list (spec §8.3), most promising first.
var dictionary = []struct {
	key    string
	values []string
	why    string
}{
	{"plan", []string{"gold", "enterprise", "premium", "pro", "free"}, "plan/tier traits commonly gate paid features"},
	{"role", []string{"admin", "staff", "internal"}, "role traits commonly gate privileged features"},
	{"is_beta", []string{"true"}, "beta flag commonly unlocks preview features"},
	{"beta", []string{"true"}, "beta flag commonly unlocks preview features"},
	{"tier", []string{"enterprise", "premium"}, "tier traits commonly gate paid features"},
	{"internal", []string{"true"}, "internal-user marker"},
	{"employee", []string{"true"}, "employee marker"},
	{"country", []string{"US"}, "country traits commonly gate regional features"},
}

var emailLocals = []string{"admin", "staff", "test"}

// heuristicHypotheses is the AI-off equivalent of Hypothesize: trait keys seen
// in the bundle first (with generic privileged values), then the dictionary,
// then e-mail guesses on the target's own domain. At most MaxHypotheses.
func heuristicHypotheses(traitKeys []string, domain string) []Hypothesis {
	var out []Hypothesis
	seen := map[string]bool{}
	add := func(k, v, why string) {
		id := k + "\x00" + v
		if seen[id] || len(out) >= MaxHypotheses || !traitKeyRe.MatchString(k) {
			return
		}
		seen[id] = true
		out = append(out, Hypothesis{TraitKey: k, TraitValue: v, Why: why})
	}
	for _, k := range traitKeys {
		for _, v := range bundleValues(k) {
			add(k, v, "trait name found in the target's JavaScript bundle")
		}
	}
	for _, d := range dictionary {
		for _, v := range d.values {
			add(d.key, v, d.why)
		}
	}
	if host := bareDomain(domain); host != "" {
		for _, l := range emailLocals {
			add("email", l+"@"+host, "e-mail traits are often matched against the company domain")
		}
	}
	return out
}

// HeuristicHypotheses returns the deterministic guesses used when the AI is
// off: bundle trait keys first, then the built-in dictionary and e-mail
// guesses on domain. It sends nothing and costs nothing, which makes it the
// basis of request-count estimates.
func HeuristicHypotheses(traitKeys []string, domain string) []Hypothesis {
	return heuristicHypotheses(traitKeys, domain)
}

func bundleValues(key string) []string {
	for _, d := range dictionary {
		if d.key == key {
			return d.values
		}
	}
	return []string{"true", "admin", "enterprise"}
}

func bareDomain(d string) string {
	d = strings.TrimSpace(strings.ToLower(d))
	if strings.Contains(d, "://") {
		if u, err := url.Parse(d); err == nil {
			d = u.Hostname()
		}
	}
	if i := strings.IndexAny(d, "/:"); i >= 0 {
		d = d[:i]
	}
	return d
}

type explainTemplate struct{ what, why, impact, fix string }

var explainTemplates = map[model.FindingType]explainTemplate{
	model.FTraitForgery: {
		"Anyone can claim user attributes such as %s from the browser and Flagsmith accepts them, unlocking %s.",
		"The environment lets client-side code set traits, so targeting rules based on traits are not a security boundary.",
		"Paid or privileged features can be used without paying or being authorised.",
		"Turn off client-side traits for this environment, or move the decision to your server.",
	},
	model.FIdentifierForgery: {
		"Anyone can pick an identifier that matches the pattern a segment looks for, which unlocks %s.",
		"The segment targets the identifier itself and the browser chooses its own identifier. No trait is involved, so turning off client-set traits does not close this.",
		"Staff-only or privileged features can be reached by anyone who guesses the identifier pattern.",
		"Assign identifiers on the server and stop targeting on identifier patterns.",
	},
	model.FPercentageReroll: {
		"A visitor can keep choosing new identifiers until they land in the rollout group for %s.",
		"Percentage rollouts are decided by the identifier, which the client controls.",
		"Gated or early-access features can be reached on demand, and rollout numbers become unreliable.",
		"Do not use percentage rollouts as access control; derive identifiers on the server.",
	},
	model.FVariantReroll: {
		"A visitor can pick the variant of %s by changing their identifier.",
		"Variants are assigned from a client-chosen identifier, so people can choose their own price or experience.",
		"Visitors can pick the cheaper price or skew results.",
		"Assign variants from a server-issued identifier.",
	},
	model.FExperimentRigging: {
		"An outsider can steer which variant of %s they receive and feed results into the experiment.",
		"Experiment results can be manipulated by anyone who knows the public key.",
		"Decisions based on the experiment may be wrong.",
		"Keep experiment identifiers server-side and review the results for contamination.",
	},
	model.FIdentityTraitLeak: {
		"Looking up identity %s with the public key returned stored traits.",
		"Public keys can read identity data when an identifier is known or guessable.",
		"Personal or commercial data about a customer is exposed.",
		"Stop storing sensitive traits in Flagsmith or restrict identity reads.",
	},
	model.FIdentityOverrideLeak: {
		"Looking up identity %s with the public key exposed per-user flag overrides.",
		"Identity overrides reveal who has special access.",
		"Information about VIP users and their entitlements is exposed.",
		"Remove sensitive identity overrides or avoid identifiers that are easy to guess.",
	},
	model.FSecretExposed: {
		"The flag %s serves a credential to every visitor.",
		"Flag values in a client-side environment are public; a key stored there is already exposed.",
		"Someone could use the credential to act as your service.",
		"Rotate the credential, then move it to server-side configuration or mark the flag server-side only.",
	},
	model.FInternalURL: {
		"The flag %s reveals an internal address or hostname.",
		"Internal URLs map your network and help targeted attacks.",
		"Attackers learn where internal systems live.",
		"Remove the value from client-visible flags or mark the flag server-side only.",
	},
	model.FUnreleasedProduct: {
		"The flag %s names an unreleased product or launch date.",
		"Flag names are visible to anyone with the public key.",
		"Competitors or press can learn about the launch early.",
		"Rename the flag to something neutral or mark it server-side only.",
	},
	model.FPricingLeak: {
		"The flag %s exposes non-public pricing or discount data.",
		"Client-side flag values are readable by everyone.",
		"Competitors or customers can see pricing before it is announced.",
		"Move pricing out of client-visible flags.",
	},
	model.FPIILeak: {
		"The flag %s serves personal data such as an e-mail address or phone number.",
		"Personal data in flag values is shown to every visitor.",
		"This may breach privacy obligations and harms the people affected.",
		"Remove the personal data from the flag and mark the flag server-side only.",
	},
	model.FPossibleSecret: {
		"The flag %s serves a random-looking value to every visitor. It needs review.",
		"It matches no known secret format, so it may be a harmless identifier or a credential.",
		"If it is a credential, anyone could use it.",
		"Check what the value is. Rotate and remove it if it is a credential.",
	},
	model.FSettingClientTraitsOn: {
		"The environment %s allows client-side traits.",
		"Anyone with the public key can send traits that change flag results.",
		"Trait-based targeting can be bypassed.",
		"Disable client traits after confirming no app code needs them.",
	},
	model.FSettingSensitiveData: {
		"The environment %s does not hide sensitive data.",
		"Sensitive flag data is returned to client-side requests.",
		"Secrets and internal details reach browsers.",
		"Enable the hide sensitive data setting.",
	},
	model.FFlagNotServerOnly: {
		"The flag %s is visible to browsers but looks server-only.",
		"Only flags marked server-side only are kept out of client responses.",
		"Server configuration is readable by anyone.",
		"Mark the flag as server-side only.",
	},
	model.FSegmentForgeable: {
		"The segment %s can be matched by forged traits.",
		"Segments built on client-controlled traits are guessable.",
		"People can enter privileged groups.",
		"Base segments on server-trusted data and disable client traits.",
	},
}

// templateExplanation is the AI-off explanation for a finding. Source is "template".
func templateExplanation(f model.Finding) *model.Explanation {
	t, ok := explainTemplates[f.Type]
	if !ok {
		t = explainTemplate{
			"Gatecrasher found an issue with %s.",
			"The behaviour lets outsiders see or change something they should not.",
			"Depends on what the flag controls.",
			"Review the finding evidence and restrict the exposure.",
		}
	}
	what := fmt.Sprintf(t.what, f.Subject)
	if f.Type == model.FTraitForgery {
		what = fmt.Sprintf(t.what, sortedTraits(f.Traits), unlockedNames(f))
	}
	title := f.Title
	if title == "" {
		title = strings.ReplaceAll(strings.ToLower(string(f.Type)), "_", " ")
	}
	r := redact.String
	return &model.Explanation{Title: r(title), WhatHappened: r(what), WhyItMatters: r(t.why), BusinessImpact: r(t.impact), FixSummary: r(t.fix), Source: "template"}
}

func unlockedNames(f model.Finding) string {
	if len(f.Unlocked) == 0 {
		return "additional flags"
	}
	names := make([]string, len(f.Unlocked))
	for i, u := range f.Unlocked {
		names[i] = u.Flag
	}
	return strings.Join(names, ", ")
}

// templatePR is the AI-off pull request draft: guidance and an impact list,
// without a diff.
func templatePR(f model.Finding, impact []model.ImpactItem) *PRDraft {
	title := "Fix " + strings.ReplaceAll(strings.ToLower(string(f.Type)), "_", " ") + ": " + f.Subject
	var b strings.Builder
	e := templateExplanation(f)
	fmt.Fprintf(&b, "## Finding %s\n\n%s\n\n**Fix:** %s\n\n", f.ID, e.WhatHappened, e.FixSummary)
	if len(impact) > 0 {
		b.WriteString("## Code affected\n\n")
		for _, it := range impact {
			fmt.Fprintf(&b, "- `%s:%d` %s\n", it.File, it.Line, it.Message)
		}
		b.WriteString("\n")
	}
	b.WriteString("_No diff generated: AI is off or unavailable. Apply the change by hand._\n")
	return &PRDraft{Title: redact.String(title), Body: redact.String(b.String()), Source: "template"}
}
