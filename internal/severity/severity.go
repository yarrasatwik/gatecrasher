// Package severity assigns deterministic severities to findings (spec §8.8).
// The AI never chooses a severity; every rule below is plain code so the same
// evidence always yields the same rating.
//
// Rules, evaluated per finding type:
//
//	SECRET_IN_CLIENT_VALUE          Critical
//	TRAIT_FORGERY                   Critical when the unlocked flag is a SECURITY_CONTROL
//	                                or admin-like (name contains admin, staff, internal,
//	                                superuser or root, or tagged "admin"); otherwise High
//	                                (a paid feature)
//	IDENTIFIER_FORGERY              same rule as TRAIT_FORGERY (the input forged is the
//	                                identifier instead of a trait)
//	IDENTITY_TRAIT_LEAK             High
//	PII_IN_CLIENT_VALUE             High
//	EXPERIMENT_RIGGING              High on pricing/revenue flags (name contains price,
//	                                pricing, plan, checkout, discount or revenue, or category
//	                                PRICING); otherwise Medium
//	INTERNAL_URL_LEAK               Medium
//	UNRELEASED_PRODUCT_LEAK         Medium
//	PERCENTAGE_REROLL               Medium
//	VARIANT_REROLL                  Medium
//	IDENTITY_OVERRIDE_LEAK          Medium
//	SEGMENT_FORGEABLE               Medium
//	PRICING_LEAK                    Medium
//	SETTING_CLIENT_TRAITS_ON        Medium when forgeable segments exist, else Low
//	SETTING_SENSITIVE_DATA_VISIBLE  Medium when an identity lookup is possible, else Low
//	FLAG_NOT_SERVER_ONLY            High when the flag holds a SECRET, else Low
//	CONTROL_OK                      Info
//	anything else                   Medium
package severity

import (
	"sort"
	"strings"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

// Hint tags a finding can carry so Assign can rate it without seeing the
// other findings. AssignAll derives the same facts from the whole set.
const (
	// TagForgeableSegments marks a finding as coexisting with forgeable segments.
	TagForgeableSegments = "forgeable-segments"
	// TagLookupPossible marks a finding as coexisting with an identity-lookup leak.
	TagLookupPossible = "lookup-possible"
	// TagHoldsSecret marks a flag finding whose value is a secret.
	TagHoldsSecret = "holds-secret"
)

// Context is the cross-finding knowledge some rules depend on.
type Context struct {
	// ForgeableSegments is true when attacker-set traits can reach a segment.
	ForgeableSegments bool
	// LookupPossible is true when an identity lookup leaks traits.
	LookupPossible bool
	// HoldsSecret is true when the finding's flag value is a secret.
	HoldsSecret bool
}

var (
	adminWords   = []string{"admin", "staff", "internal", "superuser", "root"}
	revenueWords = []string{"price", "pricing", "plan", "checkout", "discount", "revenue"}
)

// Assign sets f.Severity using only the finding itself (its type, subject,
// category and hint tags).
func Assign(f *model.Finding) {
	f.Severity = Rate(*f, contextFromTags(*f))
}

// AssignAll sets the severity of every finding, deriving cross-finding
// context (forgeable segments, lookup leaks, secret-bearing flags) from the
// set itself, scoped to the finding's environment.
func AssignAll(fs []model.Finding) {
	for i := range fs {
		ctx := contextFromTags(fs[i])
		for _, o := range fs {
			if !sameEnv(fs[i], o) {
				continue
			}
			switch o.Type {
			case model.FSegmentForgeable, model.FTraitForgery:
				ctx.ForgeableSegments = true
			case model.FIdentityTraitLeak:
				ctx.LookupPossible = true
			case model.FSecretExposed:
				if o.Subject == fs[i].Subject {
					ctx.HoldsSecret = true
				}
			}
		}
		fs[i].Severity = Rate(fs[i], ctx)
	}
}

func sameEnv(a, b model.Finding) bool {
	return a.Environment == "" || b.Environment == "" || a.Environment == b.Environment
}

func contextFromTags(f model.Finding) Context {
	return Context{
		ForgeableSegments: hasTag(f, TagForgeableSegments),
		LookupPossible:    hasTag(f, TagLookupPossible),
		HoldsSecret:       hasTag(f, TagHoldsSecret) || f.Category == model.CatSecret,
	}
}

// Rate returns the severity of f given ctx. It is a pure function.
func Rate(f model.Finding, ctx Context) model.Severity {
	switch f.Type {
	case model.FSecretExposed:
		return model.SevCritical
	case model.FTraitForgery, model.FIdentifierForgery:
		if isAdminLike(f) {
			return model.SevCritical
		}
		return model.SevHigh
	case model.FIdentityTraitLeak, model.FPIILeak:
		return model.SevHigh
	case model.FExperimentRigging:
		if isRevenue(f) {
			return model.SevHigh
		}
		return model.SevMedium
	case model.FSettingClientTraitsOn:
		return lowUnless(ctx.ForgeableSegments, model.SevMedium)
	case model.FSettingSensitiveData:
		return lowUnless(ctx.LookupPossible, model.SevMedium)
	case model.FFlagNotServerOnly:
		return lowUnless(ctx.HoldsSecret, model.SevHigh)
	case model.FControlOK:
		return model.SevInfo
	default:
		return model.SevMedium
	}
}

func lowUnless(cond bool, raised model.Severity) model.Severity {
	if cond {
		return raised
	}
	return model.SevLow
}

func isAdminLike(f model.Finding) bool {
	if f.Category == model.CatSecurityControl {
		return true
	}
	if hasTag(f, "admin") || containsAny(f.Subject, adminWords) {
		return true
	}
	for _, u := range f.Unlocked {
		if containsAny(u.Flag, adminWords) {
			return true
		}
	}
	return false
}

func isRevenue(f model.Finding) bool {
	return f.Category == model.CatPricing || containsAny(f.Subject, revenueWords)
}

func containsAny(s string, words []string) bool {
	s = strings.ToLower(s)
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

func hasTag(f model.Finding, tag string) bool {
	for _, t := range f.Tags {
		if strings.EqualFold(t, tag) {
			return true
		}
	}
	return false
}

// Sort orders findings by severity (worst first), then type, subject and ID,
// so reports are byte-stable across runs.
func Sort(fs []model.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.Subject != b.Subject {
			return a.Subject < b.Subject
		}
		return a.ID < b.ID
	})
}
