// Package mapper is Gatecrasher's inside-view stage (spec §8.7): it audits
// environment security settings, decides which segment conditions an attacker
// can forge, solves segment rules into candidate inputs and uses Flagsmith's
// own engine to prove which flag states are reachable with the smallest forged
// input. It is read-only: nothing here talks to Flagsmith.
package mapper

import (
	"github.com/Flagsmith/flagsmith-go-client/v5/flagengine/segments"

	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
)

// Rule and condition operator names as used by Flagsmith.
const (
	OpEqual          = "EQUAL"
	OpNotEqual       = "NOT_EQUAL"
	OpGreaterThan    = "GREATER_THAN"
	OpGreaterOrEqual = "GREATER_THAN_INCLUSIVE"
	OpLessThan       = "LESS_THAN"
	OpLessOrEqual    = "LESS_THAN_INCLUSIVE"
	OpContains       = "CONTAINS"
	OpNotContains    = "NOT_CONTAINS"
	OpIn             = "IN"
	OpIsSet          = "IS_SET"
	OpIsNotSet       = "IS_NOT_SET"
	OpRegex          = "REGEX"
	OpModulo         = "MODULO"
	OpPercentSplit   = "PERCENTAGE_SPLIT"
)

// Rule types.
const (
	RuleAll  = "ALL"
	RuleAny  = "ANY"
	RuleNone = "NONE"
)

// Condition is one segment condition in an engine-neutral shape.
type Condition struct {
	Property string
	Operator string
	Value    string
}

// Rule is a (possibly nested) segment rule. Type is ALL, ANY or NONE.
type Rule struct {
	Type       string
	Conditions []Condition
	Rules      []Rule
}

// Segment is a segment's identity and rules.
type Segment struct {
	ID    int
	Name  string
	Rules []Rule
}

// FromAdmin converts Admin API segments into the neutral form.
func FromAdmin(in []flagsmith.Segment) []Segment {
	out := make([]Segment, 0, len(in))
	for _, s := range in {
		out = append(out, Segment{ID: s.ID, Name: s.Name, Rules: adminRules(s.Rules)})
	}
	return out
}

func adminRules(in []flagsmith.Rule) []Rule {
	out := make([]Rule, 0, len(in))
	for _, r := range in {
		nr := Rule{Type: r.Type, Rules: adminRules(r.Rules)}
		for _, c := range r.Conditions {
			nr.Conditions = append(nr.Conditions, Condition{Property: c.Property, Operator: c.Operator, Value: c.Value})
		}
		out = append(out, nr)
	}
	return out
}

// fromDocument converts environment-document segments into the neutral form.
func fromDocument(in []*segments.SegmentModel) []Segment {
	out := make([]Segment, 0, len(in))
	for _, s := range in {
		out = append(out, Segment{ID: s.ID, Name: s.Name, Rules: documentRules(s.Rules)})
	}
	return out
}

func documentRules(in []*segments.SegmentRuleModel) []Rule {
	out := make([]Rule, 0, len(in))
	for _, r := range in {
		nr := Rule{Type: string(r.Type), Rules: documentRules(r.Rules)}
		for _, c := range r.Conditions {
			nr.Conditions = append(nr.Conditions, Condition{Property: c.Property, Operator: string(c.Operator), Value: c.Value})
		}
		out = append(out, nr)
	}
	return out
}

// fromDocumentWithStates pairs each document segment with its overrides.
func fromDocumentWithStates(in []*segments.SegmentModel) []docSegment {
	neutral := fromDocument(in)
	out := make([]docSegment, 0, len(in))
	for i, s := range in {
		out = append(out, docSegment{seg: neutral[i], states: s.FeatureStates})
	}
	return out
}
