// Package testdoc builds generated Flagsmith environment documents for tests,
// in the shape the official engine parses (segments under project.segments,
// overrides as segment feature_states, multivariate values per feature state).
package testdoc

import (
	"encoding/json"

	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
)

// Cond is a segment condition.
type Cond struct{ Property, Operator, Value string }

// Rule is a segment rule; Type is ALL, ANY or NONE.
type Rule struct {
	Type  string
	Conds []Cond
	Rules []Rule
}

// MV is a multivariate option with its percentage allocation.
type MV struct {
	ID      int
	Value   any
	Percent float64
}

// Override is a feature state served by a segment.
type Override struct {
	Feature string
	Enabled bool
	Value   any
	MV      []MV
}

// Segment is a project segment with its overrides. Priority defaults to the
// segment's 1-based position; lower numbers win.
type Segment struct {
	ID        int
	Name      string
	Rules     []Rule
	Overrides []Override
	Priority  int
}

// Feature is an environment-default feature state.
type Feature struct {
	Name    string
	Enabled bool
	Value   any
	MV      []MV
}

// Doc is an environment document.
type Doc struct {
	APIKey   string
	Features []Feature
	Segments []Segment
}

// JSON renders the document.
func (d Doc) JSON() json.RawMessage {
	ids := map[string]int{}
	for i, f := range d.Features {
		ids[f.Name] = i + 1
	}
	fs := make([]any, 0, len(d.Features))
	for i, f := range d.Features {
		fs = append(fs, state(ids[f.Name], 100+i, f.Name, f.Enabled, f.Value, f.MV, 0))
	}
	segs := make([]any, 0, len(d.Segments))
	for i, s := range d.Segments {
		prio := s.Priority
		if prio == 0 {
			prio = i + 1
		}
		states := make([]any, 0, len(s.Overrides))
		for j, o := range s.Overrides {
			states = append(states, state(ids[o.Feature], 1000*(i+1)+j, o.Feature, o.Enabled, o.Value, o.MV, prio))
		}
		rules := make([]any, 0, len(s.Rules))
		for _, r := range s.Rules {
			rules = append(rules, rule(r))
		}
		segs = append(segs, map[string]any{"id": s.ID, "name": s.Name, "rules": rules, "feature_states": states})
	}
	b, _ := json.Marshal(map[string]any{
		"id": 1, "api_key": d.APIKey, "name": "test",
		"project":            map[string]any{"id": 1, "name": "p", "segments": segs},
		"feature_states":     fs,
		"identity_overrides": []any{},
	})
	return b
}

// AdminSegments renders the segments as Admin API segments.
func (d Doc) AdminSegments() []flagsmith.Segment {
	out := make([]flagsmith.Segment, 0, len(d.Segments))
	for _, s := range d.Segments {
		as := flagsmith.Segment{ID: s.ID, Name: s.Name}
		for _, r := range s.Rules {
			as.Rules = append(as.Rules, adminRule(r))
		}
		out = append(out, as)
	}
	return out
}

func adminRule(r Rule) flagsmith.Rule {
	out := flagsmith.Rule{Type: r.Type}
	for _, c := range r.Conds {
		out.Conditions = append(out.Conditions, flagsmith.Condition{Property: c.Property, Operator: c.Operator, Value: c.Value})
	}
	for _, s := range r.Rules {
		out.Rules = append(out.Rules, adminRule(s))
	}
	return out
}

func rule(r Rule) map[string]any {
	conds := make([]any, 0, len(r.Conds))
	for _, c := range r.Conds {
		conds = append(conds, map[string]any{"property_": c.Property, "operator": c.Operator, "value": c.Value})
	}
	subs := make([]any, 0, len(r.Rules))
	for _, s := range r.Rules {
		subs = append(subs, rule(s))
	}
	return map[string]any{"type": r.Type, "conditions": conds, "rules": subs}
}

func state(featureID, djangoID int, name string, enabled bool, value any, mv []MV, priority int) map[string]any {
	mvs := make([]any, 0, len(mv))
	for _, m := range mv {
		mvs = append(mvs, map[string]any{
			"id": m.ID, "percentage_allocation": m.Percent,
			"multivariate_feature_option": map[string]any{"id": m.ID, "value": m.Value},
		})
	}
	st := map[string]any{
		"feature":                           map[string]any{"id": featureID, "name": name, "type": "STANDARD"},
		"enabled":                           enabled,
		"feature_state_value":               value,
		"django_id":                         djangoID,
		"multivariate_feature_state_values": mvs,
	}
	if priority > 0 {
		st["feature_segment"] = map[string]any{"priority": priority}
	}
	return st
}
