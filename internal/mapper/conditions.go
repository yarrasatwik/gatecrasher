package mapper

import (
	"strconv"
	"strings"
)

// ruleAlts returns the alternatives under which rule r evaluates to want.
// The engine requires a rule's conditions group AND its sub-rules group to
// hold, each combined by the rule type; an empty group holds.
func ruleAlts(r Rule, want bool, env string) []assign {
	childWant := want
	if r.Type != RuleAll && r.Type != RuleAny { // NONE (and unknown types, as the engine does)
		childWant = !want
	}
	var conds, subs [][]assign
	for _, c := range r.Conditions {
		conds = append(conds, condAlts(c, childWant, env))
	}
	for _, s := range r.Rules {
		subs = append(subs, ruleAlts(s, childWant, env))
	}
	groups := [][]assign{groupAlts(r.Type, conds, want), groupAlts(r.Type, subs, want)}
	if want {
		return all(groups)
	}
	return anyOf(groups)
}

// groupAlts combines one group of children (already requested with the
// child-side value). An empty group holds, so it can never be falsified.
func groupAlts(ruleType string, children [][]assign, want bool) []assign {
	if len(children) == 0 {
		if want {
			return []assign{newAssign()}
		}
		return nil
	}
	needAll := ruleType == RuleAll && want ||
		ruleType == RuleAny && !want ||
		ruleType != RuleAll && ruleType != RuleAny && want
	if needAll {
		return all(children)
	}
	return anyOf(children)
}

// condAlts returns the alternatives under which condition c evaluates to want.
func condAlts(c Condition, want bool, env string) []assign {
	kind, name := propertyKind(c.Property)
	switch {
	case c.Operator == OpPercentSplit:
		return splitAlts(c, kind, name, want)
	case kind == kindNone:
		if (c.Operator == OpIsNotSet) == want {
			return []assign{newAssign()}
		}
		return nil
	case kind == kindEnvironment || kind == kindOther:
		a := newAssign()
		a.props[c.Property] = true
		return []assign{a}
	case kind == kindIdentifier || kind == kindIdentityKey:
		return identityAlts(c, kind, want, env)
	}
	return traitAlts(c, name, want)
}

func traitAlts(c Condition, name string, want bool) []assign {
	var out []assign
	set := func(v string) {
		a := newAssign()
		a.vals[name] = v
		a.props[name] = true
		out = append(out, a)
	}
	omit := func() {
		a := newAssign()
		a.absent[name] = true
		out = append(out, a)
	}
	switch c.Operator {
	case OpIsSet, OpIsNotSet:
		if (c.Operator == OpIsSet) == want {
			set(setWord)
		} else {
			omit()
		}
		return out
	}
	if !want {
		omit() // an unset trait fails every value operator
	}
	for _, v := range valueCandidates(c.Operator, c.Value, want) {
		set(v)
	}
	return tidy(out)
}

// identityAlts handles conditions on the identifier or identity key. The
// identifier is always set, so only value constraints can be met.
func identityAlts(c Condition, kind propKind, want bool, env string) []assign {
	if c.Operator == OpIsSet || c.Operator == OpIsNotSet {
		if (c.Operator == OpIsSet) != want {
			return nil
		}
		a := newAssign()
		a.props[identifierProp] = true
		return []assign{a}
	}
	var out []assign
	for _, v := range valueCandidates(c.Operator, c.Value, want) {
		if kind == kindIdentityKey {
			v = strings.TrimPrefix(v, env+"_")
		}
		a := newAssign()
		a.vals[identifierProp] = v
		a.props[identifierProp] = true
		out = append(out, a)
	}
	return tidy(out)
}

func splitAlts(c Condition, kind propKind, name string, want bool) []assign {
	pct, err := strconv.ParseFloat(c.Value, 64)
	if err != nil { // the engine treats an unparseable split as never matching
		if want {
			return nil
		}
		return []assign{newAssign()}
	}
	a := newAssign()
	target := ""
	switch kind {
	case kindTrait:
		target = name
		a.props[name] = true
	case kindIdentifier:
		target = identifierProp
		a.props[identifierProp] = true
	default:
		a.props[identifierProp] = true
	}
	a.splits = []split{{Target: target, Percent: pct, Want: want}}
	return []assign{a}
}
