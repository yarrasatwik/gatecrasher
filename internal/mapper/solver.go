package mapper

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Flagsmith/flagsmith-go-client/v5/flagengine/utils"
)

// probePrefix starts every identifier or trait value found by search.
const probePrefix = "gc-probe-map-"

// DefaultMaxSearch is how many identifiers a percentage-split search tries.
const DefaultMaxSearch = 4000

// Candidate is one input that should satisfy a segment: trait values, plus an
// identifier when a condition constrains it or a percentage split needed one
// found by search. Props lists every property the input depends on, so its
// forgeability can be judged. Candidates are proposals; the reachability stage
// proves them with Flagsmith's engine.
type Candidate struct {
	Traits           map[string]string
	Identifier       string
	IdentifierForged bool
	Props            []string
}

// Cost is the number of forged inputs: traits plus a forged identifier.
func (c Candidate) Cost() int {
	n := len(c.Traits)
	if c.IdentifierForged {
		n++
	}
	return n
}

func (c Candidate) key() string {
	names := make([]string, 0, len(c.Traits))
	for k := range c.Traits {
		names = append(names, k)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, k := range names {
		fmt.Fprintf(&b, "%q=%q;", k, c.Traits[k])
	}
	fmt.Fprintf(&b, "id=%q", c.Identifier)
	return b.String()
}

// Solve returns candidate inputs that satisfy every rule of the segment,
// cheapest first. env is the environment API key (needed for identity-key
// conditions and percentage splits); maxSearch bounds identifier searches
// (DefaultMaxSearch when <= 0). The result is deterministic.
func Solve(seg Segment, env string, maxSearch int) []Candidate {
	if maxSearch <= 0 {
		maxSearch = DefaultMaxSearch
	}
	if len(seg.Rules) == 0 {
		return nil
	}
	lists := make([][]assign, 0, len(seg.Rules))
	for _, r := range seg.Rules {
		lists = append(lists, ruleAlts(r, true, env))
	}
	seen := map[string]bool{}
	var out []Candidate
	for _, a := range all(lists) {
		c, ok := resolve(a, seg.ID, env, maxSearch)
		if !ok || seen[c.key()] {
			continue
		}
		seen[c.key()] = true
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Cost() < out[j].Cost()
	})
	return out
}

// resolve turns an assignment into a candidate, searching for identifiers or
// trait values that satisfy its percentage splits.
func resolve(a assign, segID int, env string, maxSearch int) (Candidate, bool) {
	c := Candidate{Traits: map[string]string{}}
	for k, v := range a.vals {
		if k == identifierProp {
			c.Identifier, c.IdentifierForged = v, true
		} else {
			c.Traits[k] = v
		}
	}
	segKey := fmt.Sprint(segID)
	byTarget := map[string][]split{}
	for _, s := range a.splits {
		t := s.Target
		if t == "" {
			t = identifierProp
		}
		byTarget[t] = append(byTarget[t], s)
	}
	targets := make([]string, 0, len(byTarget))
	for t := range byTarget {
		targets = append(targets, t)
	}
	sort.Strings(targets)
	for _, t := range targets {
		if t == identifierProp {
			id, ok := searchSplits(byTarget[t], c.Identifier, segKey, env, maxSearch)
			if !ok {
				return c, false
			}
			c.Identifier, c.IdentifierForged = id, true
			continue
		}
		v, ok := searchSplits(byTarget[t], c.Traits[t], segKey, "", maxSearch)
		if !ok {
			return c, false
		}
		c.Traits[t] = v
	}
	for p := range a.props {
		c.Props = append(c.Props, p)
	}
	for t := range c.Traits {
		if !a.props[t] {
			c.Props = append(c.Props, t)
		}
	}
	if c.IdentifierForged && !a.props[identifierProp] {
		c.Props = append(c.Props, identifierProp)
	}
	sort.Strings(c.Props)
	return c, true
}

// searchSplits finds a value satisfying every split. env is non-empty when
// hashing the environment-keyed identity key ("<env>_<identifier>") and empty
// when hashing the value itself. A fixed value is only checked, not searched.
func searchSplits(splits []split, fixed, segKey, env string, maxSearch int) (string, bool) {
	hit := func(v string) bool {
		for _, s := range splits {
			ids := []string{segKey, v}
			if s.Target == "" && env != "" {
				ids = []string{segKey, env + "_" + v}
			}
			if (utils.GetHashedPercentageForObjectIds(ids, 1) <= s.Percent) != s.Want {
				return false
			}
		}
		return true
	}
	if fixed != "" {
		return fixed, hit(fixed)
	}
	for n := 0; n < maxSearch; n++ {
		if v := fmt.Sprintf("%s%d", probePrefix, n); hit(v) {
			return v, true
		}
	}
	return "", false
}

// TraitPool collects, per trait name, the values segment conditions mention
// or that would satisfy them. It seeds realistic random inputs for parity
// checks.
func TraitPool(segs []Segment) map[string][]string {
	pool := map[string][]string{}
	var walk func(rs []Rule)
	walk = func(rs []Rule) {
		for _, r := range rs {
			for _, c := range r.Conditions {
				kind, name := propertyKind(c.Property)
				if kind != kindTrait || c.Operator == OpPercentSplit {
					continue
				}
				for _, want := range []bool{true, false} {
					pool[name] = appendUnique(pool[name], valueCandidates(c.Operator, c.Value, want)...)
				}
			}
			walk(r.Rules)
		}
	}
	for _, s := range segs {
		walk(s.Rules)
	}
	return pool
}
