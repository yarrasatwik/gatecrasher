package mapper

import (
	"fmt"
	"sort"
	"strings"
)

// maxAlternatives bounds the alternatives kept per rule node.
const maxAlternatives = 32

// split is a PERCENTAGE_SPLIT requirement (Want true: inside the split).
// Target is "" for the environment-keyed identity key, identifierProp for the
// raw identifier, otherwise a trait name.
type split struct {
	Target  string
	Percent float64
	Want    bool
}

// assign is a partial input built while walking segment rules. vals holds
// trait values (identifierProp holds the identifier), absent the traits that
// must be omitted, props every property the input depends on.
type assign struct {
	vals   map[string]string
	absent map[string]bool
	splits []split
	props  map[string]bool
}

func newAssign() assign {
	return assign{vals: map[string]string{}, absent: map[string]bool{}, props: map[string]bool{}}
}

func (a assign) cost() int { return len(a.vals) + len(a.splits) }

func (a assign) key() string {
	var parts []string
	for k, v := range a.vals {
		parts = append(parts, fmt.Sprintf("v%q=%q", k, v))
	}
	for k := range a.absent {
		parts = append(parts, fmt.Sprintf("a%q", k))
	}
	for _, s := range a.splits {
		parts = append(parts, fmt.Sprintf("s%q/%g/%t", s.Target, s.Percent, s.Want))
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}

// merge combines two assignments; ok is false when they conflict.
func merge(a, b assign) (assign, bool) {
	out := newAssign()
	for _, src := range []assign{a, b} {
		for k, v := range src.vals {
			if old, ok := out.vals[k]; ok && old != v {
				return out, false
			}
			out.vals[k] = v
		}
		for k := range src.absent {
			out.absent[k] = true
		}
		for k := range src.props {
			out.props[k] = true
		}
		out.splits = append(out.splits, src.splits...)
	}
	for k := range out.absent {
		if _, ok := out.vals[k]; ok {
			return out, false
		}
	}
	return out, true
}

// tidy deduplicates, orders cheapest first and caps a list of alternatives.
func tidy(in []assign) []assign {
	type keyed struct {
		a assign
		k string
	}
	seen := map[string]bool{}
	var items []keyed
	for _, a := range in {
		k := a.key()
		if !seen[k] {
			seen[k] = true
			items = append(items, keyed{a, k})
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].a.cost() < items[j].a.cost()
	})
	if len(items) > maxAlternatives {
		items = items[:maxAlternatives]
	}
	out := make([]assign, len(items))
	for i, it := range items {
		out[i] = it.a
	}
	return out
}

// all returns every conflict-free combination taking one alternative from
// each list (a conjunction). No lists yields one empty assignment.
func all(lists [][]assign) []assign {
	acc := []assign{newAssign()}
	for _, l := range lists {
		var next []assign
		for _, a := range acc {
			for _, b := range l {
				if m, ok := merge(a, b); ok {
					next = append(next, m)
				}
			}
		}
		acc = tidy(next)
	}
	return acc
}

// anyOf concatenates alternatives (a disjunction).
func anyOf(lists [][]assign) []assign {
	var out []assign
	for _, l := range lists {
		out = append(out, l...)
	}
	return tidy(out)
}
