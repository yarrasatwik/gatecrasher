package mapper

import (
	"regexp"
	"regexp/syntax"
)

const (
	regexBranchLimit = 8
	regexPreferred   = "a0A-_.@ x"
)

// matchingStrings returns up to limit strings that match pattern, simplest
// first. The generator covers literals, classes, ".", repetition, groups,
// anchors and alternation; every result is re-checked with regexp, so an
// unsupported construct yields fewer (or no) strings, never a wrong one.
func matchingStrings(pattern string, limit int) []string {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	var out []string
	for _, s := range generate(re.Simplify()) {
		if compiled.MatchString(s) {
			out = append(out, s)
			if len(out) == limit {
				break
			}
		}
	}
	return out
}

// generate lists candidate strings for a parsed expression, preferred first,
// capped at regexBranchLimit per node.
func generate(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		return []string{string(re.Rune)}
	case syntax.OpCharClass:
		return classRunes(re.Rune)
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return []string{"a"}
	case syntax.OpCapture:
		return generate(re.Sub[0])
	case syntax.OpConcat:
		out := []string{""}
		for _, sub := range re.Sub {
			out = cross(out, generate(sub))
		}
		return out
	case syntax.OpAlternate:
		var out []string
		for _, sub := range re.Sub {
			out = appendUnique(out, generate(sub)...)
		}
		return capList(out)
	case syntax.OpStar:
		return capList(appendUnique(generate(re.Sub[0]), ""))
	case syntax.OpQuest:
		return capList(appendUnique([]string{""}, generate(re.Sub[0])...))
	case syntax.OpPlus:
		return generate(re.Sub[0])
	case syntax.OpNoMatch:
		return nil
	default: // empty match, anchors and word boundaries consume nothing
		return []string{""}
	}
}

func cross(a, b []string) []string {
	var out []string
	for _, x := range a {
		for _, y := range b {
			out = appendUnique(out, x+y)
		}
	}
	return capList(out)
}

func appendUnique(list []string, items ...string) []string {
	for _, it := range items {
		dup := false
		for _, e := range list {
			if e == it {
				dup = true
				break
			}
		}
		if !dup {
			list = append(list, it)
		}
	}
	return list
}

func capList(l []string) []string {
	if len(l) > regexBranchLimit {
		return l[:regexBranchLimit]
	}
	return l
}

// classRunes picks representative runes of a character class, preferring
// readable ones, then the first printable rune of the first range.
func classRunes(ranges []rune) []string {
	var out []string
	for _, p := range regexPreferred {
		if inClass(ranges, p) {
			out = appendUnique(out, string(p))
		}
	}
	for i := 0; i+1 < len(ranges); i += 2 {
		lo := ranges[i]
		if lo < 0x20 {
			lo = 0x20
		}
		if lo <= ranges[i+1] {
			out = appendUnique(out, string(lo))
			break
		}
	}
	return capList(out)
}

func inClass(ranges []rune, r rune) bool {
	for i := 0; i+1 < len(ranges); i += 2 {
		if r >= ranges[i] && r <= ranges[i+1] {
			return true
		}
	}
	return false
}
