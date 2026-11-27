package mapper

import (
	"encoding/json"
	"math"
	"regexp"
	"strconv"
	"strings"
)

const (
	noMatchWord = "gc-no-match"
	setWord     = "gc-set"
	semverTag   = ":semver"
)

// valueCandidates lists trait values that make "<value> <op> <constant>"
// evaluate to want, preferred first. Candidates are only proposals: the
// reachability stage verifies each with Flagsmith's engine.
func valueCandidates(op, v string, want bool) []string {
	switch op {
	case OpEqual:
		return pick(want, []string{base(v)}, []string{shift(v, 1)})
	case OpNotEqual:
		return pick(want, []string{shift(v, 1)}, []string{base(v)})
	case OpGreaterThan:
		return pick(want, []string{shift(v, 1)}, []string{base(v), shift(v, -1)})
	case OpGreaterOrEqual:
		return pick(want, []string{base(v), shift(v, 1)}, []string{shift(v, -1)})
	case OpLessThan:
		return pick(want, []string{shift(v, -1)}, []string{base(v), shift(v, 1)})
	case OpLessOrEqual:
		return pick(want, []string{base(v), shift(v, -1)}, []string{shift(v, 1)})
	case OpContains:
		return pick(want, []string{"gc-" + v + "-gc", v}, excluding(v))
	case OpNotContains:
		return pick(want, excluding(v), []string{"gc-" + v + "-gc", v})
	case OpIn:
		items := listItems(v)
		if want {
			if len(items) > 3 {
				items = items[:3]
			}
			return items
		}
		return notIn(items)
	case OpRegex:
		return regexValues(v, want)
	case OpModulo:
		return moduloValues(v, want)
	}
	return nil
}

func pick(want bool, yes, no []string) []string {
	if want {
		return yes
	}
	return no
}

// excluding returns strings that do not contain v.
func excluding(v string) []string {
	var out []string
	for _, s := range []string{noMatchWord, "gc-none", "0"} {
		if !strings.Contains(s, v) {
			out = append(out, s)
		}
	}
	return out
}

// listItems parses an IN value: a JSON array or a comma separated list.
func listItems(v string) []string {
	var arr []string
	if json.Unmarshal([]byte(v), &arr) == nil {
		return arr
	}
	return strings.Split(v, ",")
}

func notIn(items []string) []string {
	var out []string
	for _, s := range []string{"gc-not-in-list", "gc-other"} {
		in := false
		for _, it := range items {
			in = in || it == s
		}
		if !in {
			out = append(out, s)
		}
	}
	return out
}

func regexValues(pattern string, want bool) []string {
	if want {
		return matchingStrings(pattern, 4)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return []string{noMatchWord} // an invalid pattern never matches
	}
	var out []string
	for _, s := range []string{noMatchWord, "", "0", "x"} {
		if !re.MatchString(s) {
			out = append(out, s)
		}
	}
	return out
}

func moduloValues(v string, want bool) []string {
	parts := strings.Split(v, "|")
	if len(parts) != 2 {
		return pick(want, nil, []string{"0"})
	}
	d, err1 := strconv.ParseFloat(parts[0], 64)
	r, err2 := strconv.ParseFloat(parts[1], 64)
	if err1 != nil || err2 != nil || d == 0 {
		return pick(want, nil, []string{"0"})
	}
	var out []string
	for _, c := range []float64{r, r + d, r + 2*d, r + 1, r + 2, 0, 1} {
		if (math.Mod(c, d) == r) == want {
			out = append(out, strconv.FormatFloat(c, 'f', -1, 64))
		}
	}
	return out
}

// base strips the ":semver" marker, leaving the plain constant.
func base(v string) string { return strings.TrimSuffix(v, semverTag) }

// shift returns a value one step above (d>0) or below (d<0) the constant,
// understanding semver ("x.y.z:semver"), integers, floats, booleans and
// plain strings.
func shift(v string, d int) string {
	if strings.HasSuffix(v, semverTag) {
		return shiftSemver(base(v), d)
	}
	if i, err := strconv.ParseInt(v, 10, 64); err == nil {
		return strconv.FormatInt(i+int64(d), 10)
	}
	if f, err := strconv.ParseFloat(v, 64); err == nil {
		return strconv.FormatFloat(f+float64(d), 'f', -1, 64)
	}
	if b, err := strconv.ParseBool(v); err == nil {
		return strconv.FormatBool(!b)
	}
	if d > 0 || v == "" {
		return v + "a"
	}
	r := []rune(v)
	return string(r[:len(r)-1])
}

func shiftSemver(v string, d int) string {
	core := strings.SplitN(strings.SplitN(v, "+", 2)[0], "-", 2)[0]
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return v
	}
	nums := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return v
		}
		nums[i] = n
	}
	if d > 0 {
		nums[2]++
	} else if nums[2] > 0 {
		nums[2]--
	} else if nums[1] > 0 {
		nums[1]--
	} else if nums[0] > 0 {
		nums[0]--
	}
	return strconv.Itoa(nums[0]) + "." + strconv.Itoa(nums[1]) + "." + strconv.Itoa(nums[2])
}
