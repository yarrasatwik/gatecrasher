// Package unreleased holds the deterministic rules that decide whether a
// flag name reveals an unreleased product. They exist so that an
// UNRELEASED_PRODUCT finding never rests on the AI's opinion alone: the AI
// may suggest, these rules (or a human) confirm.
//
// Signals FOR, each sufficient on its own:
//
//   - a date in the name that is in the future relative to the audit date
//     (2026_12_15, 20261215, 2027q1);
//   - a codename pattern: project_*, *_launch_*, *_codename_*;
//   - the words unreleased, stealth, internal_only, or secret (unless the
//     name is plainly a credential, such as api_secret).
//
// The one signal AGAINST lives with the caller, because it needs live data:
// a flag currently served to a share of real users (on by default, or behind
// a live percentage rollout) is not unreleased, whatever its name says.
package unreleased

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Result is the outcome of the name rules for one flag.
type Result struct {
	// Match is true when at least one FOR signal fired.
	Match bool
	// Signals lists the rules that fired, e.g. "codename:project_*" or
	// "future_date:2026-12-15", in a stable order.
	Signals []string
}

var (
	splitRe   = regexp.MustCompile(`[^a-z0-9]+`)
	dateRe    = regexp.MustCompile(`(?:^|[^0-9])(20\d\d)[_.-]?(0[1-9]|1[0-2])[_.-]?(0[1-9]|[12]\d|3[01])(?:[^0-9]|$)`)
	quarterRe = regexp.MustCompile(`(?:^|[^0-9])(20\d\d)[_-]?q([1-4])(?:[^0-9]|$)`)
)

// credentialWords mark a name containing "secret" as a credential rather
// than a secret product.
var credentialWords = map[string]bool{
	"api": true, "key": true, "client": true, "token": true, "password": true,
	"access": true, "webhook": true, "signing": true, "oauth": true, "jwt": true, "hmac": true,
}

// Check applies the name rules to one flag name. auditDate is the day the
// audit runs; only dates after that day count as future.
func Check(name string, auditDate time.Time) Result {
	lower := strings.ToLower(name)
	var tokens []string
	for _, t := range splitRe.Split(lower, -1) {
		if t != "" {
			tokens = append(tokens, t)
		}
	}
	var r Result
	add := func(sig string) {
		r.Match = true
		r.Signals = append(r.Signals, sig)
	}
	credential := false
	for _, t := range tokens {
		credential = credential || credentialWords[t]
	}
	for i, t := range tokens {
		switch {
		case t == "project" && i == 0 && len(tokens) > 1:
			add("codename:project_*")
		case t == "launch" && i > 0 && i < len(tokens)-1:
			add("codename:*_launch_*")
		case t == "codename" && i > 0 && i < len(tokens)-1:
			add("codename:*_codename_*")
		case t == "unreleased":
			add("word:unreleased")
		case t == "stealth":
			add("word:stealth")
		case t == "secret" && !credential:
			add("word:secret")
		case t == "internal" && i < len(tokens)-1 && tokens[i+1] == "only":
			add("word:internal_only")
		}
	}
	y, m, d := auditDate.Date()
	today := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	for _, g := range dateRe.FindAllStringSubmatch(lower, -1) {
		if day, ok := date(g[1], g[2], g[3]); ok && day.After(today) {
			add("future_date:" + day.Format("2006-01-02"))
		}
	}
	for _, g := range quarterRe.FindAllStringSubmatch(lower, -1) {
		q, _ := strconv.Atoi(g[2])
		if day, ok := date(g[1], strconv.Itoa((q-1)*3+1), "1"); ok && day.After(today) {
			add("future_date:" + day.Format("2006-01-02"))
		}
	}
	return r
}

// date builds a calendar day and rejects impossible ones such as 31 June.
func date(ys, ms, ds string) (time.Time, bool) {
	y, _ := strconv.Atoi(ys)
	m, _ := strconv.Atoi(ms)
	d, _ := strconv.Atoi(ds)
	t := time.Date(y, time.Month(m), d, 0, 0, 0, 0, time.UTC)
	return t, t.Year() == y && int(t.Month()) == m && t.Day() == d
}
