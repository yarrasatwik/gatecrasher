// Package secrets is Gatecrasher's deterministic sensitivity detector
// (spec §8.2). It inspects flag names and values, recursing into JSON, and
// reports which signal fired and at which JSON path. It never decides that a
// finding is exploitable; it only classifies what a client-side visitor can see.
package secrets

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

// Signal is one detector hit.
type Signal struct {
	// Kind is a stable short identifier such as "aws_access_key" or "private_ip".
	Kind     string         `json:"kind"`
	Category model.Category `json:"category"`
	// Path locates the hit: "name" for the flag name, "$" for the value root,
	// "$.a.b[0]" for nested JSON.
	Path       string  `json:"path"`
	Confidence float64 `json:"confidence"`
	// Secret holds the matched secret material for SECRET signals so callers
	// can register it with redact. It is never serialised or printed.
	Secret string `json:"-"`
}

// String renders the signal without any matched material.
func (s Signal) String() string { return s.Kind + "@" + s.Path }

type pattern struct {
	kind string
	re   *regexp.Regexp
}

var secretPatterns = []pattern{
	{"aws_access_key", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"github_token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}`)},
	{"slack_token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}`)},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)},
	{"private_key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"acme_live_key", regexp.MustCompile(`\bacme_live_[0-9A-Za-z]{8,}`)},
	{"live_api_key", regexp.MustCompile(`\b(?:sk|rk)_live_[A-Za-z0-9]{8,}`)},
	{"anthropic_key", regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{10,}`)},
	{"flagsmith_server_key", regexp.MustCompile(`\bser\.[A-Za-z0-9_-]{8,}`)},
}

var (
	secretKeyName = regexp.MustCompile(`(?i)(secret|token|api[_-]?key|passw(?:or)?d|private[_-]?key|credential)`)
	urlRe         = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>]+`)
	emailRe       = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
	phoneRe       = regexp.MustCompile(`\+\d{1,3}[\s.-]?\d{3}[\s.-]?\d{4,}|\(?\b\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b`)
	rfc1918Re     = regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b`)
	localhostRe   = regexp.MustCompile(`(?i)\blocalhost\b|\b127\.0\.0\.1\b`)
	hostRe        = regexp.MustCompile(`(?i)\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\b`)
	internalWord  = regexp.MustCompile(`(?i)internal|corp|staging|intranet`)
	internalTLD   = regexp.MustCompile(`(?i)\.(?:local|internal|lan|intranet)$`)
	tokenRe       = regexp.MustCompile(`[A-Za-z0-9+/=_-]{20,}`)
	uuidRe        = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hexRe         = regexp.MustCompile(`^[0-9a-fA-F]+$`)

	dateRe         = regexp.MustCompile(`(?i)(?:^|[^0-9])20\d\d[_.-]?(?:0?[1-9]|1[0-2])[_.-]?(?:0?[1-9]|[12]\d|3[01])(?:[^0-9]|$)|20\d\d[_-]?q[1-4]`)
	codenameRe     = regexp.MustCompile(`(?i)(?:^|[^a-z])(?:project|codename|operation)[_\s-]+[a-z0-9]+`)
	launchRe       = regexp.MustCompile(`(?i)(?:^|[^a-z])(?:launch|unreleased|upcoming|embargo)(?:[^a-z]|$)`)
	pricingName    = regexp.MustCompile(`(?i)discount|margin|wholesale|cost[_-]?price|price[_-]?list|plan[_-]?price|coupon`)
	pricingGeneric = regexp.MustCompile(`(?i)price|pricing|amount|fee|cost`)
	amountRe       = regexp.MustCompile(`[$€£]\s?\d|\b\d+\.\d{2}\s?(?:usd|eur|gbp)\b`)
	adminGateName  = regexp.MustCompile(`(?i)admin|bypass|impersonat|sudo|staff[_-]?only|auth[_-]?override|debug[_-]?mode`)
)

// Scan inspects a flag name and value and returns every signal found.
// Value strings that contain JSON are parsed and walked, so a secret buried
// in {"payment":{"api_secret":"…"}} is reported at "$.payment.api_secret".
func Scan(name string, value any) []Signal {
	out := scanName(name, value)
	out = append(out, walk(value, "$", "")...)
	return dedupe(out)
}

func scanName(name string, value any) []Signal {
	var out []Signal
	add := func(kind string, cat model.Category, conf float64) {
		out = append(out, Signal{Kind: kind, Category: cat, Path: "name", Confidence: conf})
	}
	hasDate := dateRe.MatchString(name)
	hasCode := codenameRe.MatchString(name)
	hasLaunch := launchRe.MatchString(name)
	switch {
	case hasCode && (hasDate || hasLaunch):
		add("codename_launch", model.CatUnreleasedProduct, 0.9)
	case hasDate && hasLaunch:
		add("launch_date", model.CatUnreleasedProduct, 0.85)
	case hasLaunch:
		add("launch_name", model.CatUnreleasedProduct, 0.7)
	case hasDate:
		add("dated_name", model.CatUnreleasedProduct, 0.6)
	}
	if pricingName.MatchString(name) || (pricingGeneric.MatchString(name) && hasAmount(value)) {
		add("pricing_name", model.CatPricing, 0.6)
	}
	if adminGateName.MatchString(name) {
		add("admin_gate", model.CatSecurityControl, 0.6)
	}
	return out
}

func hasAmount(v any) bool {
	switch t := v.(type) {
	case float64:
		return true
	case string:
		if p := parseJSONContainer(t); p != nil {
			return hasAmount(p)
		}
		return amountRe.MatchString(t)
	case map[string]any:
		for _, e := range t {
			if hasAmount(e) {
				return true
			}
		}
	case []any:
		for _, e := range t {
			if hasAmount(e) {
				return true
			}
		}
	}
	return false
}

func parseJSONContainer(s string) any {
	t := strings.TrimSpace(s)
	if len(t) < 2 || (t[0] != '{' && t[0] != '[') {
		return nil
	}
	var v any
	if json.Unmarshal([]byte(t), &v) != nil {
		return nil
	}
	return v
}

func walk(v any, path, key string) []Signal {
	switch t := v.(type) {
	case map[string]any:
		var out []Signal
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out = append(out, walk(t[k], path+"."+k, k)...)
		}
		return out
	case []any:
		var out []Signal
		for i, e := range t {
			out = append(out, walk(e, fmt.Sprintf("%s[%d]", path, i), key)...)
		}
		return out
	case string:
		if p := parseJSONContainer(t); p != nil {
			return walk(p, path, key)
		}
		return scanString(t, path, key)
	case float64:
		if pricingGeneric.MatchString(key) {
			return []Signal{{Kind: "pricing_value", Category: model.CatPricing, Path: path, Confidence: 0.6}}
		}
	}
	return nil
}

func scanString(s, path, key string) []Signal {
	var out []Signal
	sig := func(kind string, cat model.Category, conf float64, secret string) {
		out = append(out, Signal{Kind: kind, Category: cat, Path: path, Confidence: conf, Secret: secret})
	}
	for _, p := range secretPatterns {
		if m := p.re.FindString(s); m != "" {
			sig(p.kind, model.CatSecret, 0.95, m)
		}
	}
	if key != "" && secretKeyName.MatchString(key) && isSecretLike(s) {
		sig("secret_key_name", model.CatSecret, 0.85, s)
	}
	if tok := highEntropyToken(s); tok != "" {
		sig("high_entropy", model.CatSecret, 0.7, tok)
	}
	out = append(out, scanInternal(s, path)...)
	if emailRe.MatchString(s) {
		sig("email", model.CatPII, 0.85, "")
	}
	if phoneRe.MatchString(s) {
		sig("phone", model.CatPII, 0.8, "")
	}
	if pricingGeneric.MatchString(key) && amountRe.MatchString(s) {
		sig("pricing_value", model.CatPricing, 0.6, "")
	}
	if codenameRe.MatchString(s) && (dateRe.MatchString(s) || launchRe.MatchString(s)) {
		sig("codename_launch", model.CatUnreleasedProduct, 0.8, "")
	}
	return out
}

func isSecretLike(s string) bool {
	return len(s) >= 8 && !strings.ContainsAny(s, " \t\n") && !strings.HasPrefix(s, "http")
}

func scanInternal(s, path string) []Signal {
	var out []Signal
	add := func(kind string, conf float64) {
		out = append(out, Signal{Kind: kind, Category: model.CatInternalURL, Path: path, Confidence: conf})
	}
	if rfc1918Re.MatchString(s) {
		add("private_ip", 0.9)
	}
	if localhostRe.MatchString(s) {
		add("localhost", 0.8)
	}
	for _, h := range hostRe.FindAllString(emailRe.ReplaceAllString(s, " "), -1) {
		if internalWord.MatchString(h) || internalTLD.MatchString(h) {
			add("internal_host", 0.85)
			break
		}
	}
	return out
}

// highEntropyToken returns the first token of s that looks like random key
// material: at least 20 characters, Shannon entropy above 3.5, and either
// mixed upper/lower/digit or a long hex string. URLs, e-mail addresses and
// UUIDs are stripped first so ordinary product text does not trigger it.
func highEntropyToken(s string) string {
	s = urlRe.ReplaceAllString(s, " ")
	s = emailRe.ReplaceAllString(s, " ")
	for _, tok := range tokenRe.FindAllString(s, -1) {
		if uuidRe.MatchString(tok) || Entropy(tok) <= 3.5 {
			continue
		}
		if hasAllClasses(tok) || (len(tok) >= 32 && hexRe.MatchString(tok)) {
			return tok
		}
	}
	return ""
}

func hasAllClasses(s string) bool {
	var up, lo bool
	digits := 0
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			up = true
		case r >= 'a' && r <= 'z':
			lo = true
		case r >= '0' && r <= '9':
			digits++
		}
	}
	return up && lo && digits >= 2
}

// Entropy returns the Shannon entropy of s in bits per character.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]float64{}
	n := 0.0
	for _, r := range s {
		freq[r]++
		n++
	}
	h := 0.0
	for _, c := range freq {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

func dedupe(in []Signal) []Signal {
	seen := map[string]bool{}
	var out []Signal
	for _, s := range in {
		k := s.Kind + "|" + s.Path
		if !seen[k] {
			seen[k] = true
			out = append(out, s)
		}
	}
	return out
}

// categoryOrder is the tie-break when several categories fire on one flag.
var categoryOrder = []model.Category{
	model.CatSecret, model.CatInternalURL, model.CatPII,
	model.CatUnreleasedProduct, model.CatPricing, model.CatSecurityControl,
}

// Classify deterministically categorises one flag from its name and RawValue.
// Plain kill-switch booleans such as maintenance_mode and ordinary display
// text such as a shipping banner are HARMLESS and never produce a finding.
func Classify(flag model.FlagView) model.Classification {
	sigs := Scan(flag.Name, flag.RawValue)
	c := model.Classification{Flag: flag.Name, Category: model.CatHarmless, Confidence: 0.9, Method: model.MethodDeterministic, Rationale: "no sensitive pattern found in name or value"}
	for _, cat := range categoryOrder {
		var best *Signal
		for i := range sigs {
			if sigs[i].Category == cat && (best == nil || sigs[i].Confidence > best.Confidence) {
				best = &sigs[i]
			}
		}
		if best == nil {
			continue
		}
		c.Category = cat
		c.Confidence = best.Confidence
		c.Rationale = rationale(cat, *best)
		break
	}
	for _, s := range sigs {
		c.Signals = append(c.Signals, s.String())
	}
	return c
}

func rationale(cat model.Category, s Signal) string {
	where := "flag name"
	if s.Path != "name" {
		where = "value at " + s.Path
	}
	return fmt.Sprintf("%s detected in %s (%s)", strings.ToLower(strings.ReplaceAll(string(cat), "_", " ")), where, s.Kind)
}
