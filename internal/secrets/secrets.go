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
	{"mapbox_secret_token", regexp.MustCompile(`\bsk\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
}

// publicPattern is a key that is public by design: it ships in every browser
// bundle and is never a SECRET. A hit is reported as an informational
// HARMLESS signal so the report can still carry the hardening note.
type publicPattern struct {
	kind string
	re   *regexp.Regexp
	note string
}

var publicPatterns = []publicPattern{
	{"public_stripe_publishable_key", regexp.MustCompile(`\bpk_(?:live|test)_[A-Za-z0-9]{8,}`),
		"Stripe publishable key: public by design"},
	{"public_firebase_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}`),
		"Firebase/Google browser API key: public by design; restrict it by HTTP referrer in the Google Cloud console"},
	{"public_mapbox_token", regexp.MustCompile(`\bpk\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
		"Mapbox public token: public by design; restrict it by URL in the Mapbox account"},
	{"public_sentry_dsn", regexp.MustCompile(`(?i)\bhttps?://[0-9a-z]{8,}@[a-z0-9.-]*sentry[a-z0-9.-]*(?::\d+)?/\d+`),
		"Sentry DSN: public by design"},
}

// recaptchaKeyRe matches reCAPTCHA keys. Site keys and secret keys share the
// format, so it only counts as public when the JSON key is not secret-named.
var recaptchaKeyRe = regexp.MustCompile(`\b6L[0-9A-Za-z_-]{38}`)

const (
	noteRecaptcha = "reCAPTCHA site key: public by design"
	noteAlgolia   = "Algolia search-only key: public by design"
)

// secretKeySuffixes are the JSON key names that mark a credential once
// separators and case are removed: api_secret, dbPassword, private-key,
// auth_token... The word must end the key, so password_policy, token_ttl
// and csrf_token_header are not credentials.
var secretKeySuffixes = []string{"secret", "secretkey", "password", "passwd", "privatekey", "token", "apikey", "credential", "credentials"}

var (
	anyURLRe  = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s"'<>]+`)
	dataURIRe = regexp.MustCompile(`(?i)\bdata:[a-z0-9.+/-]*(?:;[a-z0-9=-]+)*,[A-Za-z0-9+/=%_-]*`)
	// credURLRe matches scheme://user:password@host for any scheme
	// (postgres, mysql, mongodb+srv, redis, amqp, http(s), ftp...).
	credURLRe = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s/:@"'<>]*:([^\s/"'<>]+)@[^\s/:?#"'<>]+`)
	// userinfoRe captures the scheme and any userinfo so it can be dropped.
	userinfoRe    = regexp.MustCompile(`(?i)(\b[a-z][a-z0-9+.-]*://)([^\s/@"'<>]*)@`)
	searchKeyRe   = regexp.MustCompile(`(?i)search`)
	strongKeyRe   = regexp.MustCompile(`(?i)secret|admin|write|passw|private`)
	siteKeyRe     = regexp.MustCompile(`(?i)site[_-]?key`)
	algoliaKeyRe  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	lowerHexRe    = regexp.MustCompile(`^[0-9a-f]+$`)
	placeholderRe = regexp.MustCompile(`^(?:\$\{.*\}|\{\{.*\}\}|<.*>|%.*%|\$[A-Z_][A-Z0-9_]*|[*xX•.]+)$`)
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
	// 1. Known secret formats: unambiguous wherever they appear.
	for _, p := range secretPatterns {
		if m := p.re.FindString(s); m != "" {
			sig(p.kind, model.CatSecret, 0.95, m)
		}
	}
	// 2. A password inside a URL: scheme://user:password@host.
	for _, m := range credURLRe.FindAllStringSubmatch(s, -1) {
		if !placeholderRe.MatchString(m[1]) {
			sig("url_credential", model.CatSecret, 0.95, m[1])
		}
	}
	// 3. Public-by-design keys: informational only, and removed from the
	// text before any guesswork so they can never read as a secret.
	keyed := isSecretKey(key)
	rest := s
	for _, p := range publicPatterns {
		if p.re.MatchString(rest) {
			sig(p.kind, model.CatHarmless, 0.9, "")
			rest = p.re.ReplaceAllString(rest, " ")
		}
	}
	if !keyed && recaptchaKeyRe.MatchString(rest) {
		sig("public_recaptcha_site_key", model.CatHarmless, 0.9, "")
		rest = recaptchaKeyRe.ReplaceAllString(rest, " ")
	}
	algolia := searchKeyRe.MatchString(key) && !strongKeyRe.MatchString(key) && algoliaKeyRe.MatchString(s)
	if algolia {
		sig("public_algolia_search_key", model.CatHarmless, 0.9, "")
	}
	// 4. A secret-named key (api_secret, password, private_key, token...).
	if keyed && !algolia && isSecretLike(strings.TrimSpace(rest)) {
		sig("secret_key_name", model.CatSecret, 0.85, s)
	}
	// 5. Randomness alone is never more than "needs review".
	if !siteKeyRe.MatchString(key) {
		if tok := userinfoToken(rest); tok != "" {
			sig("url_userinfo", model.CatPossibleSecret, 0.5, tok)
		}
		if tok := highEntropyToken(rest); tok != "" {
			sig("high_entropy", model.CatPossibleSecret, 0.5, tok)
		}
	}
	out = append(out, scanInternal(s, path)...)
	if hasStandaloneEmail(s) {
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

// isSecretKey reports whether a JSON key names a credential.
func isSecretKey(key string) bool {
	k := strings.ToLower(strings.NewReplacer("_", "", "-", "", ".", "", " ", "").Replace(key))
	if k == "" {
		return false
	}
	for _, suf := range secretKeySuffixes {
		if strings.HasSuffix(k, suf) {
			return true
		}
	}
	return false
}

// isSecretLike reports whether the value under a secret-named key looks like
// credential material rather than a setting ("required"), a placeholder
// ("${API_SECRET}") or a URL. It needs a digit, a symbol, inner capitals or
// at least 12 letters.
func isSecretLike(s string) bool {
	if len(s) < 8 || strings.ContainsAny(s, " \t\n") || strings.Contains(s, "://") || placeholderRe.MatchString(s) {
		return false
	}
	letters := true
	for i, r := range s {
		switch {
		case r >= '0' && r <= '9', strings.ContainsRune("!@#$%^&*+=~?/", r):
			return true
		case r >= 'A' && r <= 'Z':
			if i > 0 {
				return true
			}
		case r >= 'a' && r <= 'z':
		default:
			letters = false
		}
	}
	return letters && len(s) >= 12
}

// userinfoToken returns a long password-less userinfo such as the token in
// https://<token>@host. With no password and no known format it is only a
// possible secret.
func userinfoToken(s string) string {
	for _, m := range userinfoRe.FindAllStringSubmatch(s, -1) {
		if u := m[2]; len(u) >= 16 && !strings.Contains(u, ":") && !placeholderRe.MatchString(u) {
			return u
		}
	}
	return ""
}

// hasStandaloneEmail reports a local@domain.tld address that stands on its
// own. Anything inside a URL (DSNs, connection strings, query parameters)
// and user:pass@host credentials are not e-mail addresses.
func hasStandaloneEmail(s string) bool {
	s = anyURLRe.ReplaceAllString(s, " ")
	for _, loc := range emailRe.FindAllStringIndex(s, -1) {
		if loc[0] == 0 {
			return true
		}
		switch s[loc[0]-1] {
		case '/', '@':
			continue
		case ':':
			if !strings.HasSuffix(strings.ToLower(s[:loc[0]]), "mailto:") {
				continue
			}
		}
		return true
	}
	return false
}

// stripEmails blanks standalone e-mail addresses so their domain is not
// mistaken for a hostname.
func stripEmails(s string) string {
	return emailRe.ReplaceAllString(s, " ")
}

func scanInternal(s, path string) []Signal {
	var out []Signal
	add := func(kind string, conf float64) {
		out = append(out, Signal{Kind: kind, Category: model.CatInternalURL, Path: path, Confidence: conf})
	}
	// Drop URL userinfo first: in postgres://app:pw@db.internal the host is
	// db.internal, and "pw@db.internal" is not an e-mail address.
	s = userinfoRe.ReplaceAllString(s, "$1")
	if rfc1918Re.MatchString(s) {
		add("private_ip", 0.9)
	}
	if localhostRe.MatchString(s) {
		add("localhost", 0.8)
	}
	for _, h := range hostRe.FindAllString(stripEmails(s), -1) {
		if internalWord.MatchString(h) || internalTLD.MatchString(h) {
			add("internal_host", 0.85)
			break
		}
	}
	return out
}

// highEntropyToken returns the first token of s that looks like random key
// material: at least 20 characters, Shannon entropy above 3.5, and either
// mixed upper/lower/digit or a long hex string. URLs (image and asset links
// included), base64 data URIs, e-mail addresses, UUIDs and 32/40/64-character
// lowercase hex digests (MD5, git SHA-1, SHA-256) are ordinary product data
// and never trigger it.
func highEntropyToken(s string) string {
	s = dataURIRe.ReplaceAllString(s, " ")
	s = anyURLRe.ReplaceAllString(s, " ")
	s = emailRe.ReplaceAllString(s, " ")
	for _, tok := range tokenRe.FindAllString(s, -1) {
		if uuidRe.MatchString(tok) || isDigest(tok) || Entropy(tok) <= 3.5 {
			continue
		}
		if hasAllClasses(tok) || (len(tok) >= 32 && hexRe.MatchString(tok)) {
			return tok
		}
	}
	return ""
}

func isDigest(tok string) bool {
	return (len(tok) == 32 || len(tok) == 40 || len(tok) == 64) && lowerHexRe.MatchString(tok)
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
// POSSIBLE_SECRET comes last: any firmer signal wins over a guess.
var categoryOrder = []model.Category{
	model.CatSecret, model.CatInternalURL, model.CatPII,
	model.CatUnreleasedProduct, model.CatPricing, model.CatSecurityControl,
	model.CatPossibleSecret,
}

// publicNotes maps informational signal kinds to their hardening note.
var publicNotes = func() map[string]string {
	m := map[string]string{"public_recaptcha_site_key": noteRecaptcha, "public_algolia_search_key": noteAlgolia}
	for _, p := range publicPatterns {
		m[p.kind] = p.note
	}
	return m
}()

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
		if note, ok := publicNotes[s.Kind]; ok && c.Category == model.CatHarmless {
			c.Rationale = fmt.Sprintf("info: %s (value at %s); not a secret", note, s.Path)
		}
	}
	return c
}

func rationale(cat model.Category, s Signal) string {
	where := "flag name"
	if s.Path != "name" {
		where = "value at " + s.Path
	}
	if cat == model.CatPossibleSecret {
		return fmt.Sprintf("possible secret, needs review: %s looks random (%s) but matches no known secret pattern, secret-named key or URL credential", where, s.Kind)
	}
	return fmt.Sprintf("%s detected in %s (%s)", strings.ToLower(strings.ReplaceAll(string(cat), "_", " ")), where, s.Kind)
}
