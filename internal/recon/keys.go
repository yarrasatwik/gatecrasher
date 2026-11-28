package recon

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/yarrasatwik/gatecrasher/internal/redact"
	"github.com/yarrasatwik/gatecrasher/internal/secrets"
)

var (
	envIDRe     = regexp.MustCompile(`(?i)environment_?id["']?\s*[:=]\s*["']([A-Za-z0-9]{16,40})["']`)
	envIdentRe  = regexp.MustCompile(`(?i)environment_?id["']?\s*[:=]\s*([A-Za-z_$][\w$]*)`)
	flagsEnvRe  = regexp.MustCompile(`(?i)(FLAGSMITH_(?:ENVIRONMENT|ENV)_?ID)["']?\s*[:=]\s*["']([A-Za-z0-9]{16,40})["']`)
	flagsAPIRe  = regexp.MustCompile(`(?i)FLAGSMITH_API(?:_URL)?["']?\s*[:=]\s*["']((?:https?://|/)[^"']+)["']`)
	envHeaderRe = regexp.MustCompile(`(?i)x-environment-key["']?\s*[:,=]\s*["']([A-Za-z0-9]{16,40})["']`)
	quoted22Re  = regexp.MustCompile(`["']([A-Za-z0-9]{22})["']`)
	serverKeyRe = regexp.MustCompile(`ser\.[A-Za-z0-9_-]{8,}`)
	apiOptionRe = regexp.MustCompile(`(?i)\bapi["']?\s*:\s*["']((?:https?://|/)[^"']+)["']`)

	setTraitRe    = regexp.MustCompile(`setTrait\(\s*["']([\w.\-]+)["']`)
	setTraitsRe   = regexp.MustCompile(`setTraits\(\s*\{([^}]*)\}`)
	identifyRe    = regexp.MustCompile(`identify\(\s*[^,(){}]+,\s*\{([^}]*)\}`)
	objectKeyRe   = regexp.MustCompile(`^\s*["']?([A-Za-z_][\w\-]*)["']?\s*(?::|$)`)
	nearbyWindow  = 400
	flagsmithHint = regexp.MustCompile(`(?i)flagsmith|environmentid`)
)

// candidate is a possible client-side environment key and where it was seen.
type candidate struct {
	key     string
	sources []string
	rank    int // lower is stronger evidence
}

// leak is a server-side key found in a public bundle.
type leak struct {
	source      string
	fingerprint string
}

// extraction is everything recon learns from the scripts.
type extraction struct {
	candidates []*candidate
	leaks      []leak
	apiURLs    []string
	traitKeys  []string
}

type extractor struct {
	byKey  map[string]*candidate
	apiSet map[string]bool
	traits map[string]bool
	out    extraction
}

// extract scans every source for keys, API hosts, leaked server keys and
// trait names. Discovered keys are registered with redact immediately.
func extract(srcs []source) extraction {
	e := &extractor{byKey: map[string]*candidate{}, apiSet: map[string]bool{}, traits: map[string]bool{}}
	for _, s := range srcs {
		e.scan(s)
	}
	cands := make([]*candidate, 0, len(e.byKey))
	for _, c := range e.byKey {
		cands = append(cands, c)
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].rank != cands[j].rank {
			return cands[i].rank < cands[j].rank
		}
		return cands[i].sources[0] < cands[j].sources[0]
	})
	e.out.candidates = cands
	for t := range e.traits {
		e.out.traitKeys = append(e.out.traitKeys, t)
	}
	sort.Strings(e.out.traitKeys)
	return e.out
}

func (e *extractor) scan(s source) {
	if !(s.json && e.addJSON(s)) {
		e.addKeys(s, envIDRe, "environmentID", 0)
		e.addFlagsmithEnv(s)
		e.addIdentifierKeys(s)
		e.addKeys(s, envHeaderRe, "X-Environment-Key", 1)
	}
	e.addNearby(s)
	e.addServerKeys(s)
	e.addAPIURLs(s)
	e.addTraits(s)
}

func (e *extractor) addKeys(s source, re *regexp.Regexp, what string, rank int) {
	for _, m := range re.FindAllStringSubmatchIndex(s.text, -1) {
		if what == "environmentID" && m[0] > 0 && s.text[m[0]-1] == '_' {
			continue // FLAGSMITH_ENVIRONMENT_ID and friends have their own pass
		}
		e.addCandidate(s, s.text[m[2]:m[3]], m[2], what, rank)
	}
}

// addFlagsmithEnv finds FLAGSMITH_ENVIRONMENT_ID style config keys.
func (e *extractor) addFlagsmithEnv(s source) {
	for _, m := range flagsEnvRe.FindAllStringSubmatchIndex(s.text, -1) {
		e.addCandidate(s, s.text[m[4]:m[5]], m[4], s.text[m[2]:m[3]], 0)
	}
}

// addIdentifierKeys handles environmentID passed as a bare identifier, as in
// minified bundles: it looks for the identifier's string assignment anywhere
// in the file (K="...", const K="...", {K:"..."}). A match is strong evidence.
func (e *extractor) addIdentifierKeys(s source) {
	done := map[string]bool{}
	for _, m := range envIdentRe.FindAllStringSubmatchIndex(s.text, -1) {
		ident := s.text[m[2]:m[3]]
		if m[1] < len(s.text) && strings.ContainsRune(".([", rune(s.text[m[1]])) {
			continue // a property access or call, not a bare identifier
		}
		switch ident {
		case "true", "false", "null", "undefined", "void", "window", "process":
			continue
		}
		if done[ident] {
			continue
		}
		done[ident] = true
		re := regexp.MustCompile(`(?:^|[^\w$.])` + regexp.QuoteMeta(ident) + `\s*[:=]\s*["']([A-Za-z0-9]{16,40})["']`)
		for _, a := range re.FindAllStringSubmatchIndex(s.text, 5) {
			e.addCandidate(s, s.text[a[2]:a[3]], a[2], "environmentID via "+ident, 0)
		}
	}
}

// addJSON scans a JSON data block (__NEXT_DATA__, __NUXT_DATA__, ...) for
// environment keys and API URLs. It returns false when the block is not valid
// JSON so the caller can fall back to plain text scanning.
func (e *extractor) addJSON(s source) bool {
	var doc any
	if err := json.Unmarshal([]byte(s.text), &doc); err != nil {
		return false
	}
	e.walkJSON(s, doc)
	return true
}

var jsonKeyRe = regexp.MustCompile(`^[A-Za-z0-9]{16,40}$`)

func normKey(k string) string {
	return strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(k))
}

func isEnvKeyName(k string) bool {
	n := normKey(k)
	if strings.Contains(n, "environmentid") {
		return true
	}
	return strings.HasPrefix(n, "flagsmith") && (strings.HasSuffix(n, "envid") || strings.HasSuffix(n, "envkey") || strings.HasSuffix(n, "environmentkey"))
}

func isAPIKeyName(k string, hasEnv bool) bool {
	n := normKey(k)
	if strings.HasPrefix(n, "flagsmith") && strings.Contains(n, "api") {
		return true
	}
	return hasEnv && (n == "api" || n == "apiurl" || n == "baseurl" || n == "apihost")
}

func (e *extractor) walkJSON(s source, node any) {
	switch v := node.(type) {
	case []any:
		for _, x := range v {
			e.walkJSON(s, x)
		}
	case map[string]any:
		keys := make([]string, 0, len(v))
		hasEnv := false
		for k, x := range v {
			keys = append(keys, k)
			if str, ok := x.(string); ok && isEnvKeyName(k) && jsonKeyRe.MatchString(str) {
				hasEnv = true
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			switch x := v[k].(type) {
			case string:
				switch {
				case isEnvKeyName(k) && jsonKeyRe.MatchString(x):
					e.addCandidate(s, x, jsonOffset(s.text, x), k, 0)
				case isAPIKeyName(k, hasEnv) && (strings.HasPrefix(x, "http://") || strings.HasPrefix(x, "https://") || strings.HasPrefix(x, "/")):
					if !e.apiSet[x] {
						e.apiSet[x] = true
						e.out.apiURLs = append(e.out.apiURLs, x)
					}
				}
			default:
				e.walkJSON(s, x)
			}
		}
	}
}

// jsonOffset finds the byte offset of a string value in the raw JSON text.
func jsonOffset(text, val string) int {
	if i := strings.Index(text, `"`+val+`"`); i >= 0 {
		return i + 1
	}
	if i := strings.Index(text, val); i >= 0 {
		return i
	}
	return 0
}

func (e *extractor) addNearby(s source) {
	for _, m := range quoted22Re.FindAllStringSubmatchIndex(s.text, -1) {
		tok := s.text[m[2]:m[3]]
		lo, hi := max(0, m[0]-nearbyWindow), min(len(s.text), m[1]+nearbyWindow)
		if e.byKey[tok] == nil && flagsmithHint.MatchString(s.text[lo:hi]) && keyShaped(tok) {
			e.addCandidate(s, tok, m[2], "key-shaped string near flagsmith", 2)
		}
	}
}

// keyShaped rejects plain words: a Flagsmith client key mixes letters and
// digits and has high entropy.
func keyShaped(tok string) bool {
	hasDigit, hasLetter := false, false
	for _, r := range tok {
		hasDigit = hasDigit || (r >= '0' && r <= '9')
		hasLetter = hasLetter || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
	}
	return hasDigit && hasLetter && secrets.Entropy(tok) > 3.0
}

func (e *extractor) addCandidate(s source, key string, off int, what string, rank int) {
	redact.Register(key, "CLIENT_KEY")
	c := e.byKey[key]
	if c == nil {
		c = &candidate{key: key, rank: rank}
		e.byKey[key] = c
	}
	c.rank = min(c.rank, rank)
	c.sources = append(c.sources, fmt.Sprintf("%s:%d %s", s.label, lineAt(s.text, off), what))
}

func (e *extractor) addServerKeys(s source) {
	for _, m := range serverKeyRe.FindAllStringIndex(s.text, -1) {
		key := s.text[m[0]:m[1]]
		redact.Register(key, "SERVER_KEY")
		e.out.leaks = append(e.out.leaks, leak{
			source:      fmt.Sprintf("%s:%d", s.label, lineAt(s.text, m[0])),
			fingerprint: redact.Fingerprint(key, "SERVER_KEY"),
		})
	}
}

func (e *extractor) addAPIURLs(s source) {
	for _, m := range flagsAPIRe.FindAllStringSubmatch(s.text, -1) {
		if !e.apiSet[m[1]] {
			e.apiSet[m[1]] = true
			e.out.apiURLs = append(e.out.apiURLs, m[1])
		}
	}
	for _, m := range apiOptionRe.FindAllStringSubmatchIndex(s.text, -1) {
		lo, hi := max(0, m[0]-nearbyWindow*3/2), min(len(s.text), m[1]+nearbyWindow*3/2)
		if !flagsmithHint.MatchString(s.text[lo:hi]) {
			continue
		}
		if v := s.text[m[2]:m[3]]; !e.apiSet[v] {
			e.apiSet[v] = true
			e.out.apiURLs = append(e.out.apiURLs, v)
		}
	}
}

func (e *extractor) addTraits(s source) {
	for _, m := range setTraitRe.FindAllStringSubmatch(s.text, -1) {
		e.traits[m[1]] = true
	}
	for _, re := range []*regexp.Regexp{setTraitsRe, identifyRe} {
		for _, m := range re.FindAllStringSubmatch(s.text, -1) {
			for _, part := range strings.Split(m[1], ",") {
				if k := objectKeyRe.FindStringSubmatch(part); k != nil {
					e.traits[k[1]] = true
				}
			}
		}
	}
}

// resolveAPI picks the Flagsmith API base URL. Candidates found in the bundle
// are resolved against the page; the first in scope wins. If the bundle names
// API hosts but none is in scope, recon refuses with an error rather than
// falling back silently.
func resolveAPI(found []string, base *url.URL, configured string, allowed func(string) error) (string, []string, error) {
	var notes []string
	var firstErr error
	for _, raw := range found {
		ref, err := url.Parse(raw)
		if err != nil {
			continue
		}
		abs := base.ResolveReference(ref).String()
		if err := allowed(abs); err != nil {
			notes = append(notes, "refused API host from bundle: "+redact.String(abs))
			if firstErr == nil {
				firstErr = fmt.Errorf("bundle points at Flagsmith API %s which is out of scope: add its host to allowed_api_hosts to permit it: %w", redact.String(abs), err)
			}
			continue
		}
		return abs, notes, nil
	}
	if firstErr != nil {
		return "", notes, firstErr
	}
	if configured == "" {
		return "", notes, fmt.Errorf("no Flagsmith API URL found in the bundle and none configured")
	}
	if err := allowed(configured); err != nil {
		return "", notes, fmt.Errorf("configured Flagsmith API URL is out of scope: %w", err)
	}
	return configured, notes, nil
}
