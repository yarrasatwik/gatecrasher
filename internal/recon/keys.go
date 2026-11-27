package recon

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/yarrasatwik/gatecrasher/internal/redact"
	"github.com/yarrasatwik/gatecrasher/internal/secrets"
)

var (
	envIDRe     = regexp.MustCompile(`(?i)environment(?:ID|Id)["']?\s*[:=]\s*["']([A-Za-z0-9]{16,40})["']`)
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
	e.addKeys(s, envIDRe, "environmentID", 0)
	e.addKeys(s, envHeaderRe, "X-Environment-Key", 1)
	e.addNearby(s)
	e.addServerKeys(s)
	e.addAPIURLs(s)
	e.addTraits(s)
}

func (e *extractor) addKeys(s source, re *regexp.Regexp, what string, rank int) {
	for _, m := range re.FindAllStringSubmatchIndex(s.text, -1) {
		e.addCandidate(s, s.text[m[2]:m[3]], m[2], what, rank)
	}
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
