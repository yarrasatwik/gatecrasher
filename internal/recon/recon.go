// Package recon performs Stage 1 of Gatecrasher (spec §8.1): it fetches the
// target page, scans its in-scope JavaScript for Flagsmith client keys, checks
// each candidate with one GET flags/ call and builds the public inventory an
// anonymous visitor could see. It only reads, and every request goes through
// the scope-locked httpx client.
package recon

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
	"github.com/yarrasatwik/gatecrasher/internal/httpx"
	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

// maxCandidates bounds how many candidate keys are validated per run.
const maxCandidates = 10

// ReconConfig configures one recon run.
type ReconConfig struct {
	// TargetURL is the page to fetch; its host must be in scope.
	TargetURL string
	// APIURL is the Flagsmith API base URL (for example http://localhost:8000/api/v1/)
	// used when the bundle does not declare one.
	APIURL string
	// MaxScripts bounds how many scripts and chunks are fetched. Zero means
	// DefaultMaxScripts (60); it comes from recon.max_scripts.
	MaxScripts int
	// SuppliedKeys are client keys the operator gave (GATECRASHER_CLIENT_KEYS,
	// environment name to key). They are only tried when the page and its
	// scripts yield no candidate, for apps whose key is not in a web bundle.
	SuppliedKeys map[string]string
}

// Leak is a server-side key found in a public bundle. It is always a
// CRITICAL finding: server keys must never ship to browsers.
type Leak struct {
	Source      string         `json:"source"` // file:line
	Fingerprint string         `json:"fingerprint"`
	Severity    model.Severity `json:"severity"`
}

// Candidate records one candidate key and whether the API accepted it.
type Candidate struct {
	Fingerprint string   `json:"fingerprint"`
	Sources     []string `json:"sources"`
	Valid       bool     `json:"valid"`
}

// Result is the full outcome of a recon run.
type Result struct {
	Inventory  *model.PublicInventory
	Candidates []Candidate
	// Leaks lists server-side keys found in bundles (CRITICAL).
	Leaks []Leak
	// Notes records skipped out-of-scope scripts, refused hosts and other
	// observations for the report.
	Notes []string

	tried tried
}

// Recon runs Stage 1 and returns the public inventory.
func Recon(ctx context.Context, c *httpx.Client, cfg ReconConfig) (*model.PublicInventory, error) {
	r, err := Run(ctx, c, cfg)
	if err != nil {
		return nil, err
	}
	return r.Inventory, nil
}

// Run is Recon with the extra detail (notes, candidates, key leaks).
func Run(ctx context.Context, c *httpx.Client, cfg ReconConfig) (*Result, error) {
	base, srcs, res, err := gather(ctx, c, cfg.TargetURL, cfg.MaxScripts)
	if err != nil {
		return nil, err
	}
	ex := extract(srcs)
	if len(ex.candidates) == 0 {
		ex.candidates = suppliedCandidates(cfg.SuppliedKeys)
		if len(ex.candidates) > 0 {
			res.Notes = append(res.Notes, "no client key found in the page or its scripts; trying the key(s) from GATECRASHER_CLIENT_KEYS")
		}
	}
	for _, l := range ex.leaks {
		res.Leaks = append(res.Leaks, Leak{Source: l.source, Fingerprint: l.fingerprint, Severity: model.SevCritical})
		res.Notes = append(res.Notes, fmt.Sprintf("CRITICAL: server-side key %s found in public bundle at %s", l.fingerprint, l.source))
	}
	if len(ex.candidates) == 0 {
		return res, noKeyError(res.tried, 0, "")
	}
	api, notes, err := resolveAPI(ex.apiURLs, base, cfg.APIURL, c.Lock().CheckURL)
	res.Notes = append(res.Notes, notes...)
	if err != nil {
		return res, err
	}
	inv := &model.PublicInventory{TargetURL: cfg.TargetURL, APIURL: api, TraitKeys: ex.traitKeys, FetchedAt: time.Now().UTC()}
	res.Inventory = inv
	if err := validate(ctx, c, ex.candidates, api, res); err != nil {
		return res, err
	}
	return res, nil
}

// gather fetches the page, its scripts, its JSON data blocks and, one level
// deep, the chunks those scripts preload or import.
func gather(ctx context.Context, c *httpx.Client, target string, maxScripts int) (*url.URL, []source, *Result, error) {
	resp, err := c.Do(ctx, httpx.Request{URL: target})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("fetch target: %w", err)
	}
	if !resp.OK() {
		return nil, nil, nil, fmt.Errorf("fetch target: HTTP %d", resp.Status)
	}
	base, err := url.Parse(resp.URL)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse target URL: %w", err)
	}
	p := parsePage(string(resp.Body), base)
	f := newFetcher(c, maxScripts)
	res := &Result{Notes: p.notes}
	res.tried = tried{inline: len(p.inline), json: len(p.json)}

	srcs := append(append([]source{}, p.inline...), p.json...)
	holders := make([]holder, 0, len(p.inline)+len(p.external))
	for _, s := range p.inline {
		holders = append(holders, holder{text: s.text})
	}
	for _, u := range p.external {
		if s, ok := f.get(ctx, u, "script"); ok {
			res.tried.linked++
			srcs = append(srcs, s)
			holders = append(holders, holder{url: u, text: s.text})
		}
	}
	for _, u := range p.links {
		if !sameOrigin(u, base) {
			if !f.seen[u.String()] {
				f.seen[u.String()] = true
				f.notes = append(f.notes, fmt.Sprintf("skipped cross-origin chunk %s%s: not on the page's origin", u.Host, redact.String(u.Path)))
			}
			continue
		}
		if s, ok := f.get(ctx, u, "chunk"); ok {
			res.tried.chunks++
			srcs = append(srcs, s)
			holders = append(holders, holder{url: u, text: s.text})
		}
	}
	// One level deep: chunks referenced by the page's own scripts. Chunks
	// found this way are scanned but not followed further.
	srcs = append(srcs, f.followChunks(ctx, base, holders, &res.tried)...)
	res.Notes = append(res.Notes, f.finish()...)
	return base, srcs, res, nil
}

// suppliedCandidates turns GATECRASHER_CLIENT_KEYS into candidates, in a
// stable order.
func suppliedCandidates(keys map[string]string) []*candidate {
	names := make([]string, 0, len(keys))
	for n := range keys {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []*candidate
	for _, n := range names {
		redact.Register(keys[n], "CLIENT_KEY")
		out = append(out, &candidate{key: keys[n], rank: 3, sources: []string{"GATECRASHER_CLIENT_KEYS (" + n + ")"}})
	}
	return out
}

// noKeyError says what recon tried and how to supply the key by hand.
func noKeyError(t tried, checked int, api string) error {
	what := fmt.Sprintf("tried %d inline script(s), %d JSON data block(s), %d linked script(s) and %d imported or preloaded chunk(s), looking for environmentID, FLAGSMITH_ENVIRONMENT_ID and key-shaped strings near \"flagsmith\"", t.inline, t.json, t.linked, t.chunks)
	if checked > 0 {
		what += fmt.Sprintf("; %d candidate(s) checked against %s, none accepted", checked, redact.String(api))
	} else {
		what += "; nothing found"
	}
	return fmt.Errorf("no valid Flagsmith client key found: %s. Fix: set GATECRASHER_CLIENT_KEYS=Production=<key> for apps whose key isn't in a web bundle (mobile apps, server-rendered pages)", what)
}

// validate checks each candidate with one GET flags/ and fills the inventory
// from the first key the API accepts.
func validate(ctx context.Context, c *httpx.Client, cands []*candidate, api string, res *Result) error {
	if len(cands) > maxCandidates {
		res.Notes = append(res.Notes, fmt.Sprintf("%d candidate keys found; only the first %d were validated", len(cands), maxCandidates))
		cands = cands[:maxCandidates]
	}
	inv := res.Inventory
	for _, cand := range cands {
		fp := redact.Fingerprint(cand.key, "CLIENT_KEY")
		flags, _, err := flagsmith.NewSDK(c, api, cand.key).EnvironmentFlags(ctx)
		res.Candidates = append(res.Candidates, Candidate{Fingerprint: fp, Sources: cand.sources, Valid: err == nil})
		if err != nil {
			res.Notes = append(res.Notes, fmt.Sprintf("candidate key %s rejected: %s", fp, redact.String(err.Error())))
			continue
		}
		if inv.Key != "" {
			res.Notes = append(res.Notes, fmt.Sprintf("additional valid client key %s at %s (second environment?)", fp, strings.Join(cand.sources, ", ")))
			continue
		}
		inv.Key, inv.KeyFingerprint, inv.KeySources = cand.key, fp, cand.sources
		inv.Flags = flagViews(flags)
	}
	if inv.Key == "" {
		return noKeyError(res.tried, len(cands), api)
	}
	return nil
}

func flagViews(flags flagsmith.Flags) []model.FlagView {
	names := flags.Names()
	sort.Strings(names)
	out := make([]model.FlagView, 0, len(names))
	for _, n := range names {
		out = append(out, flagView(flags[n]))
	}
	return out
}
