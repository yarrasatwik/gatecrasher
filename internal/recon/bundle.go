package recon

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/yarrasatwik/gatecrasher/internal/httpx"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

// DefaultMaxScripts bounds how many script resources one recon run fetches
// when ReconConfig.MaxScripts is not set (recon.max_scripts in the config).
const DefaultMaxScripts = 60

var (
	scriptTagRe = regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script>`)
	linkTagRe   = regexp.MustCompile(`(?is)<link\b([^>]*)>`)
)

// source is one piece of JavaScript, JSON or page text to scan for keys.
type source struct {
	label string // "app.js", "inline-1" or "__NEXT_DATA__"; the file in file:line
	text  string
	json  bool // a type="application/json" data block
}

// tried counts what recon looked at, for the "no key found" message.
type tried struct {
	inline, json, linked, chunks int
}

// pageParts is what the page HTML itself contributes.
type pageParts struct {
	inline   []source   // inline scripts
	json     []source   // JSON data blocks (__NEXT_DATA__, __NUXT_DATA__, ...)
	external []*url.URL // <script src>
	links    []*url.URL // modulepreload / preload as=script
	notes    []string
}

// attr returns the value of an HTML attribute, case-insensitively.
func attr(attrs, name string) (string, bool) {
	re := regexp.MustCompile(`(?i)(?:^|\s)` + regexp.QuoteMeta(name) + `\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	m := re.FindStringSubmatch(attrs)
	if m == nil {
		return "", false
	}
	return firstNonEmpty(m[1], m[2], m[3]), true
}

// parsePage splits the page into inline scripts, JSON data blocks, script
// URLs and preload links, in document order without duplicate URLs.
func parsePage(page string, base *url.URL) pageParts {
	var p pageParts
	seen := map[string]bool{}
	resolve := func(raw, what string) *url.URL {
		ref, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || strings.TrimSpace(raw) == "" {
			p.notes = append(p.notes, "skipped unparseable "+what)
			return nil
		}
		abs := base.ResolveReference(ref)
		abs.Fragment = ""
		if seen[abs.String()] {
			return nil
		}
		seen[abs.String()] = true
		return abs
	}
	for _, m := range scriptTagRe.FindAllStringSubmatch(page, -1) {
		attrs, body := m[1], m[2]
		if t, ok := attr(attrs, "type"); ok && strings.Contains(strings.ToLower(t), "json") {
			if strings.TrimSpace(body) != "" {
				label, ok := attr(attrs, "id")
				if !ok || label == "" {
					label = fmt.Sprintf("json-%d", len(p.json)+1)
				}
				p.json = append(p.json, source{label: label, text: body, json: true})
			}
			continue
		}
		raw, ok := attr(attrs, "src")
		if !ok {
			if strings.TrimSpace(body) != "" {
				p.inline = append(p.inline, source{label: fmt.Sprintf("inline-%d", len(p.inline)+1), text: body})
			}
			continue
		}
		if u := resolve(raw, "script src"); u != nil {
			p.external = append(p.external, u)
		}
	}
	for _, m := range linkTagRe.FindAllStringSubmatch(page, -1) {
		rel, _ := attr(m[1], "rel")
		as, _ := attr(m[1], "as")
		rel = strings.ToLower(rel)
		if !strings.Contains(rel, "modulepreload") && !(strings.Contains(rel, "preload") && strings.EqualFold(as, "script")) {
			continue
		}
		if href, ok := attr(m[1], "href"); ok {
			if u := resolve(href, "preload link"); u != nil {
				p.links = append(p.links, u)
			}
		}
	}
	return p
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

// fetcher downloads in-scope scripts under one cap, remembering what it has
// fetched so nothing is requested twice. Out-of-scope URLs are never requested.
type fetcher struct {
	c        *httpx.Client
	max      int
	fetched  int
	overflow int
	seen     map[string]bool
	notes    []string
}

func newFetcher(c *httpx.Client, max int) *fetcher {
	if max <= 0 {
		max = DefaultMaxScripts
	}
	return &fetcher{c: c, max: max, seen: map[string]bool{}}
}

// get fetches u unless it was fetched before, is out of scope, or the cap is
// reached. kind is "script" or "chunk" and only shapes the notes.
func (f *fetcher) get(ctx context.Context, u *url.URL, kind string) (source, bool) {
	if f.seen[u.String()] {
		return source{}, false
	}
	f.seen[u.String()] = true
	if err := f.c.Lock().Check(u); err != nil {
		f.notes = append(f.notes, fmt.Sprintf("skipped out-of-scope %s %s%s: host not in allowed_domains", kind, u.Host, redact.String(u.Path)))
		return source{}, false
	}
	if f.fetched >= f.max {
		f.overflow++
		return source{}, false
	}
	f.fetched++
	resp, err := f.c.Do(ctx, httpx.Request{URL: u.String()})
	if err != nil {
		f.notes = append(f.notes, fmt.Sprintf("could not fetch %s %s: %s", kind, u.Path, redact.String(err.Error())))
		return source{}, false
	}
	if !resp.OK() {
		f.notes = append(f.notes, fmt.Sprintf("%s %s returned HTTP %d", kind, u.Path, resp.Status))
		return source{}, false
	}
	return source{label: scriptLabel(u), text: string(resp.Body)}, true
}

// finish returns the notes, including the cap note when scripts were dropped.
func (f *fetcher) finish() []string {
	if f.overflow > 0 {
		f.notes = append(f.notes, fmt.Sprintf("script limit reached (%d): %d further scripts not fetched; raise recon.max_scripts to fetch them", f.max, f.overflow))
	}
	return f.notes
}

// sameOrigin reports whether a and b share scheme and host:port.
func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

// followChunks fetches the chunks that scripts reference, one level deep.
// Each reference resolves against the script that holds it (or against the
// page for inline code and Vite dependency maps). A chunk must be on the
// origin of the page or of the script that references it, and in scope.
func (f *fetcher) followChunks(ctx context.Context, base *url.URL, holders []holder, t *tried) []source {
	var out []source
	for _, h := range holders {
		for _, r := range chunkRefs(h.text) {
			from := h.url
			if r.fromPage || from == nil {
				from = base
			}
			ref, err := url.Parse(r.ref)
			if err != nil {
				continue
			}
			u := from.ResolveReference(ref)
			u.Fragment = ""
			if u.Scheme != "http" && u.Scheme != "https" {
				continue
			}
			if !sameOrigin(u, base) && !sameOrigin(u, from) {
				if !f.seen[u.String()] {
					f.seen[u.String()] = true
					f.notes = append(f.notes, fmt.Sprintf("skipped cross-origin chunk %s%s: not on the page's origin", u.Host, redact.String(u.Path)))
				}
				continue
			}
			if s, ok := f.get(ctx, u, "chunk"); ok {
				t.chunks++
				out = append(out, s)
			}
		}
	}
	return out
}

// holder is a script whose text may reference chunks.
type holder struct {
	url  *url.URL // nil for inline scripts
	text string
}

var (
	importFromRe = regexp.MustCompile(`\b(?:from|import)\s*["']([^"'\s]+)["']`)
	dynImportRe  = regexp.MustCompile(`\bimport\s*\(\s*["']([^"'\s]+)["']\s*\)`)
	viteDepsRe   = regexp.MustCompile(`(?:__vite__mapDeps\s*\(\s*\[|m\.f\s*\|\|\s*\(\s*m\.f\s*=\s*\[)([^\]]*)\]`)
	quotedRe     = regexp.MustCompile(`["']([^"'\s]+)["']`)
	wpURLFuncRe  = regexp.MustCompile(`\.u\s*=\s*(?:function\s*\(\s*\w+\s*\)\s*\{\s*return\s*|\(?\s*\w+\s*\)?\s*=>\s*)([^;]*)`)
	wpPublicRe   = regexp.MustCompile(`\.p\s*=\s*["']([^"']*)["']`)
	wpMapRe      = regexp.MustCompile(`\{([^{}]*)\}\s*\[\s*\w+\s*\]`)
	wpPairRe     = regexp.MustCompile(`["']?([\w.\-@/]+)["']?\s*:\s*["']([^"']*)["']`)
	bareIdentRe  = regexp.MustCompile(`^\w+$`)
	wpStringRe   = regexp.MustCompile(`^["']([^"']*)["']$`)
)

// chunkRef is a script reference found in code.
type chunkRef struct {
	ref      string
	fromPage bool // resolve against the page URL, not the holding script
}

func jsLike(ref string) bool {
	p := ref
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	switch strings.ToLower(path.Ext(p)) {
	case ".js", ".mjs", ".cjs":
		return true
	}
	return false
}

// chunkRefs lists the script files referenced by static imports, dynamic
// imports, Vite dependency maps and webpack chunk maps written as string
// literals. Bare module names ("flagsmith") are ignored.
func chunkRefs(js string) []chunkRef {
	var out []chunkRef
	seen := map[string]bool{}
	add := func(ref string, fromPage bool) {
		if ref != "" && jsLike(ref) && !seen[ref] {
			seen[ref] = true
			out = append(out, chunkRef{ref: ref, fromPage: fromPage})
		}
	}
	for _, re := range []*regexp.Regexp{importFromRe, dynImportRe} {
		for _, m := range re.FindAllStringSubmatch(js, -1) {
			if ref := m[1]; strings.HasPrefix(ref, ".") || strings.HasPrefix(ref, "/") || strings.Contains(ref, "://") {
				add(ref, false)
			}
		}
	}
	for _, m := range viteDepsRe.FindAllStringSubmatch(js, -1) {
		for _, q := range quotedRe.FindAllStringSubmatch(m[1], -1) {
			add(q[1], true)
		}
	}
	for _, ref := range webpackChunks(js) {
		add(ref, false)
	}
	return out
}

// webpackChunks expands a webpack chunk URL function such as
// __webpack_require__.u=e=>"static/chunks/"+e+"."+{123:"abc"}[e]+".js" into
// the URLs it can produce, when every part is a string literal, the chunk id
// or a literal id-to-hash map.
func webpackChunks(js string) []string {
	m := wpURLFuncRe.FindStringSubmatch(js)
	if m == nil {
		return nil
	}
	public := ""
	if p := wpPublicRe.FindStringSubmatch(js); p != nil {
		public = p[1]
	}
	parts := splitPlus(m[1])
	var ids []string
	for _, p := range parts {
		if mm := wpMapRe.FindStringSubmatch(p); mm != nil {
			for _, kv := range wpPairRe.FindAllStringSubmatch(mm[1], -1) {
				ids = append(ids, kv[1])
			}
			break
		}
	}
	var out []string
	for _, id := range ids {
		var b strings.Builder
		ok := true
		for _, p := range parts {
			p = strings.TrimSpace(p)
			switch {
			case wpStringRe.MatchString(p):
				b.WriteString(wpStringRe.FindStringSubmatch(p)[1])
			case wpMapRe.MatchString(p):
				val := ""
				for _, kv := range wpPairRe.FindAllStringSubmatch(wpMapRe.FindStringSubmatch(p)[1], -1) {
					if kv[1] == id {
						val = kv[2]
					}
				}
				b.WriteString(val)
			case bareIdentRe.MatchString(p):
				b.WriteString(id)
			default:
				ok = false
			}
		}
		if ok {
			out = append(out, public+b.String())
		}
	}
	return out
}

// splitPlus splits a JS concatenation on top-level + signs.
func splitPlus(s string) []string {
	var parts []string
	depth, start := 0, 0
	var quote rune
	for i, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == '{' || r == '(' || r == '[':
			depth++
		case r == '}' || r == ')' || r == ']':
			depth--
		case r == '+' && depth == 0:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}

func scriptLabel(u *url.URL) string {
	b := path.Base(u.Path)
	if b == "." || b == "/" || b == "" {
		return u.Host
	}
	return b
}

// lineAt returns the 1-based line of byte offset off in text.
func lineAt(text string, off int) int {
	return 1 + strings.Count(text[:off], "\n")
}
