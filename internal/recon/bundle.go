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

// maxScripts bounds how many script resources one recon run will fetch.
const maxScripts = 30

var (
	scriptTagRe = regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script>`)
	srcAttrRe   = regexp.MustCompile(`(?i)\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	typeAttrRe  = regexp.MustCompile(`(?i)\btype\s*=\s*["']?([^"'\s>]+)`)
)

// source is one piece of JavaScript (or the page) to scan for keys.
type source struct {
	label string // "app.js" or "inline-1"; used as the file in file:line
	text  string
}

// pageScripts parses the page HTML and returns the inline scripts plus the
// resolved external script URLs, in document order without duplicates.
func pageScripts(page string, base *url.URL) (inline []source, external []*url.URL, notes []string) {
	seen := map[string]bool{}
	for _, m := range scriptTagRe.FindAllStringSubmatch(page, -1) {
		attrs, body := m[1], m[2]
		if t := typeAttrRe.FindStringSubmatch(attrs); t != nil && strings.Contains(strings.ToLower(t[1]), "json") {
			continue
		}
		sm := srcAttrRe.FindStringSubmatch(attrs)
		if sm == nil {
			if strings.TrimSpace(body) != "" {
				inline = append(inline, source{label: fmt.Sprintf("inline-%d", len(inline)+1), text: body})
			}
			continue
		}
		raw := firstNonEmpty(sm[1], sm[2], sm[3])
		ref, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || raw == "" {
			notes = append(notes, "skipped unparseable script src")
			continue
		}
		abs := base.ResolveReference(ref)
		abs.Fragment = ""
		if !seen[abs.String()] {
			seen[abs.String()] = true
			external = append(external, abs)
		}
	}
	return inline, external, notes
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

// fetchScripts downloads every in-scope script. Out-of-scope scripts are
// skipped and recorded as notes; they are never requested.
func fetchScripts(ctx context.Context, c *httpx.Client, urls []*url.URL) (out []source, notes []string) {
	for i, u := range urls {
		if i >= maxScripts {
			notes = append(notes, fmt.Sprintf("script limit reached: %d further scripts not fetched", len(urls)-maxScripts))
			break
		}
		if err := c.Lock().Check(u); err != nil {
			notes = append(notes, fmt.Sprintf("skipped out-of-scope script %s%s: host not in allowed_domains", u.Host, redact.String(u.Path)))
			continue
		}
		resp, err := c.Do(ctx, httpx.Request{URL: u.String()})
		if err != nil {
			notes = append(notes, fmt.Sprintf("could not fetch script %s: %s", u.Path, redact.String(err.Error())))
			continue
		}
		if !resp.OK() {
			notes = append(notes, fmt.Sprintf("script %s returned HTTP %d", u.Path, resp.Status))
			continue
		}
		out = append(out, source{label: scriptLabel(u), text: string(resp.Body)})
	}
	return out, notes
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
