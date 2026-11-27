package server

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

//go:embed templates static
var assets embed.FS

// pageNames are the full pages; each is parsed together with the layout
// and shared partials.
var pageNames = []string{"dashboard", "report", "plans", "watch", "audit", "message"}

// pageData is the data every full page receives.
type pageData struct {
	Title   string
	Active  string
	CSRF    string
	Notice  string
	Error   string
	Pending int
	HTMXURL string
	HTMXSRI string
	Body    any
}

// notices maps the fixed ?ok= codes to messages, so a link can never put
// arbitrary text on the page.
var notices = map[string]string{
	"approved":   "Plan approved. It has not been applied yet.",
	"rejected":   "Plan rejected. Nothing was changed.",
	"applied":    "Plan applied to Flagsmith. Run Verify to re-attack and confirm the fix.",
	"verified":   "Verification finished. The before/after results are below.",
	"rolledback": "Plan rolled back. The previous state was restored.",
	"planned":    "Fix plans created from the report. Review each one below.",
}

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"rd":        func(s string) string { return redact.String(s) },
		"time":      fmtTime,
		"sevGlyph":  sevGlyph,
		"val":       fmtVal,
		"short":     shortHash,
		"lower":     strings.ToLower,
		"upper":     strings.ToUpper,
		"ms":        fmtMS,
		"pct":       func(f float64) string { return fmt.Sprintf("%.1f%%", f*100) },
		"isControl": func(t model.FindingType) bool { return t == model.FControlOK },
		"yesno": func(b *bool) string {
			switch {
			case b == nil:
				return "unknown"
			case *b:
				return "on"
			}
			return "off"
		},
	}
}

func loadTemplates() (map[string]*template.Template, error) {
	base, err := template.New("base").Funcs(templateFuncs()).ParseFS(assets, "templates/layout.html", "templates/partials.html")
	if err != nil {
		return nil, fmt.Errorf("parse base templates: %w", err)
	}
	pages := map[string]*template.Template{"partials": base}
	for _, name := range pageNames {
		c, err := base.Clone()
		if err != nil {
			return nil, err
		}
		if _, err := c.ParseFS(assets, "templates/"+name+".html"); err != nil {
			return nil, fmt.Errorf("parse %s template: %w", name, err)
		}
		pages[name] = c
	}
	if _, err := fs.Stat(assets, "static/app.css"); err != nil {
		return nil, fmt.Errorf("missing embedded stylesheet: %w", err)
	}
	return pages, nil
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}

func fmtMS(ms int64) string {
	if ms >= 1000 {
		return fmt.Sprintf("%.1f s", float64(ms)/1000)
	}
	return fmt.Sprintf("%d ms", ms)
}

func sevGlyph(s model.Severity) string {
	switch s {
	case model.SevCritical:
		return "◆"
	case model.SevHigh:
		return "▲"
	case model.SevMedium:
		return "●"
	case model.SevLow:
		return "■"
	}
	return "○"
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// fmtVal renders a JSON-ish value compactly for before/after tables.
func fmtVal(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case string:
		return t
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// render executes a full page into a buffer first so a template error
// yields a clean 500 rather than a half-written page.
func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, status int, p pageData) {
	p.CSRF = csrfToken(r)
	p.HTMXURL, p.HTMXSRI = HTMXURL, htmxSRI
	if p.Notice == "" {
		p.Notice = notices[r.URL.Query().Get("ok")]
	}
	p.Pending = s.pendingPlans()
	var buf bytes.Buffer
	if err := s.pages[page].ExecuteTemplate(&buf, "layout", p); err != nil {
		s.log.Error("render page", "page", page, "err", redact.String(err.Error()))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// renderPartial executes one named partial (an HTMX or SSE fragment).
func (s *Server) renderPartial(name string, data any) (string, error) {
	var buf bytes.Buffer
	if err := s.pages["partials"].ExecuteTemplate(&buf, name, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (s *Server) writePartial(w http.ResponseWriter, name string, data any) {
	out, err := s.renderPartial(name, data)
	if err != nil {
		s.log.Error("render partial", "partial", name, "err", redact.String(err.Error()))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(out))
}

func (s *Server) pendingPlans() int {
	n := 0
	for _, p := range s.be.Plans() {
		if p.State == model.PlanPending {
			n++
		}
	}
	return n
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request, what string) {
	s.render(w, r, "message", http.StatusNotFound, pageData{Title: "Not found", Error: what + " not found."})
}
