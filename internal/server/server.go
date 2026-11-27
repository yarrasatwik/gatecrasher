package server

import (
	"context"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DefaultAddr is the default listen address: loopback only.
const DefaultAddr = "127.0.0.1:8787"

// WebhookPath is where Options.Webhook is mounted.
const WebhookPath = "/webhooks/flagsmith"

// HTMXURL is the exact, pinned HTMX build the pages load. The Content
// Security Policy allows this URL and nothing else outside 'self'.
const HTMXURL = "https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js"

// htmxSRI is the Subresource Integrity hash of HTMXURL.
const htmxSRI = "sha384-HGfztofotfshcF7+8n44JQL2oJmowVChPTg48S+jvZoztPfvwD79OC/LTtG6dMp+"

const csp = "default-src 'none'; script-src 'self' " + HTMXURL + "; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// Options configures a Server.
type Options struct {
	// Backend supplies all data and actions. Required.
	Backend Backend
	// Addr is the listen address for ListenAndServe; defaults to DefaultAddr.
	Addr string
	// AllowedHosts lists extra Host header values accepted besides
	// loopback names (defence against DNS rebinding). Needed only when the
	// UI is deliberately reachable under another name.
	AllowedHosts []string
	// Webhook, if set, is mounted at WebhookPath. It bypasses the Host and
	// CSRF checks because Flagsmith, not a browser, calls it; it must
	// authenticate callers itself (watch.Receiver verifies an HMAC).
	Webhook http.Handler
	// Files, if set, serves /files/ (report downloads such as
	// /files/{id}.html, .json and .sarif).
	Files http.Handler
	// Operator is recorded as the approver of web approvals. Defaults to "web".
	Operator string
	// Logger defaults to slog.Default().
	Logger *slog.Logger
}

// Server is the web UI.
type Server struct {
	be     Backend
	opts   Options
	log    *slog.Logger
	pages  map[string]*template.Template
	hosts  map[string]struct{}
	mux    *http.ServeMux
	base   context.Context
	cancel context.CancelFunc

	runMu sync.Mutex
	run   runState
}

// New builds a Server and parses its embedded templates.
func New(opts Options) (*Server, error) {
	if opts.Backend == nil {
		return nil, errors.New("server: a Backend is required")
	}
	if opts.Addr == "" {
		opts.Addr = DefaultAddr
	}
	if opts.Operator == "" {
		opts.Operator = "web"
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	pages, err := loadTemplates()
	if err != nil {
		return nil, err
	}
	base, cancel := context.WithCancel(context.Background())
	s := &Server{be: opts.Backend, opts: opts, log: opts.Logger, pages: pages, base: base, cancel: cancel,
		hosts: allowedHosts(opts)}
	s.mux = s.routes()
	return s, nil
}

// Close cancels any audit run still in flight.
func (s *Server) Close() { s.cancel() }

// Handler returns the full handler with security middleware applied.
func (s *Server) Handler() http.Handler {
	var h http.Handler = s.mux
	h = s.csrf(h)
	h = s.hostCheck(h)
	return securityHeaders(h)
}

// ListenAndServe serves on Options.Addr until ctx is cancelled, then shuts
// down gracefully. There is no write timeout because /watch/stream is long-lived.
func (s *Server) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{Addr: s.opts.Addr, Handler: s.Handler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		sctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		s.Close()
		return srv.Shutdown(sctx)
	}
}

func (s *Server) routes() *http.ServeMux {
	m := http.NewServeMux()
	staticFS, _ := fs.Sub(assets, "static")
	m.Handle("GET /static/", http.StripPrefix("/static/", cacheStatic(http.FileServerFS(staticFS))))
	m.HandleFunc("GET /{$}", s.dashboard)
	m.HandleFunc("POST /run", s.startRunHandler)
	m.HandleFunc("GET /run/status", s.runStatus)
	m.HandleFunc("GET /report/{id}", s.report)
	m.HandleFunc("GET /plans", s.plans)
	m.HandleFunc("POST /plans/make", s.makePlans)
	m.HandleFunc("POST /plans/{id}/{action}", s.planAction)
	m.HandleFunc("GET /watch", s.watchPage)
	m.HandleFunc("GET /watch/stream", s.watchStream)
	m.HandleFunc("GET /audit", s.auditPage)
	if s.opts.Files != nil {
		m.Handle("GET /files/", s.opts.Files)
	}
	if s.opts.Webhook != nil {
		m.Handle(WebhookPath, s.opts.Webhook)
	}
	return m
}

func cacheStatic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=300")
		next.ServeHTTP(w, r)
	})
}

// securityHeaders sets the strict CSP and friends on every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// allowedHosts builds the accepted Host header set: loopback names plus the
// configured extras and the host of Addr.
func allowedHosts(opts Options) map[string]struct{} {
	set := map[string]struct{}{"localhost": {}, "127.0.0.1": {}, "::1": {}}
	add := func(v string) {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			return
		}
		set[v] = struct{}{}
		if h, _, err := net.SplitHostPort(v); err == nil {
			set[h] = struct{}{}
		}
	}
	for _, h := range opts.AllowedHosts {
		add(h)
	}
	if h, _, err := net.SplitHostPort(opts.Addr); err == nil && h != "" && h != "0.0.0.0" && h != "::" {
		add(h)
	}
	return set
}

// hostCheck rejects requests whose Host is not allowed, which stops DNS
// rebinding attacks against the localhost UI.
func (s *Server) hostCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.opts.Webhook != nil && r.URL.Path == WebhookPath {
			next.ServeHTTP(w, r)
			return
		}
		host := strings.ToLower(r.Host)
		name := host
		if h, _, err := net.SplitHostPort(host); err == nil {
			name = h
		}
		name = strings.Trim(name, "[]")
		_, okName := s.hosts[name]
		_, okFull := s.hosts[host]
		if !okName && !okFull {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
