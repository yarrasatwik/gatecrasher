package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
)

const (
	csrfCookie  = "gc_csrf"
	csrfField   = "csrf_token"
	csrfHeader  = "X-CSRF-Token"
	maxFormBody = 1 << 20
)

type ctxKey int

const csrfKey ctxKey = 1

func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("server: no entropy for CSRF token: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func validToken(t string) bool {
	if len(t) != 64 {
		return false
	}
	_, err := hex.DecodeString(t)
	return err == nil
}

func csrfToken(r *http.Request) string {
	t, _ := r.Context().Value(csrfKey).(string)
	return t
}

// csrf implements a double-submit cookie: the HttpOnly SameSite=Strict
// cookie holds a random token, and every state-changing request must echo
// it in the csrf_token form field or X-CSRF-Token header. Cross-origin
// requests are additionally refused by Origin / Sec-Fetch-Site.
func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.opts.Webhook != nil && r.URL.Path == WebhookPath {
			next.ServeHTTP(w, r)
			return
		}
		tok := ""
		if c, err := r.Cookie(csrfCookie); err == nil && validToken(c.Value) {
			tok = c.Value
		}
		hadCookie := tok != ""
		if !hadCookie {
			tok = newToken()
			http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: tok, Path: "/", HttpOnly: true,
				SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil})
		}
		if isUnsafe(r.Method) {
			if !sameOrigin(r) {
				http.Error(w, "cross-origin request refused", http.StatusForbidden)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
			sent := r.Header.Get(csrfHeader)
			if sent == "" {
				sent = r.PostFormValue(csrfField)
			}
			if !hadCookie || subtle.ConstantTimeCompare([]byte(sent), []byte(tok)) != 1 {
				http.Error(w, "invalid or missing CSRF token; reload the page and try again", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), csrfKey, tok)))
	})
}

func isUnsafe(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// sameOrigin reports whether a state-changing request came from this host.
func sameOrigin(r *http.Request) bool {
	// A matching Origin is authoritative. Some embedded browsers report a
	// conservative Sec-Fetch-Site for same-origin form posts, so that header
	// only decides when Origin is absent. The CSRF token is checked as well.
	if origin := r.Header.Get("Origin"); origin != "" && origin != "null" {
		u, err := url.Parse(origin)
		return err == nil && strings.EqualFold(u.Host, r.Host)
	}
	site := r.Header.Get("Sec-Fetch-Site")
	return site == "" || site == "same-origin" || site == "none"
}
