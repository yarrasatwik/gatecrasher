package httpx

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/scope"
)

// recorder is an in-scope server that remembers every header it was sent.
type recorder struct {
	*httptest.Server
	mu   sync.Mutex
	hits int
	seen []http.Header
}

func newRecorder() *recorder {
	r := &recorder{}
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.hits++
		r.seen = append(r.seen, req.Header.Clone())
		r.mu.Unlock()
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	return r
}

func (r *recorder) sawHeader(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, h := range r.seen {
		if h.Get(name) != "" {
			return true
		}
	}
	return false
}

func hostOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

// A redirects to B; both are in scope. A request carrying a key header must
// stop at A with a clear error and the key must never reach B.
func TestKeyHeadersDoNotFollowRedirects(t *testing.T) {
	for header, value := range map[string]string{
		"X-Environment-Key": "CQJFFFBP5Hk65U5vDHU3MS",
		"Authorization":     "Api-Key 8VpiXQiR.abcdefghijklmnopqrstuvwxyz012345",
		"x-environment-key": "CQJFFFBP5Hk65U5vDHU3MS", // header names are case-insensitive
	} {
		t.Run(header, func(t *testing.T) {
			b := newRecorder()
			defer b.Close()
			var aHits atomic.Int32
			a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				aHits.Add(1)
				http.Redirect(w, r, b.URL+"/api/v1/flags/?token=ser.AbCdEfGhIjKlMnOpQrStUv", http.StatusFound)
			}))
			defer a.Close()
			c := New(scope.MustNew(nil, []string{hostOf(t, a.URL), hostOf(t, b.URL)}))

			_, err := c.Do(context.Background(), Request{URL: a.URL + "/api/v1/flags/", Header: map[string]string{header: value}})
			if !errors.Is(err, ErrRedirectWithKey) {
				t.Fatalf("want ErrRedirectWithKey, got %v", err)
			}
			msg := err.Error()
			if !strings.Contains(msg, hostOf(t, b.URL)+"/api/v1/flags/") {
				t.Fatalf("error must name the redirect target, got %q", msg)
			}
			if !strings.Contains(strings.ToLower(msg), strings.ToLower(http.CanonicalHeaderKey(header))) {
				t.Fatalf("error must name the header, got %q", msg)
			}
			for _, leak := range []string{value, "ser.AbCdEfGhIjKlMnOpQrStUv", "8VpiXQiR"} {
				if strings.Contains(msg, leak) {
					t.Fatalf("error leaks key material: %q", msg)
				}
			}
			if b.hits != 0 {
				t.Fatalf("redirect target was contacted %d times", b.hits)
			}
			if b.sawHeader("X-Environment-Key") || b.sawHeader("Authorization") {
				t.Fatal("key header reached the redirect target")
			}
			if aHits.Load() != 1 {
				t.Fatalf("a refused redirect must not be retried, got %d attempts", aHits.Load())
			}
		})
	}
}

// Requests without key headers still follow in-scope redirects.
func TestRedirectFollowedWithoutKeyHeaders(t *testing.T) {
	b := newRecorder()
	defer b.Close()
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, b.URL+"/app.js", http.StatusFound)
	}))
	defer a.Close()
	c := New(scope.MustNew(nil, []string{hostOf(t, a.URL), hostOf(t, b.URL)}))
	resp, err := c.Do(context.Background(), Request{URL: a.URL, Header: map[string]string{"X-Trace": "1"}})
	if err != nil || !resp.OK() || b.hits != 1 {
		t.Fatalf("err=%v hits=%d", err, b.hits)
	}
}

// Second safeguard, tested on its own: whatever is on a redirected request,
// both key headers are removed as soon as the host or the port changes.
func TestStripKeyHeadersWhenOriginChanges(t *testing.T) {
	cases := []struct {
		from, to string
		stripped bool
	}{
		{"http://localhost:8000/a", "http://localhost:3030/a", true},          // port changes
		{"http://localhost:8000/a", "http://127.0.0.1:8000/a", true},          // host changes
		{"https://api.example.com/a", "https://api.example.com:8443/a", true}, // default port -> explicit other port
		{"http://api.example.com/a", "https://api.example.com/a", true},       // 80 -> 443
		{"https://api.example.com/a", "https://sub.api.example.com/a", true},
		{"https://api.example.com/a", "https://api.example.com:443/b", false}, // same origin spelled differently
		{"http://LOCALHOST:8000/a", "http://localhost:8000/b", false},
	}
	for _, tc := range cases {
		prev, _ := http.NewRequest(http.MethodGet, tc.from, nil)
		next, _ := http.NewRequest(http.MethodGet, tc.to, nil)
		next.Header.Set("X-Environment-Key", "CQJFFFBP5Hk65U5vDHU3MS")
		next.Header.Set("Authorization", "Api-Key secret")
		next.Header.Set("Accept", "application/json")
		stripKeyHeadersOnOriginChange(next, prev)
		gone := next.Header.Get("X-Environment-Key") == "" && next.Header.Get("Authorization") == ""
		kept := next.Header.Get("X-Environment-Key") != "" && next.Header.Get("Authorization") != ""
		if tc.stripped && !gone {
			t.Errorf("%s -> %s: key headers must be stripped, have %v", tc.from, tc.to, next.Header)
		}
		if !tc.stripped && !kept {
			t.Errorf("%s -> %s: same origin must keep headers, have %v", tc.from, tc.to, next.Header)
		}
		if next.Header.Get("Accept") == "" {
			t.Errorf("%s -> %s: unrelated headers must stay", tc.from, tc.to)
		}
	}
}

// Both safeguards together inside CheckRedirect: even though the request is
// refused, the hop that was about to be sent no longer carries the keys.
func TestCheckRedirectStripsBeforeRefusing(t *testing.T) {
	c := New(scope.MustNew(nil, []string{"localhost:8000", "localhost:3030"}))
	first, _ := http.NewRequest(http.MethodGet, "http://localhost:8000/api/v1/flags", nil)
	first.Header.Set("X-Environment-Key", "CQJFFFBP5Hk65U5vDHU3MS")
	next, _ := http.NewRequest(http.MethodGet, "http://localhost:3030/steal", nil)
	next.Header = first.Header.Clone() // net/http copies headers onto the next hop
	err := c.hc.CheckRedirect(next, []*http.Request{first})
	if !errors.Is(err, ErrRedirectWithKey) {
		t.Fatalf("want ErrRedirectWithKey, got %v", err)
	}
	if next.Header.Get("X-Environment-Key") != "" {
		t.Fatal("key header still on the cross-port hop")
	}
}
