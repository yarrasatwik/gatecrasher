package httpx

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/scope"
)

func lockFor(t *testing.T, srv *httptest.Server) *scope.Lock {
	t.Helper()
	u, _ := url.Parse(srv.URL)
	return scope.MustNew(nil, []string{u.Host})
}

func TestScopeRefusedBeforeSending(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	c := New(scope.MustNew([]string{"example.com"}, nil))
	_, err := c.Do(context.Background(), Request{URL: srv.URL})
	if !errors.Is(err, scope.ErrOutOfScope) {
		t.Fatalf("want out of scope, got %v", err)
	}
	if hits.Load() != 0 || c.Sent() != 0 {
		t.Fatal("request must not be sent")
	}
}

func TestRedirectOutOfScopeRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.org/steal", http.StatusFound)
	}))
	defer srv.Close()
	_, err := New(lockFor(t, srv)).Do(context.Background(), Request{URL: srv.URL})
	if !errors.Is(err, scope.ErrOutOfScope) {
		t.Fatalf("redirect must be refused, got %v", err)
	}
}

func TestRetryOn5xxThenSuccess(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	var out struct{ OK bool }
	if _, err := New(lockFor(t, srv)).JSON(context.Background(), Request{URL: srv.URL}, &out); err != nil || !out.OK {
		t.Fatalf("err=%v out=%v", err, out)
	}
	if n.Load() != 3 {
		t.Fatalf("attempts=%d", n.Load())
	}
}

func TestNonIdempotentPostNotRetried(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	_, err := New(lockFor(t, srv)).JSON(context.Background(), Request{Method: "POST", URL: srv.URL, Body: map[string]int{"a": 1}}, nil)
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 500 || n.Load() != 1 {
		t.Fatalf("err=%v attempts=%d", err, n.Load())
	}
}

func TestBodyCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, 2048))
	}))
	defer srv.Close()
	if _, err := New(lockFor(t, srv)).Do(context.Background(), Request{URL: srv.URL, MaxBody: 1024}); err == nil {
		t.Fatal("expected size error")
	}
}

func TestRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c := New(lockFor(t, srv), WithRate(50))
	start := time.Now()
	for i := 0; i < 6; i++ {
		if _, err := c.Do(context.Background(), Request{URL: srv.URL}); err != nil {
			t.Fatal(err)
		}
	}
	if el := time.Since(start); el < 90*time.Millisecond {
		t.Fatalf("rate limit not applied: %v", el)
	}
	if c.Sent() != 6 {
		t.Fatalf("sent=%d", c.Sent())
	}
}
