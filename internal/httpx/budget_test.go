package httpx

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

func countingServer(t *testing.T, status int) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestBudgetStopsRequestsAtTheLimit(t *testing.T) {
	srv, hits := countingServer(t, 200)
	c := New(lockFor(t, srv))
	b := NewBudget(3)
	ctx := WithBudget(context.Background(), b)
	var refused int
	for i := 0; i < 6; i++ {
		_, err := c.Do(ctx, Request{URL: srv.URL})
		if errors.Is(err, ErrBudget) {
			refused++
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if hits.Load() != 3 || b.Used() != 3 || refused != 3 || b.Refused() != 3 {
		t.Fatalf("hits=%d used=%d refused=%d/%d, want 3/3/3/3", hits.Load(), b.Used(), refused, b.Refused())
	}
	if !b.Exhausted() || b.Max() != 3 {
		t.Fatalf("exhausted=%v max=%d", b.Exhausted(), b.Max())
	}
}

func TestBudgetCountsEveryRetryAttempt(t *testing.T) {
	srv, hits := countingServer(t, 503)
	c := New(lockFor(t, srv), WithRetries(5))
	b := NewBudget(2)
	_, err := c.Do(WithBudget(context.Background(), b), Request{URL: srv.URL})
	if !errors.Is(err, ErrBudget) {
		t.Fatalf("err = %v, want ErrBudget after the retries used the budget", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("server saw %d requests, want 2", hits.Load())
	}
}

func TestBudgetIsHonouredUnderConcurrency(t *testing.T) {
	srv, hits := countingServer(t, 200)
	c := New(lockFor(t, srv))
	b := NewBudget(10)
	ctx := WithBudget(context.Background(), b)
	var wg sync.WaitGroup
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.Do(ctx, Request{URL: srv.URL})
		}()
	}
	wg.Wait()
	if hits.Load() != 10 || b.Used() != 10 {
		t.Fatalf("hits=%d used=%d, want exactly 10", hits.Load(), b.Used())
	}
}

func TestZeroBudgetCountsButNeverStops(t *testing.T) {
	srv, hits := countingServer(t, 200)
	c := New(lockFor(t, srv))
	b := NewBudget(0)
	ctx := WithBudget(context.Background(), b)
	for i := 0; i < 5; i++ {
		if _, err := c.Do(ctx, Request{URL: srv.URL}); err != nil {
			t.Fatal(err)
		}
	}
	if hits.Load() != 5 || b.Used() != 5 || b.Exhausted() {
		t.Fatalf("hits=%d used=%d exhausted=%v", hits.Load(), b.Used(), b.Exhausted())
	}
}

func TestWithBudgetNilDetachesAnInheritedBudget(t *testing.T) {
	srv, hits := countingServer(t, 200)
	c := New(lockFor(t, srv))
	b := NewBudget(1)
	ctx := WithBudget(WithBudget(context.Background(), b), nil)
	for i := 0; i < 3; i++ {
		if _, err := c.Do(ctx, Request{URL: srv.URL}); err != nil {
			t.Fatal(err)
		}
	}
	if hits.Load() != 3 || b.Used() != 0 {
		t.Fatalf("hits=%d used=%d: a detached context must not touch the budget", hits.Load(), b.Used())
	}
}

func TestBudgetRefusalDoesNotSendOrCountAsSent(t *testing.T) {
	srv, hits := countingServer(t, 200)
	c := New(lockFor(t, srv))
	ctx := WithBudget(context.Background(), NewBudget(1))
	_, _ = c.Do(ctx, Request{URL: srv.URL})
	_, err := c.Do(ctx, Request{URL: srv.URL})
	if !errors.Is(err, ErrBudget) || hits.Load() != 1 || c.Sent() != 1 {
		t.Fatalf("err=%v hits=%d sent=%d", err, hits.Load(), c.Sent())
	}
}
