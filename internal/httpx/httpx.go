// Package httpx is the only way Gatecrasher talks to the network. Every
// request (and every redirect hop) is checked against the scope lock, bodies
// are size-capped, idempotent requests are retried with backoff, and a
// token-bucket rate limit keeps probing polite.
package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/redact"
	"github.com/yarrasatwik/gatecrasher/internal/scope"
)

// MaxBody is the default response body cap (5 MB, spec §8.1).
const MaxBody = 5 << 20

// Client is a scope-locked HTTP client.
type Client struct {
	lock    *scope.Lock
	hc      *http.Client
	retries int
	sent    atomic.Int64
	limiter *limiter
	ua      string
}

// Option configures a Client.
type Option func(*Client)

// WithRate limits requests to perSec (0 = unlimited).
func WithRate(perSec float64) Option {
	return func(c *Client) {
		if perSec > 0 {
			c.limiter = newLimiter(perSec)
		}
	}
}

// WithTimeout sets the per-request timeout.
func WithTimeout(d time.Duration) Option { return func(c *Client) { c.hc.Timeout = d } }

// WithRetries sets how many times idempotent requests are retried.
func WithRetries(n int) Option { return func(c *Client) { c.retries = n } }

// New builds a scope-locked client. A nil lock refuses everything.
func New(lock *scope.Lock, opts ...Option) *Client {
	c := &Client{lock: lock, retries: 2, ua: "gatecrasher/1 (+https://github.com/yarrasatwik/gatecrasher)"}
	c.hc = &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return lock.Check(req.URL)
		},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Lock returns the client's scope lock.
func (c *Client) Lock() *scope.Lock { return c.lock }

// Sent returns the number of requests sent so far.
func (c *Client) Sent() int64 { return c.sent.Load() }

// Response is a fully-read, size-capped response.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
	URL    string
}

// JSON decodes the body into v.
func (r *Response) JSON(v any) error {
	if err := json.Unmarshal(r.Body, v); err != nil {
		return fmt.Errorf("decode %s: %w (body: %s)", redact.String(r.URL), err, redact.String(truncate(string(r.Body), 200)))
	}
	return nil
}

// OK reports a 2xx status.
func (r *Response) OK() bool { return r.Status >= 200 && r.Status < 300 }

// StatusError is returned by Expect helpers for non-2xx responses.
type StatusError struct {
	Method, URL string
	Status      int
	Body        string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("%s %s: HTTP %d: %s", e.Method, redact.String(e.URL), e.Status, redact.String(truncate(e.Body, 300)))
}

// Request describes one call.
type Request struct {
	Method  string
	URL     string
	Header  map[string]string
	Body    any // marshalled as JSON when non-nil ([]byte sent raw)
	MaxBody int64
	// Idempotent marks a non-GET request as safe to retry.
	Idempotent bool
}

// Do performs the request after checking scope, with retries on 429/5xx and
// transport errors for idempotent requests.
func (c *Client) Do(ctx context.Context, r Request) (*Response, error) {
	if r.Method == "" {
		r.Method = http.MethodGet
	}
	if err := c.lock.CheckURL(r.URL); err != nil {
		return nil, err
	}
	var payload []byte
	switch b := r.Body.(type) {
	case nil:
	case []byte:
		payload = b
	default:
		var err error
		if payload, err = json.Marshal(b); err != nil {
			return nil, fmt.Errorf("encode body: %w", err)
		}
	}
	max := r.MaxBody
	if max <= 0 {
		max = MaxBody
	}
	attempts := 1
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Idempotent {
		attempts += c.retries
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			backoff := time.Duration(200*(1<<(i-1))) * time.Millisecond
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}
		if c.limiter != nil {
			if err := c.limiter.wait(ctx); err != nil {
				return nil, err
			}
		}
		req, err := http.NewRequestWithContext(ctx, r.Method, r.URL, bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", c.ua)
		req.Header.Set("Accept", "application/json, text/html;q=0.9, */*;q=0.8")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range r.Header {
			req.Header.Set(k, v)
		}
		c.sent.Add(1)
		resp, err := c.hc.Do(req)
		if err != nil {
			if errors.Is(err, scope.ErrOutOfScope) {
				return nil, err
			}
			lastErr = fmt.Errorf("%s %s: %s", r.Method, redact.String(r.URL), redact.String(err.Error()))
			continue
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, max+1))
		resp.Body.Close()
		if rerr != nil {
			lastErr = rerr
			continue
		}
		if int64(len(body)) > max {
			return nil, fmt.Errorf("%s %s: response exceeds %d bytes", r.Method, redact.String(r.URL), max)
		}
		out := &Response{Status: resp.StatusCode, Header: resp.Header, Body: body, URL: resp.Request.URL.String()}
		if (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500) && i < attempts-1 {
			lastErr = &StatusError{r.Method, r.URL, resp.StatusCode, string(body)}
			continue
		}
		return out, nil
	}
	return nil, lastErr
}

// JSON performs the request, requires 2xx, and decodes into out (if non-nil).
func (c *Client) JSON(ctx context.Context, r Request, out any) (*Response, error) {
	resp, err := c.Do(ctx, r)
	if err != nil {
		return nil, err
	}
	if !resp.OK() {
		return resp, &StatusError{r.Method, r.URL, resp.Status, string(resp.Body)}
	}
	if out != nil && len(resp.Body) > 0 {
		if err := resp.JSON(out); err != nil {
			return resp, err
		}
	}
	return resp, nil
}

// JoinURL joins a base URL (with or without trailing slash) and a path.
func JoinURL(base, path string) string {
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(path, "/")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

type limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newLimiter(perSec float64) *limiter {
	return &limiter{interval: time.Duration(float64(time.Second) / perSec)}
}

func (l *limiter) wait(ctx context.Context) error {
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	at := l.next
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()
	if d := time.Until(at); d > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
		}
	}
	return nil
}
