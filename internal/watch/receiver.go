package watch

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

const (
	// DefaultDebounce is the window in which repeated changes to the same
	// object collapse into one re-check.
	DefaultDebounce = 250 * time.Millisecond
	// MaxAlerts is how many alerts are kept in memory.
	MaxAlerts = 200

	defaultRecheckTimeout = 60 * time.Second
	subscriberBuffer      = 16
)

// Rechecker re-runs the map stage and targeted probes for one change and
// returns the findings that currently apply to it. The lead wires this.
type Rechecker func(ctx context.Context, c Change) ([]model.Finding, error)

// Alert is raised when a change introduces findings not seen before.
type Alert struct {
	ID       string          `json:"id"`
	At       time.Time       `json:"at"`
	Change   Change          `json:"change"`
	Findings []model.Finding `json:"findings"`
	// LatencyMS is the time from webhook receipt to this alert.
	LatencyMS int64 `json:"latency_ms"`
	// EventLatencyMS is the time from the event's own timestamp to this
	// alert; zero when the payload carried no timestamp.
	EventLatencyMS int64 `json:"event_latency_ms,omitempty"`
	// ReviewURL opens the approval card for the first finding.
	ReviewURL string `json:"review_url"`
	// Error is set when the re-check itself failed (no findings then).
	Error string `json:"error,omitempty"`
}

// Options configures a Receiver.
type Options struct {
	// Secret is the webhook HMAC secret. Required.
	Secret string
	// Recheck is called once per debounced change. Required.
	Recheck Rechecker
	// Debounce overrides DefaultDebounce.
	Debounce time.Duration
	// BaseURL prefixes ReviewURL (e.g. http://127.0.0.1:8787); may be empty.
	BaseURL string
	// Slack optionally receives a redacted copy of each alert.
	Slack *SlackNotifier
	// Logger defaults to slog.Default().
	Logger *slog.Logger
	// Now is the clock; defaults to time.Now.
	Now func() time.Time
}

// Receiver is the Flagsmith webhook endpoint. It is an http.Handler.
type Receiver struct {
	opts Options
	log  *slog.Logger
	ctx  context.Context
	stop context.CancelFunc

	procMu sync.Mutex // serialises re-checks

	mu      sync.Mutex
	pending map[string]*pendingChange
	known   map[string]struct{}
	alerts  []Alert // oldest first
	subs    map[int]chan Alert
	nextSub int
}

type pendingChange struct {
	change Change
	timer  *time.Timer
}

// NewReceiver validates opts and returns a ready Receiver.
func NewReceiver(opts Options) (*Receiver, error) {
	if opts.Secret == "" {
		return nil, errors.New("watch: webhook secret is required (unsigned webhooks are never accepted)")
	}
	if opts.Recheck == nil {
		return nil, errors.New("watch: a Rechecker is required")
	}
	if opts.Debounce <= 0 {
		opts.Debounce = DefaultDebounce
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	opts.BaseURL = strings.TrimRight(opts.BaseURL, "/")
	redact.Register(opts.Secret, "WEBHOOK_SECRET")
	ctx, stop := context.WithCancel(context.Background())
	return &Receiver{
		opts: opts, log: opts.Logger, ctx: ctx, stop: stop,
		pending: map[string]*pendingChange{},
		known:   map[string]struct{}{},
		subs:    map[int]chan Alert{},
	}, nil
}

// Close stops pending timers and cancels in-flight re-checks.
func (r *Receiver) Close() {
	r.stop()
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, p := range r.pending {
		p.timer.Stop()
		delete(r.pending, k)
	}
}

// Seed replaces the set of finding IDs treated as already known, normally
// with the findings of the baseline audit, so only new ones raise alerts.
func (r *Receiver) Seed(ids []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.known = make(map[string]struct{}, len(ids))
	for _, id := range ids {
		r.known[id] = struct{}{}
	}
}

// ServeHTTP verifies and accepts a webhook. It answers 202 as soon as the
// change is queued; the re-check runs after the debounce window.
func (r *Receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sig := req.Header.Get(SignatureHeader)
	if sig == "" {
		http.Error(w, "unsigned webhook rejected", http.StatusUnauthorized)
		return
	}
	received := r.opts.Now()
	body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, MaxBodyBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "unreadable body", http.StatusBadRequest)
		return
	}
	if !VerifySignature(r.opts.Secret, body, sig) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	change, err := parseChange(body, received)
	if err != nil {
		http.Error(w, "unrecognised webhook payload", http.StatusBadRequest)
		return
	}
	r.enqueue(change)
	w.WriteHeader(http.StatusAccepted)
}

// enqueue starts the debounce window for change, or merges it into the
// window already open for the same object. The window is fixed from the
// first event so a steady stream cannot delay a re-check indefinitely.
func (r *Receiver) enqueue(c Change) {
	key := c.key()
	r.mu.Lock()
	defer r.mu.Unlock()
	if p, ok := r.pending[key]; ok {
		p.change = mergeChange(p.change, c)
		return
	}
	r.pending[key] = &pendingChange{change: c, timer: time.AfterFunc(r.opts.Debounce, func() { r.fire(key) })}
}

// mergeChange keeps the earliest timestamps and fills gaps from the newer event.
func mergeChange(old, next Change) Change {
	if old.Feature == "" {
		old.Feature = next.Feature
	}
	if old.Segment == "" {
		old.Segment = next.Segment
	}
	if old.EventTime.IsZero() {
		old.EventTime = next.EventTime
	}
	return old
}

func (r *Receiver) fire(key string) {
	r.mu.Lock()
	p, ok := r.pending[key]
	delete(r.pending, key)
	r.mu.Unlock()
	if ok && r.ctx.Err() == nil {
		r.process(p.change)
	}
}

func (r *Receiver) process(c Change) {
	r.procMu.Lock()
	defer r.procMu.Unlock()
	ctx, cancel := context.WithTimeout(r.ctx, defaultRecheckTimeout)
	defer cancel()
	findings, err := r.opts.Recheck(ctx, c)
	if err != nil {
		msg := redact.String(err.Error())
		r.log.Warn("watch re-check failed", "object", c.Object(), "err", msg)
		r.publish(ctx, c, nil, msg)
		return
	}
	fresh := r.newFindings(findings)
	if len(fresh) == 0 {
		return
	}
	r.publish(ctx, c, fresh, "")
}

// newFindings returns findings not seen before and marks all as known.
func (r *Receiver) newFindings(findings []model.Finding) []model.Finding {
	r.mu.Lock()
	defer r.mu.Unlock()
	var fresh []model.Finding
	for _, f := range findings {
		if _, seen := r.known[f.ID]; seen {
			continue
		}
		r.known[f.ID] = struct{}{}
		if f.Type != model.FControlOK {
			fresh = append(fresh, f)
		}
	}
	return fresh
}

func (r *Receiver) publish(ctx context.Context, c Change, findings []model.Finding, errMsg string) {
	now := r.opts.Now()
	a := Alert{ID: newAlertID(), At: now, Change: c, Findings: findings, Error: errMsg,
		LatencyMS: nonNegativeMS(now.Sub(c.ReceivedAt))}
	if !c.EventTime.IsZero() {
		a.EventLatencyMS = nonNegativeMS(now.Sub(c.EventTime))
	}
	a.ReviewURL = r.opts.BaseURL + "/plans"
	if len(findings) > 0 {
		a.ReviewURL += "?finding=" + url.QueryEscape(findings[0].ID)
	}
	r.store(a)
	if r.opts.Slack != nil && len(findings) > 0 {
		if err := r.opts.Slack.Notify(ctx, a); err != nil {
			r.log.Warn("slack notification failed", "err", redact.String(err.Error()))
		}
	}
}

// store records the alert and fans it out to subscribers without blocking.
func (r *Receiver) store(a Alert) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.alerts = append(r.alerts, a)
	if len(r.alerts) > MaxAlerts {
		r.alerts = append([]Alert(nil), r.alerts[len(r.alerts)-MaxAlerts:]...)
	}
	for _, ch := range r.subs {
		select {
		case ch <- a:
		default: // slow subscriber: drop rather than stall the receiver
		}
	}
}

// Alerts returns the retained alerts, newest first.
func (r *Receiver) Alerts() []Alert {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Alert, len(r.alerts))
	for i, a := range r.alerts {
		out[len(r.alerts)-1-i] = a
	}
	return out
}

// Subscribe returns a channel of future alerts and a function that
// unsubscribes and closes it.
func (r *Receiver) Subscribe() (<-chan Alert, func()) {
	ch := make(chan Alert, subscriberBuffer)
	r.mu.Lock()
	id := r.nextSub
	r.nextSub++
	r.subs[id] = ch
	r.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			r.mu.Lock()
			delete(r.subs, id)
			r.mu.Unlock()
			close(ch)
		})
	}
}

func newAlertID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "AL-" + hex.EncodeToString([]byte(time.Now().Format("150405.000")))
	}
	return "AL-" + hex.EncodeToString(b)
}

func nonNegativeMS(d time.Duration) int64 {
	if d < 0 {
		return 0
	}
	return d.Milliseconds()
}
