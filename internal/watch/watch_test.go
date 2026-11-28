package watch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
	"github.com/yarrasatwik/gatecrasher/internal/httpx"
	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/scope"
)

const testSecret = "unit-test-webhook-secret"

func lockFor(t *testing.T, srv *httptest.Server) *scope.Lock {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return scope.MustNew(nil, []string{u.Host})
}

func TestSignAndVerify(t *testing.T) {
	body := []byte(`{"event_type":"FLAG_UPDATED","data":{}}`)
	good := Sign(testSecret, body)
	tests := []struct {
		name   string
		secret string
		body   []byte
		header string
		want   bool
	}{
		{"valid", testSecret, body, good, true},
		{"valid with spaces", testSecret, body, " " + good + " ", true},
		{"wrong secret", "other", body, good, false},
		{"tampered body", testSecret, []byte(`{}`), good, false},
		{"empty header", testSecret, body, "", false},
		{"not hex", testSecret, body, "zz", false},
		{"empty secret", "", body, good, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := VerifySignature(tc.secret, tc.body, tc.header); got != tc.want {
				t.Fatalf("VerifySignature = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSignMatchesFlagsmithKnownVector(t *testing.T) {
	// HMAC-SHA256("key", "The quick brown fox jumps over the lazy dog")
	got := Sign("key", []byte("The quick brown fox jumps over the lazy dog"))
	want := "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
	if got != want {
		t.Fatalf("Sign = %s, want %s", got, want)
	}
}

func TestRegisterAndRemove(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	var posted map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "Api-Key ABCDEFGH.0123456789abcdef0123456789abcdef" {
			t.Errorf("bad auth header %q", r.Header.Get("Authorization"))
		}
		if r.Method == http.MethodPost {
			_ = json.NewDecoder(r.Body).Decode(&posted)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":42}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	admin := flagsmith.NewAdmin(httpx.New(lockFor(t, srv)), srv.URL+"/api/v1/", "ABCDEFGH.0123456789abcdef0123456789abcdef")
	reg, err := Register(context.Background(), admin, 7, "http://host.docker.internal:8787/webhooks/flagsmith", "")
	if err != nil {
		t.Fatal(err)
	}
	if reg.HookID != 42 || len(reg.Secret) != 64 {
		t.Fatalf("unexpected registration %+v", reg)
	}
	if posted["secret"] != reg.Secret || posted["enabled"] != true || posted["url"] != reg.URL {
		t.Fatalf("unexpected body %v", posted)
	}
	if err := reg.Remove(context.Background(), admin); err != nil {
		t.Fatal(err)
	}
	want := []string{"POST /api/v1/organisations/7/webhooks/", "DELETE /api/v1/organisations/7/webhooks/42/"}
	if strings.Join(calls, ",") != strings.Join(want, ",") {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
}

func TestRegisterKeepsConfiguredSecretAndReportsErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()
	admin := flagsmith.NewAdmin(httpx.New(lockFor(t, srv)), srv.URL+"/api/v1/", "ABCDEFGH.0123456789abcdef0123456789abcdef")
	if _, err := Register(context.Background(), admin, 1, "http://x/", testSecret); err == nil {
		t.Fatal("expected error from forbidden API")
	}
	if _, err := Register(context.Background(), admin, 1, " ", ""); err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestParseChange(t *testing.T) {
	recv := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		body string
		want Change
	}{
		{"flag updated", `{"event_type":"FLAG_UPDATED","data":{"timestamp":"2026-01-01T00:00:00.5Z","new_state":{"feature":{"id":1,"name":"beta_ui"},"environment":{"id":2,"name":"Production"}}}}`,
			Change{Kind: "FLAG_UPDATED", Environment: "Production", Feature: "beta_ui", EventTime: time.Date(2026, 1, 1, 0, 0, 0, 500000000, time.UTC)}},
		{"flag deleted uses previous state", `{"event_type":"FLAG_DELETED","data":{"previous_state":{"feature":{"name":"old"},"environment":{"name":"Dev"}}}}`,
			Change{Kind: "FLAG_DELETED", Environment: "Dev", Feature: "old"}},
		{"segment updated", `{"event_type":"SEGMENT_UPDATED","data":{"segment":{"name":"vip"},"environment":"Production"}}`,
			Change{Kind: "SEGMENT_UPDATED", Environment: "Production", Segment: "vip"}},
		{"audit feature", `{"event_type":"AUDIT_LOG_CREATED","data":{"created_date":"2020-02-23T17:30:57.006318Z","log":"New Flag / Remote Config created: my_feature","environment":null,"related_object_type":"FEATURE"}}`,
			Change{Kind: "AUDIT_LOG_CREATED", Feature: "my_feature", EventTime: time.Date(2020, 2, 23, 17, 30, 57, 6318000, time.UTC)}},
		{"audit segment quoted", `{"event_type":"AUDIT_LOG_CREATED","data":{"log":"Segment 'beta users' updated","related_object_type":"SEGMENT"}}`,
			Change{Kind: "AUDIT_LOG_CREATED", Segment: "beta users"}},
		{"unknown shape", `{"event_type":"NEW_VERSION_PUBLISHED","data":{"weird":[1,2]}}`,
			Change{Kind: "NEW_VERSION_PUBLISHED"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseChange([]byte(tc.body), recv)
			if err != nil {
				t.Fatal(err)
			}
			tc.want.ReceivedAt = recv
			if !got.EventTime.Equal(tc.want.EventTime) {
				t.Errorf("EventTime = %v, want %v", got.EventTime, tc.want.EventTime)
			}
			got.EventTime, tc.want.EventTime = time.Time{}, time.Time{}
			if got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
	for _, bad := range []string{`not json`, `{"data":{}}`} {
		if _, err := parseChange([]byte(bad), recv); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

type recorder struct {
	mu      sync.Mutex
	changes []Change
	calls   atomic.Int32
	result  []model.Finding
	err     error
	done    chan struct{}
}

func newRecorder(result []model.Finding) *recorder {
	return &recorder{result: result, done: make(chan struct{}, 16)}
}

func (r *recorder) recheck(_ context.Context, c Change) ([]model.Finding, error) {
	r.mu.Lock()
	r.changes = append(r.changes, c)
	res, err := r.result, r.err
	r.mu.Unlock()
	r.calls.Add(1)
	r.done <- struct{}{}
	return res, err
}

func finding(id string) model.Finding {
	return model.Finding{ID: id, Type: model.FSegmentForgeable, Severity: model.SevHigh, Title: "Segment " + id}
}

func newTestReceiver(t *testing.T, rec *recorder, mod func(*Options)) *Receiver {
	t.Helper()
	opts := Options{Secret: testSecret, Recheck: rec.recheck, Debounce: 40 * time.Millisecond, BaseURL: "http://127.0.0.1:8787/"}
	if mod != nil {
		mod(&opts)
	}
	r, err := NewReceiver(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

func post(t *testing.T, h http.Handler, body string, sig *string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/webhooks/flagsmith", strings.NewReader(body))
	if sig != nil {
		req.Header.Set(SignatureHeader, *sig)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func signed(body string) *string {
	s := Sign(testSecret, []byte(body))
	return &s
}

func wait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for re-check")
	}
}

const flagBody = `{"event_type":"FLAG_UPDATED","data":{"new_state":{"feature":{"name":"beta"},"environment":{"name":"Production"}}}}`

func TestNewReceiverValidation(t *testing.T) {
	if _, err := NewReceiver(Options{Recheck: newRecorder(nil).recheck}); err == nil {
		t.Error("empty secret must be rejected")
	}
	if _, err := NewReceiver(Options{Secret: testSecret}); err == nil {
		t.Error("nil rechecker must be rejected")
	}
}

func TestReceiverSignatureHandling(t *testing.T) {
	bad := "deadbeef"
	empty := ""
	tests := []struct {
		name   string
		method string
		sig    *string
		body   string
		status int
		recall bool
	}{
		{"valid", http.MethodPost, signed(flagBody), flagBody, http.StatusAccepted, true},
		{"missing header", http.MethodPost, nil, flagBody, http.StatusUnauthorized, false},
		{"empty header", http.MethodPost, &empty, flagBody, http.StatusUnauthorized, false},
		{"invalid signature", http.MethodPost, &bad, flagBody, http.StatusUnauthorized, false},
		{"signature for other body", http.MethodPost, signed(`{}`), flagBody, http.StatusUnauthorized, false},
		{"bad payload but signed", http.MethodPost, signed(`nope`), `nope`, http.StatusBadRequest, false},
		{"get not allowed", http.MethodGet, signed(flagBody), flagBody, http.StatusMethodNotAllowed, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := newRecorder(nil)
			r := newTestReceiver(t, rec, nil)
			req := httptest.NewRequest(tc.method, "/", strings.NewReader(tc.body))
			if tc.sig != nil {
				req.Header.Set(SignatureHeader, *tc.sig)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d", w.Code, tc.status)
			}
			time.Sleep(120 * time.Millisecond)
			if (rec.calls.Load() > 0) != tc.recall {
				t.Fatalf("recheck called = %v, want %v", rec.calls.Load() > 0, tc.recall)
			}
		})
	}
}

func TestReceiverBodyCap(t *testing.T) {
	r := newTestReceiver(t, newRecorder(nil), nil)
	big := `{"event_type":"FLAG_UPDATED","pad":"` + strings.Repeat("a", MaxBodyBytes) + `"}`
	if w := post(t, r, big, signed(big)); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", w.Code)
	}
}

func TestReceiverDebouncesBursts(t *testing.T) {
	rec := newRecorder(nil)
	r := newTestReceiver(t, rec, func(o *Options) { o.Debounce = 150 * time.Millisecond })
	for i := 0; i < 5; i++ {
		if w := post(t, r, flagBody, signed(flagBody)); w.Code != http.StatusAccepted {
			t.Fatalf("status %d", w.Code)
		}
	}
	wait(t, rec.done)
	time.Sleep(350 * time.Millisecond)
	if n := rec.calls.Load(); n != 1 {
		t.Fatalf("recheck called %d times for one burst, want 1", n)
	}
	other := `{"event_type":"FLAG_UPDATED","data":{"new_state":{"feature":{"name":"gamma"},"environment":{"name":"Production"}}}}`
	post(t, r, other, signed(other))
	wait(t, rec.done)
	if n := rec.calls.Load(); n != 2 {
		t.Fatalf("distinct object should re-check separately, calls = %d", n)
	}
}

func TestReceiverAlertsOnlyForNewFindings(t *testing.T) {
	rec := newRecorder([]model.Finding{finding("GC-1"), {ID: "GC-OK", Type: model.FControlOK}})
	r := newTestReceiver(t, rec, nil)
	ch, cancel := r.Subscribe()
	defer cancel()
	r.Seed([]string{"GC-0"})

	post(t, r, flagBody, signed(flagBody))
	wait(t, rec.done)
	var a Alert
	select {
	case a = <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("no alert emitted")
	}
	if len(a.Findings) != 1 || a.Findings[0].ID != "GC-1" {
		t.Fatalf("findings = %+v", a.Findings)
	}
	if a.ReviewURL != "http://127.0.0.1:8787/plans?finding=GC-1" {
		t.Errorf("ReviewURL = %q", a.ReviewURL)
	}
	if a.Change.Feature != "beta" || a.Change.Environment != "Production" || !strings.HasPrefix(a.ID, "AL-") {
		t.Errorf("unexpected alert %+v", a)
	}
	if a.LatencyMS < 30 {
		t.Errorf("LatencyMS = %d, expected to include the debounce window", a.LatencyMS)
	}

	// A later event for the same object re-checks, but the finding is known.
	again := flagEvent("beta", time.Now())
	post(t, r, again, signed(again))
	wait(t, rec.done)
	select {
	case dup := <-ch:
		t.Fatalf("repeat finding raised a second alert: %+v", dup)
	case <-time.After(250 * time.Millisecond):
	}
	if got := r.Alerts(); len(got) != 1 {
		t.Fatalf("Alerts() = %d, want 1", len(got))
	}
}

func TestReceiverEventLatencyAndClock(t *testing.T) {
	base := time.Date(2026, 5, 1, 12, 0, 10, 0, time.UTC)
	var tick atomic.Int64
	now := func() time.Time { return base.Add(time.Duration(tick.Add(1000)) * time.Millisecond) }
	rec := newRecorder([]model.Finding{finding("GC-9")})
	r := newTestReceiver(t, rec, func(o *Options) { o.Now = now })
	body := `{"event_type":"FLAG_UPDATED","data":{"timestamp":"2026-05-01T12:00:00Z","new_state":{"feature":{"name":"f"},"environment":{"name":"E"}}}}`
	post(t, r, body, signed(body))
	wait(t, rec.done)
	deadline := time.Now().Add(3 * time.Second)
	for len(r.Alerts()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	a := r.Alerts()[0]
	if a.LatencyMS != 1000 {
		t.Errorf("LatencyMS = %d, want 1000 (receipt -> alert)", a.LatencyMS)
	}
	if a.EventLatencyMS != 12000 {
		t.Errorf("EventLatencyMS = %d, want 12000 (event timestamp -> alert)", a.EventLatencyMS)
	}
}

func TestReceiverRecheckErrorBecomesAlert(t *testing.T) {
	rec := newRecorder(nil)
	rec.err = errors.New("admin API said Api-Key ABCDEFGH.0123456789abcdef0123456789abcdef is bad")
	r := newTestReceiver(t, rec, nil)
	ch, cancel := r.Subscribe()
	defer cancel()
	post(t, r, flagBody, signed(flagBody))
	select {
	case a := <-ch:
		if a.Error == "" || strings.Contains(a.Error, "0123456789abcdef0123456789abcdef") || len(a.Findings) != 0 {
			t.Fatalf("expected redacted error alert, got %+v", a)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no alert")
	}
}

func TestAlertHistoryCapAndUnsubscribe(t *testing.T) {
	r := newTestReceiver(t, newRecorder(nil), nil)
	ch, cancel := r.Subscribe()
	for i := 0; i < MaxAlerts+25; i++ {
		r.store(Alert{ID: "AL-" + string(rune('a'+i%26)), LatencyMS: int64(i)})
	}
	got := r.Alerts()
	if len(got) != MaxAlerts {
		t.Fatalf("kept %d alerts, want %d", len(got), MaxAlerts)
	}
	if got[0].LatencyMS != MaxAlerts+24 {
		t.Errorf("newest first expected, got %d", got[0].LatencyMS)
	}
	cancel()
	cancel()       // idempotent
	for range ch { // drained and closed
	}
	r.store(Alert{ID: "after"}) // must not panic on closed subscriber
}

func TestSlackNotifierPostsRedactedMessage(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
	}))
	defer srv.Close()
	n := newSlack(httpx.New(lockFor(t, srv)), srv.URL+"/services/T000/B000/xyz")
	f := finding("GC-1")
	f.Title = "Leaked ser.abcdefghijklmnop in value"
	a := Alert{Findings: []model.Finding{f}, Change: Change{Kind: "FLAG_UPDATED", Feature: "beta", Environment: "Production"},
		LatencyMS: 812, ReviewURL: "http://127.0.0.1:8787/plans?finding=GC-1"}
	if err := n.Notify(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	text := got["text"]
	if strings.Contains(text, "ser.abcdefghijklmnop") || !strings.Contains(text, "812 ms") || !strings.Contains(text, "beta") {
		t.Fatalf("unexpected slack text %q", text)
	}
}

func TestNewSlackOnlyAllowsSlackHost(t *testing.T) {
	for _, u := range []string{"https://evil.example.com/x", "http://hooks.slack.com/services/a", "https://hooks.slack.com.evil.io/x", "::bad"} {
		if _, err := NewSlack(u); err == nil {
			t.Errorf("NewSlack(%q) should fail", u)
		}
	}
	if _, err := NewSlack("https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXX"); err != nil {
		t.Errorf("valid slack URL rejected: %v", err)
	}
}

func TestSlackTextTruncatesLongLists(t *testing.T) {
	var fs []model.Finding
	for i := 0; i < 8; i++ {
		fs = append(fs, finding("GC-"+string(rune('A'+i))))
	}
	text := SlackText(Alert{Findings: fs, Change: Change{Kind: "SEGMENT_UPDATED", Segment: "vip"}})
	if !strings.Contains(text, "and 3 more") || !strings.Contains(text, "vip") {
		t.Fatalf("unexpected text %q", text)
	}
	if bytes.Count([]byte(text), []byte("\n- [")) != 5 {
		t.Fatalf("expected 5 listed findings, got %q", text)
	}
}
