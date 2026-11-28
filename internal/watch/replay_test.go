package watch

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// flagEvent is a FLAG_UPDATED payload for feature with the given event time.
func flagEvent(feature string, at time.Time) string {
	return fmt.Sprintf(`{"event_type":"FLAG_UPDATED","data":{"timestamp":%q,"new_state":{"feature":{"name":%q},"environment":{"name":"Production"}}}}`,
		at.UTC().Format(time.RFC3339Nano), feature)
}

// stepClock is a clock tests move by hand.
type stepClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *stepClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// settle waits long enough for any queued re-check to have run.
func settle() { time.Sleep(200 * time.Millisecond) }

func TestSameSignedBodyDeliveredTwiceTriggersOneRecheck(t *testing.T) {
	clock := &stepClock{now: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)}
	rec := newRecorder(nil)
	r := newTestReceiver(t, rec, func(o *Options) { o.Now = clock.Now })
	body := flagEvent("beta", clock.Now().Add(-2*time.Second))
	sig := signed(body)

	if w := post(t, r, body, sig); w.Code != http.StatusAccepted {
		t.Fatalf("first delivery: status %d", w.Code)
	}
	wait(t, rec.done)

	// The same delivery again, after the debounce window has closed: it is
	// acknowledged, so the sender does not retry, but nothing is re-checked.
	clock.Advance(time.Minute)
	w := post(t, r, body, sig)
	if w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), "duplicate") {
		t.Fatalf("duplicate delivery: status %d body %q", w.Code, w.Body.String())
	}
	settle()
	if n := rec.calls.Load(); n != 1 {
		t.Fatalf("re-check ran %d times for one delivery sent twice, want 1", n)
	}

	// A new event for the same object is a different delivery.
	next := flagEvent("beta", clock.Now())
	if w := post(t, r, next, signed(next)); w.Code != http.StatusAccepted {
		t.Fatalf("new event: status %d", w.Code)
	}
	wait(t, rec.done)
	if n := rec.calls.Load(); n != 2 {
		t.Fatalf("re-check calls = %d, want 2", n)
	}
}

func TestDuplicateWithoutTimestampIsRememberedForTenMinutes(t *testing.T) {
	clock := &stepClock{now: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)}
	rec := newRecorder(nil)
	r := newTestReceiver(t, rec, func(o *Options) { o.Now = clock.Now })
	post(t, r, flagBody, signed(flagBody))
	wait(t, rec.done)

	clock.Advance(DedupWindow - time.Second)
	post(t, r, flagBody, signed(flagBody))
	settle()
	if n := rec.calls.Load(); n != 1 {
		t.Fatalf("duplicate inside the window re-checked: calls = %d", n)
	}

	clock.Advance(2 * time.Second)
	if w := post(t, r, flagBody, signed(flagBody)); w.Code != http.StatusAccepted {
		t.Fatalf("status %d", w.Code)
	}
	wait(t, rec.done)
	if n := rec.calls.Load(); n != 2 {
		t.Fatalf("after the window the delivery is new again: calls = %d, want 2", n)
	}
	r.mu.Lock()
	kept := len(r.seen)
	r.mu.Unlock()
	if kept != 1 {
		t.Fatalf("expired deliveries must be forgotten, still tracking %d", kept)
	}
}

func TestStaleAndFutureEventsRefused(t *testing.T) {
	clock := &stepClock{now: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)}
	rec := newRecorder(nil)
	r := newTestReceiver(t, rec, func(o *Options) { o.Now = clock.Now })
	now := clock.Now()
	tests := []struct {
		name string
		at   time.Time
		code int
		want string
	}{
		{"11 minutes old", now.Add(-11 * time.Minute), http.StatusBadRequest, "too old"},
		{"just over the limit", now.Add(-MaxEventAge - time.Second), http.StatusBadRequest, "too old"},
		{"a day old", now.Add(-24 * time.Hour), http.StatusBadRequest, "too old"},
		{"an hour in the future", now.Add(time.Hour), http.StatusBadRequest, "in the future"},
		{"just past the clock-skew allowance", now.Add(MaxClockSkew + time.Second), http.StatusBadRequest, "in the future"},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := flagEvent(fmt.Sprintf("refused_%d", i), tc.at)
			w := post(t, r, body, signed(body))
			if w.Code != tc.code || !strings.Contains(w.Body.String(), tc.want) {
				t.Fatalf("status %d body %q, want %d containing %q", w.Code, w.Body.String(), tc.code, tc.want)
			}
		})
	}
	settle()
	if n := rec.calls.Load(); n != 0 {
		t.Fatalf("refused events were re-checked %d times", n)
	}

	// The signature is checked before the timestamp: an unsigned or badly
	// signed stale event is an authentication failure, not a timestamp one.
	stale := flagEvent("unsigned", now.Add(-time.Hour))
	bad := "sha256=" + strings.Repeat("0", 64)
	if w := post(t, r, stale, &bad); w.Code != http.StatusUnauthorized {
		t.Fatalf("bad signature on a stale event: status %d, want 401", w.Code)
	}
	if w := post(t, r, stale, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned stale event: status %d, want 401", w.Code)
	}

	// Inside the limits events are accepted.
	for i, at := range []time.Time{now.Add(-MaxEventAge + time.Second), now, now.Add(MaxClockSkew - time.Second)} {
		body := flagEvent(fmt.Sprintf("accepted_%d", i), at)
		if w := post(t, r, body, signed(body)); w.Code != http.StatusAccepted {
			t.Fatalf("event at %s: status %d, want 202", at.Sub(now), w.Code)
		}
		wait(t, rec.done)
	}
}

func TestEventStampedAheadCannotBeReplayed(t *testing.T) {
	clock := &stepClock{now: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)}
	rec := newRecorder(nil)
	r := newTestReceiver(t, rec, func(o *Options) { o.Now = clock.Now })
	// An event stamped slightly ahead of our clock is remembered until it
	// is too old to be accepted, so it can never be replayed.
	body := flagEvent("beta", clock.Now().Add(MaxClockSkew-time.Second))
	post(t, r, body, signed(body))
	wait(t, rec.done)
	clock.Advance(DedupWindow + time.Second)
	if w := post(t, r, body, signed(body)); !strings.Contains(w.Body.String(), "duplicate") {
		t.Fatalf("replay after the window: status %d body %q, want a duplicate", w.Code, w.Body.String())
	}
	clock.Advance(MaxClockSkew)
	if w := post(t, r, body, signed(body)); w.Code != http.StatusBadRequest {
		t.Fatalf("replay once stale: status %d, want 400", w.Code)
	}
	settle()
	if n := rec.calls.Load(); n != 1 {
		t.Fatalf("re-check calls = %d, want 1", n)
	}
}
