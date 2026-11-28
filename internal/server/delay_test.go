package server

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

// fakeClock is the server clock in tests, so the review delay can be
// crossed without sleeping.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Unix(1700001000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// stamp loads the plans page and returns the signed render timestamp in
// the approve form of plan id.
func (h *harness) stamp(id string) string {
	h.t.Helper()
	_, page, _ := h.get("/plans")
	re := regexp.MustCompile(`action="/plans/` + regexp.QuoteMeta(id) + `/approve"[\s\S]*?name="rendered_at" value="([^"]+)"`)
	m := re.FindStringSubmatch(page)
	if m == nil {
		h.t.Fatalf("no render timestamp in the approve form of plan %s", id)
	}
	return m[1]
}

// approve submits an approval the way a person does: load the page, wait
// out the review delay, then post the form.
func (h *harness) approve(id string, form url.Values) (int, string, http.Header) {
	h.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	form.Set("rendered_at", h.stamp(id))
	h.clock.Advance(ProtectedApproveDelay + time.Second)
	return h.postCSRF("/plans/"+id+"/approve", form)
}

func TestProtectedApproveButtonUnlocksAfterDelay(t *testing.T) {
	h := newHarness(t, nil)
	h.fb.addPlan(samplePlan("P1", true, false, model.PlanPending))
	dev := samplePlan("P2", false, false, model.PlanPending)
	dev.Plan.Environment = "Development"
	h.fb.addPlan(dev)
	_, page, _ := h.get("/plans")
	contains(t, page, `name="rendered_at"`, `data-unlock-after="3"`, `src="/static/approve.js"`, `name="typed_env"`,
		"unlocks 3 seconds after this page loads")
	if n := strings.Count(page, `name="rendered_at"`); n != 1 {
		t.Fatalf("only the protected plan gets a review delay, found %d", n)
	}
	code, js, _ := h.get("/static/approve.js")
	if code != http.StatusOK || !strings.Contains(js, "data-unlock-after") {
		t.Fatalf("approve.js = %d", code)
	}
}

func TestProtectedApproveRefusedBeforeDelay(t *testing.T) {
	h := newHarness(t, nil)
	h.fb.addPlan(samplePlan("P1", true, false, model.PlanPending))
	h.fb.addPlan(samplePlan("P9", true, false, model.PlanPending))
	good := url.Values{"typed_env": {"Production"}}
	refused := func(name string, form url.Values, want string) {
		t.Helper()
		code, body, _ := h.postCSRF("/plans/P1/approve", form)
		if code != http.StatusUnprocessableEntity || !strings.Contains(body, want) {
			t.Fatalf("%s: status %d, want 422 with %q", name, code, want)
		}
		if n := len(h.fb.called("approve")); n != 0 {
			t.Fatalf("%s: backend Approve was called %d times", name, n)
		}
	}
	with := func(stamp string) url.Values {
		return url.Values{"typed_env": good["typed_env"], "rendered_at": {stamp}}
	}

	refused("no timestamp", good, "Reload the page")
	stamp := h.stamp("P1")
	refused("immediately", with(stamp), "3-second review delay")
	h.clock.Advance(ProtectedApproveDelay - time.Millisecond)
	refused("just before the delay ends", with(stamp), "3-second review delay")

	// A timestamp cannot be forged, backdated or borrowed from another plan.
	ms, sig, _ := strings.Cut(stamp, ".")
	refused("unsigned", with(ms), "Reload the page")
	refused("backdated", with("1"+"."+sig), "Reload the page")
	refused("garbage", with("soon.deadbeef"), "Reload the page")
	other := h.stamp("P9")
	h.clock.Advance(time.Minute)
	refused("another plan's timestamp", with(other), "Reload the page")

	code, _, hdr := h.postCSRF("/plans/P1/approve", with(stamp))
	if code != http.StatusSeeOther || !strings.HasPrefix(hdr.Get("Location"), "/plans?ok=approved") {
		t.Fatalf("approve after the delay = %d %q", code, hdr.Get("Location"))
	}
	if n := len(h.fb.called("approve")); n != 1 {
		t.Fatalf("backend Approve calls = %d, want 1", n)
	}
}

func TestProtectedApproveRefusedWhenPageIsStale(t *testing.T) {
	h := newHarness(t, nil)
	h.fb.addPlan(samplePlan("P1", true, false, model.PlanPending))
	stamp := h.stamp("P1")
	h.clock.Advance(approveFormMaxAge + time.Second)
	code, body, _ := h.postCSRF("/plans/P1/approve", url.Values{"typed_env": {"Production"}, "rendered_at": {stamp}})
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, "Review the plan again") {
		t.Fatalf("stale page accepted: %d", code)
	}
	if n := len(h.fb.called("approve")); n != 0 {
		t.Fatalf("backend Approve was called %d times", n)
	}
}

func TestTimestampFromAnotherServerIsRefused(t *testing.T) {
	a, b := newHarness(t, nil), newHarness(t, nil)
	a.fb.addPlan(samplePlan("P1", true, false, model.PlanPending))
	b.fb.addPlan(samplePlan("P1", true, false, model.PlanPending))
	stamp := a.stamp("P1")
	b.clock.Advance(time.Minute)
	code, body, _ := b.postCSRF("/plans/P1/approve", url.Values{"typed_env": {"Production"}, "rendered_at": {stamp}})
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, "Reload the page") {
		t.Fatalf("timestamp signed by another server accepted: %d", code)
	}
}
