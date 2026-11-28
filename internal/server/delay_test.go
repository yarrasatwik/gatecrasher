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

// sampleHashSuffix is the last 4 characters of samplePlan's hash.
const sampleHashSuffix = "cdef"

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
	if _, ok := form["typed_hash"]; !ok {
		form.Set("typed_hash", sampleHashSuffix)
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
	good := url.Values{"typed_env": {"Production"}, "typed_hash": {sampleHashSuffix}}
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
		return url.Values{"typed_env": good["typed_env"], "typed_hash": good["typed_hash"], "rendered_at": {stamp}}
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

	// Even with a valid token, cookie and timestamp after the delay, a
	// request with no Origin and no Sec-Fetch-Site (curl) is refused.
	if code, _, _ := h.postScript("/plans/P1/approve", with(stamp)); code != http.StatusForbidden {
		t.Fatalf("header-less approve after the delay = %d, want 403", code)
	}
	if n := len(h.fb.called("approve")); n != 0 {
		t.Fatalf("backend Approve called %d times by a header-less request", n)
	}

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
	code, body, _ := h.postCSRF("/plans/P1/approve", url.Values{"typed_env": {"Production"}, "typed_hash": {sampleHashSuffix}, "rendered_at": {stamp}})
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
	code, body, _ := b.postCSRF("/plans/P1/approve", url.Values{"typed_env": {"Production"}, "typed_hash": {sampleHashSuffix}, "rendered_at": {stamp}})
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, "Reload the page") {
		t.Fatalf("timestamp signed by another server accepted: %d", code)
	}
}

// A script can read the cookie, CSRF token and timestamp from the plans
// page, wait out the delay and post. It cannot send an Origin or
// Sec-Fetch-Site header the way a browser does, so a protected change must
// be refused without one.
func TestProtectedChangesRefuseRequestsWithoutBrowserOrigin(t *testing.T) {
	h := newHarness(t, nil)
	h.fb.addPlan(samplePlan("P1", true, false, model.PlanPending))
	h.fb.addPlan(samplePlan("P4", true, false, model.PlanApproved))
	h.fb.addPlan(samplePlan("P5", true, false, model.PlanApplied))

	form := url.Values{"typed_env": {"Production"}, "typed_hash": {sampleHashSuffix}, "rendered_at": {h.stamp("P1")}}
	h.clock.Advance(ProtectedApproveDelay + time.Second)
	for _, tc := range []struct{ name, path string }{
		{"approve", "/plans/P1/approve"}, {"apply", "/plans/P4/apply"}, {"rollback", "/plans/P5/rollback"},
	} {
		code, body, _ := h.postScript(tc.path, form)
		if code != http.StatusForbidden || !strings.Contains(body, "must be submitted from the Gatecrasher page in a browser") {
			t.Fatalf("%s without Origin/Sec-Fetch-Site: status %d", tc.name, code)
		}
	}
	for _, name := range []string{"approve", "apply", "rollback"} {
		if n := len(h.fb.called(name)); n != 0 {
			t.Fatalf("backend %s was called %d times by a script", name, n)
		}
	}
	// Other values do not pass either: only the page's own Origin or
	// Sec-Fetch-Site: same-origin does.
	for _, hdr := range []map[string]string{{"Sec-Fetch-Site": "none"}, {"Sec-Fetch-Site": "same-site"}, {"Origin": "null"}} {
		f := url.Values{"typed_env": {"Production"}, "typed_hash": {sampleHashSuffix}, "rendered_at": {h.stamp("P1")}, "csrf_token": {h.token()}}
		h.clock.Advance(ProtectedApproveDelay + time.Second)
		if code, _, _ := h.post("/plans/P1/approve", f, hdr); code == http.StatusSeeOther {
			t.Fatalf("approve accepted with headers %v", hdr)
		}
	}
	if n := len(h.fb.called("approve")); n != 0 {
		t.Fatalf("backend approve called %d times", n)
	}

	// A browser sends the page's own Origin or Sec-Fetch-Site: same-origin.
	f := url.Values{"typed_env": {"Production"}, "typed_hash": {sampleHashSuffix}, "rendered_at": {h.stamp("P1")}, "csrf_token": {h.token()}}
	h.clock.Advance(ProtectedApproveDelay + time.Second)
	if code, _, _ := h.post("/plans/P1/approve", f, map[string]string{"Origin": h.ts.URL}); code != http.StatusSeeOther {
		t.Fatalf("approve with the page's Origin = %d", code)
	}
	if code, _, _ := h.postCSRF("/plans/P4/apply", nil); code != http.StatusSeeOther {
		t.Fatalf("apply from the page = %d", code)
	}
	if code, _, _ := h.postCSRF("/plans/P5/rollback", nil); code != http.StatusSeeOther {
		t.Fatalf("rollback from the page = %d", code)
	}
}

// The terminal asks for the last 4 characters of the plan hash; the web form
// does too, and the server checks the suffix.
func TestProtectedApproveNeedsPlanHashSuffix(t *testing.T) {
	h := newHarness(t, nil)
	h.fb.addPlan(samplePlan("P1", true, false, model.PlanPending))
	dev := samplePlan("P2", false, false, model.PlanPending)
	dev.Plan.Environment = "Development"
	h.fb.addPlan(dev)

	_, page, _ := h.get("/plans")
	contains(t, page, `name="typed_hash"`, "0123456789abcdef0123456789abcdef", "last 4 characters of the plan hash")
	if n := strings.Count(page, `name="typed_hash"`); n != 1 {
		t.Fatalf("only the protected plan asks for the hash suffix, found %d fields", n)
	}
	// The placeholder stays neutral: it must not hint at the answer.
	notContains(t, page, `placeholder="cdef"`, `placeholder="0123`)

	for name, suffix := range map[string]string{"missing": "", "wrong": "beef", "too short": "f", "prefix not suffix": "0123", "too long": "bcdef"} {
		code, body, _ := h.approve("P1", url.Values{"typed_env": {"Production"}, "typed_hash": {suffix}})
		if code != http.StatusUnprocessableEntity || !strings.Contains(body, "last 4 characters of the plan hash") {
			t.Fatalf("%s suffix: status %d", name, code)
		}
	}
	if n := len(h.fb.called("approve")); n != 0 {
		t.Fatalf("backend Approve called %d times with a bad suffix", n)
	}
	code, _, _ := h.approve("P1", url.Values{"typed_env": {"Production"}, "typed_hash": {" CDEF "}})
	if code != http.StatusSeeOther {
		t.Fatalf("right suffix = %d", code)
	}
	if n := len(h.fb.called("approve")); n != 1 {
		t.Fatalf("backend Approve calls = %d, want 1", n)
	}
	// Non-protected environments keep the current behaviour.
	if code, _, _ := h.postCSRF("/plans/P2/approve", nil); code != http.StatusSeeOther {
		t.Fatalf("non-protected approve = %d", code)
	}
}

// Plans for other environments keep the current behaviour.
func TestNonProtectedChangesDoNotNeedBrowserOrigin(t *testing.T) {
	h := newHarness(t, nil)
	dev := samplePlan("P2", false, false, model.PlanPending)
	dev.Plan.Environment = "Development"
	h.fb.addPlan(dev)
	if code, _, _ := h.postScript("/plans/P2/approve", nil); code != http.StatusSeeOther {
		t.Fatalf("non-protected approve = %d", code)
	}
}
