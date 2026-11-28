package server

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/watch"
)

type harness struct {
	t      *testing.T
	fb     *stubBackend
	srv    *Server
	ts     *httptest.Server
	client *http.Client
	clock  *fakeClock
}

func newHarness(t *testing.T, mod func(*Options)) *harness {
	t.Helper()
	fb := newStubBackend()
	clock := newFakeClock()
	opts := Options{Backend: fb, Now: clock.Now}
	if mod != nil {
		mod(&opts)
	}
	srv, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(func() { ts.Close(); srv.Close() })
	return &harness{t: t, fb: fb, srv: srv, ts: ts, client: client, clock: clock}
}

func (h *harness) do(req *http.Request) (int, string, http.Header) {
	h.t.Helper()
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func (h *harness) get(path string) (int, string, http.Header) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, h.ts.URL+path, nil)
	return h.do(req)
}

// token returns the CSRF token for this client, visiting a page first.
func (h *harness) token() string {
	h.t.Helper()
	h.get("/")
	u, _ := url.Parse(h.ts.URL)
	for _, c := range h.client.Jar.Cookies(u) {
		if c.Name == csrfCookie {
			return c.Value
		}
	}
	h.t.Fatal("no CSRF cookie issued")
	return ""
}

func (h *harness) post(path string, form url.Values, headers map[string]string) (int, string, http.Header) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return h.do(req)
}

// postCSRF posts with a valid token.
func (h *harness) postCSRF(path string, form url.Values) (int, string, http.Header) {
	h.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	form.Set("csrf_token", h.token())
	return h.post(path, form, nil)
}

func contains(t *testing.T, body string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(body, w) {
			t.Errorf("body missing %q", w)
		}
	}
}

func notContains(t *testing.T, body string, nots ...string) {
	t.Helper()
	for _, n := range nots {
		if strings.Contains(body, n) {
			t.Errorf("body must not contain %q", n)
		}
	}
}

func TestNewRequiresBackend(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("expected error without a Backend")
	}
}

func TestPagesRender(t *testing.T) {
	h := newHarness(t, nil)
	h.fb.addPlan(samplePlan("P1", true, true, model.PlanPending))
	h.fb.push(watch.Alert{ID: "AL-1", At: time.Unix(1700000300, 0), LatencyMS: 812, EventLatencyMS: 2300, ReviewURL: "/plans?finding=GC-AAAA1111",
		Change:   watch.Change{Kind: "SEGMENT_UPDATED", Segment: "beta", Environment: "Production"},
		Findings: []model.Finding{{ID: "GC-AAAA1111", Severity: model.SevCritical, Title: "Anyone can join"}}})
	tests := []struct {
		path  string
		wants []string
	}{
		{"/", []string{"Run full audit", "https://shop.example.com", "off (heuristics)", "2 ways in", "Skip to main content", `aria-live="polite"`, "shop.example.com", "localhost:8000"}},
		{"/report/R1", []string{"2 ways in", "Anyone can join the beta segment", "/files/R1.html", "/files/R1.json", "/files/R1.sarif", "CRITICAL", "Evidence (1)", "Reachability map", "Environment security settings", "Controls that held", "&lt;CLIENT_KEY&gt;"}},
		{"/plans", []string{"Disable client traits", "Experiment warning", "checkout_v2", "web/app.js:42", "PR draft", "PRODUCTION", "Approve", "Reject"}},
		{"/watch", []string{"Review fix", "812 ms", "2.3 s", `id="alert-list"`, "Anyone can join"}},
		{"/audit", []string{"Chain valid", "2 entries verified", "plan.approve", "aaaaaaaaaaaa"}},
		{"/static/app.css", []string{"prefers-color-scheme: dark"}},
		{"/static/watch.js", []string{"EventSource"}},
		{"/static/favicon.svg", []string{"<svg"}},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			code, body, _ := h.get(tc.path)
			if code != http.StatusOK {
				t.Fatalf("status = %d", code)
			}
			contains(t, body, tc.wants...)
		})
	}
}

func TestNotFound(t *testing.T) {
	h := newHarness(t, nil)
	for _, p := range []string{"/report/nope", "/report/bad%20id", "/report/..%2Fetc", "/nothing-here", "/static/missing.css"} {
		if code, _, _ := h.get(p); code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, code)
		}
	}
	tok := h.token()
	for _, p := range []string{"/plans/NOPE/approve", "/plans/P1/explode"} {
		if code, _, _ := h.post(p, url.Values{"csrf_token": {tok}}, nil); code != http.StatusNotFound {
			t.Errorf("POST %s = %d, want 404", p, code)
		}
	}
}

var inlineScript = regexp.MustCompile(`(?is)<script(?:\s[^>]*)?>`)

func TestSecurityHeadersAndNoInlineScript(t *testing.T) {
	h := newHarness(t, nil)
	h.fb.addPlan(samplePlan("P1", true, false, model.PlanPending))
	for _, p := range []string{"/", "/report/R1", "/plans", "/watch", "/audit", "/nothing"} {
		_, body, hdr := h.get(p)
		policy := hdr.Get("Content-Security-Policy")
		contains(t, policy, "script-src 'self' "+HTMXURL, "frame-ancestors 'none'", "default-src 'none'")
		notContains(t, policy, "unsafe-inline", "unsafe-eval")
		if hdr.Get("X-Frame-Options") != "DENY" || hdr.Get("X-Content-Type-Options") != "nosniff" || hdr.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: missing hardening headers: %v", p, hdr)
		}
		for _, m := range inlineScript.FindAllString(body, -1) {
			if !strings.Contains(m, "src=") {
				t.Errorf("%s: inline script tag %q", p, m)
			}
		}
		if strings.Contains(body, " style=") || strings.Contains(body, " onclick=") {
			t.Errorf("%s: inline style or handler attribute present", p)
		}
	}
	_, body, _ := h.get("/")
	contains(t, body, `src="`+HTMXURL+`"`, `integrity="sha384-`)
}

func TestCookieAttributes(t *testing.T) {
	h := newHarness(t, nil)
	_, _, hdr := h.get("/")
	var set string
	for _, v := range hdr.Values("Set-Cookie") {
		if strings.HasPrefix(v, csrfCookie+"=") {
			set = v
		}
	}
	contains(t, set, "HttpOnly", "SameSite=Strict", "Path=/")
}

func TestHostCheckBlocksRebinding(t *testing.T) {
	h := newHarness(t, nil)
	req, _ := http.NewRequest(http.MethodGet, h.ts.URL+"/", nil)
	req.Host = "evil.example.com"
	if code, _, _ := h.do(req); code != http.StatusForbidden {
		t.Fatalf("foreign Host status = %d, want 403", code)
	}
	h2 := newHarness(t, func(o *Options) { o.AllowedHosts = []string{"gc.internal:8787"} })
	req, _ = http.NewRequest(http.MethodGet, h2.ts.URL+"/", nil)
	req.Host = "gc.internal:8787"
	if code, _, _ := h2.do(req); code != http.StatusOK {
		t.Fatalf("allow-listed Host status = %d, want 200", code)
	}
}

func TestCSRFRejection(t *testing.T) {
	h := newHarness(t, nil)
	tok := h.token()
	tests := []struct {
		name    string
		form    url.Values
		headers map[string]string
		want    int
	}{
		{"no token", url.Values{}, nil, http.StatusForbidden},
		{"wrong token", url.Values{"csrf_token": {strings.Repeat("a", 64)}}, nil, http.StatusForbidden},
		{"cross-origin", url.Values{"csrf_token": {tok}}, map[string]string{"Origin": "http://evil.example.com"}, http.StatusForbidden},
		{"cross-site fetch", url.Values{"csrf_token": {tok}}, map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"valid form token", url.Values{"csrf_token": {tok}}, nil, http.StatusSeeOther},
		{"valid header token", url.Values{}, map[string]string{"X-CSRF-Token": tok}, http.StatusSeeOther},
	}
	h.fb.runGate = make(chan struct{})
	defer close(h.fb.runGate)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if code, _, _ := h.post("/run", tc.form, tc.headers); code != tc.want {
				t.Fatalf("status = %d, want %d", code, tc.want)
			}
		})
	}
	t.Run("no cookie at all", func(t *testing.T) {
		fresh := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := fresh.PostForm(h.ts.URL+"/run", url.Values{"csrf_token": {tok}})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("cookieless POST = %d, want 403", resp.StatusCode)
		}
	})
}

func TestRunAuditProgress(t *testing.T) {
	h := newHarness(t, nil)
	h.fb.runGate = make(chan struct{})
	code, body, _ := h.post("/run", url.Values{"csrf_token": {h.token()}}, map[string]string{"HX-Request": "true"})
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	contains(t, body, "Audit running", `hx-get="/run/status"`)
	notContains(t, body, "<html")

	waitFor(t, func() bool {
		_, b, _ := h.get("/run/status")
		return strings.Contains(b, "fetching target")
	})
	close(h.fb.runGate)
	var final string
	waitFor(t, func() bool {
		_, final, _ = h.get("/run/status")
		return strings.Contains(final, "Audit complete")
	})
	contains(t, final, `href="/report/R1"`, "probing with")
	notContains(t, final, "ser.abcdefghijklmnop", `hx-trigger`)

	_, dash, _ := h.get("/")
	contains(t, dash, "Audit complete")
}

func TestRunAuditFailureAndSingleFlight(t *testing.T) {
	h := newHarness(t, nil)
	h.fb.failWith = errors.New("boom with Api-Key ABCDEFGH.0123456789abcdef0123456789abcdef")
	h.fb.runGate = make(chan struct{})
	tok := h.token()
	h.post("/run", url.Values{"csrf_token": {tok}}, nil)
	h.post("/run", url.Values{"csrf_token": {tok}}, nil) // second click while running must not start another
	close(h.fb.runGate)
	var final string
	waitFor(t, func() bool {
		_, final, _ = h.get("/run/status")
		return strings.Contains(final, "Audit failed")
	})
	notContains(t, final, "0123456789abcdef0123456789abcdef")
	if n := len(h.fb.called("recon")); n != 0 {
		t.Fatalf("unexpected calls %d", n)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

func TestApprovalRequiresTypedEnvironment(t *testing.T) {
	h := newHarness(t, nil)
	h.fb.addPlan(samplePlan("P1", true, false, model.PlanPending))
	tests := []struct {
		name  string
		typed string
	}{
		{"empty", ""},
		{"wrong name", "Staging"},
		{"wrong case", "production"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, body, _ := h.postCSRF("/plans/P1/approve", url.Values{"typed_env": {tc.typed}})
			if code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422", code)
			}
			contains(t, body, `Type the environment name &#34;Production&#34; exactly`, `role="alert"`, `aria-invalid="true"`, `for="env-P1"`)
			if n := len(h.fb.called("approve")); n != 0 {
				t.Fatalf("backend Approve called %d times without confirmation", n)
			}
		})
	}
	code, _, hdr := h.approve("P1", url.Values{"typed_env": {"Production"}})
	if code != http.StatusSeeOther || !strings.HasPrefix(hdr.Get("Location"), "/plans?ok=approved") {
		t.Fatalf("approve = %d %q", code, hdr.Get("Location"))
	}
	calls := h.fb.called("approve")
	if len(calls) != 1 || !strings.Contains(calls[0], `env="Production"`) || !strings.Contains(calls[0], "by=web") {
		t.Fatalf("backend calls = %v", calls)
	}
	_, page, _ := h.get(hdr.Get("Location"))
	contains(t, page, "Plan approved", "Apply to Flagsmith")
}

func TestNonProductionApprovalNeedsNoTyping(t *testing.T) {
	h := newHarness(t, nil)
	rec := samplePlan("P2", false, false, model.PlanPending)
	rec.Plan.Environment = "Development"
	h.fb.addPlan(rec)
	_, page, _ := h.get("/plans")
	notContains(t, page, `name="typed_env"`)
	if code, _, _ := h.postCSRF("/plans/P2/approve", nil); code != http.StatusSeeOther {
		t.Fatalf("approve status = %d", code)
	}
}

func TestApprovalRequiresContaminateConfirmation(t *testing.T) {
	h := newHarness(t, nil)
	h.fb.addPlan(samplePlan("P1", true, true, model.PlanPending))
	_, page, _ := h.get("/plans")
	contains(t, page, `name="typed_contaminate"`, "contaminate-experiment")

	code, body, _ := h.postCSRF("/plans/P1/approve", url.Values{"typed_env": {"Production"}})
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, "affects a running experiment") {
		t.Fatalf("missing contaminate text accepted: %d", code)
	}
	if n := len(h.fb.called("approve")); n != 0 {
		t.Fatal("backend called despite missing confirmation")
	}
	code, _, _ = h.approve("P1", url.Values{"typed_env": {"Production"}, "typed_contaminate": {"contaminate-experiment"}})
	if code != http.StatusSeeOther {
		t.Fatalf("status = %d", code)
	}
	if c := h.fb.called("approve"); len(c) != 1 || !strings.Contains(c[0], `contaminate="contaminate-experiment"`) {
		t.Fatalf("calls = %v", c)
	}
}

func TestBackendErrorsAreShownRedacted(t *testing.T) {
	h := newHarness(t, nil)
	h.fb.addPlan(samplePlan("P1", true, false, model.PlanPending))
	h.fb.failWith = errors.New("plan is stale; token ser.abcdefghijklmnop rejected")
	code, body, _ := h.approve("P1", url.Values{"typed_env": {"Production"}})
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d", code)
	}
	contains(t, body, "plan is stale")
	notContains(t, body, "ser.abcdefghijklmnop")
}

func TestPlanLifecycleActions(t *testing.T) {
	h := newHarness(t, nil)
	h.fb.addPlan(samplePlan("P1", false, false, model.PlanApproved))
	h.fb.addPlan(samplePlan("P3", false, false, model.PlanPending))

	steps := []struct {
		id, action, wantNotice, wantCall string
	}{
		{"P1", "apply", "applied", "apply P1"},
		{"P1", "verify", "verified", "verify P1"},
		{"P1", "rollback", "rolledback", "rollback P1"},
		{"P3", "reject", "rejected", "reject P3 by=web"},
	}
	for _, s := range steps {
		code, _, hdr := h.postCSRF("/plans/"+s.id+"/"+s.action, nil)
		if code != http.StatusSeeOther || !strings.Contains(hdr.Get("Location"), "ok="+s.wantNotice) {
			t.Fatalf("%s: %d %q", s.action, code, hdr.Get("Location"))
		}
		if len(h.fb.called(s.wantCall)) != 1 {
			t.Fatalf("backend not called with %q: %v", s.wantCall, h.fb.calls)
		}
	}
	// Actions invalid for the current state are refused without touching the backend.
	for _, a := range []string{"apply", "verify", "rollback"} {
		before := len(h.fb.calls)
		code, body, _ := h.postCSRF("/plans/P3/"+a, nil)
		if code != http.StatusUnprocessableEntity || !strings.Contains(body, "cannot be") || len(h.fb.calls) != before {
			t.Errorf("%s on rejected plan: status %d, backend touched=%v", a, code, len(h.fb.calls) != before)
		}
	}
}

func TestAppliedPlanShowsVerifyRollbackAndBeforeAfter(t *testing.T) {
	h := newHarness(t, nil)
	h.fb.addPlan(samplePlan("P1", false, false, model.PlanApplied))
	_, page, _ := h.get("/plans")
	contains(t, page, "Verify (re-attack)", "Roll back", `action="/plans/P1/verify"`, `action="/plans/P1/rollback"`)
	notContains(t, page, "Apply to Flagsmith", `name="typed_env"`)

	h.postCSRF("/plans/P1/verify", nil)
	_, page, _ = h.get("/plans")
	contains(t, page, "Before and after", "Forgeable segment", "EXPLOITABLE", "BLOCKED", "probe returned default")
}

func TestPlanCardDetails(t *testing.T) {
	h := newHarness(t, nil)
	h.fb.addPlan(samplePlan("P1", true, true, model.PlanPending))
	_, page, _ := h.get("/plans?finding=GC-AAAA1111")
	contains(t, page,
		"What changes", "allow_client_traits", `class="before"`, `class="after"`,
		"Why", `href="/report/R1#f-GC-AAAA1111"`, "Anyone can join the beta segment",
		"What could break", "web/app.js:42", "Will break", "client.identify",
		"<details><summary>PR draft</summary>", "Guidance only, never executed",
		"Showing plans for finding")
	_, page, _ = h.get("/plans?finding=GC-UNKNOWN")
	contains(t, page, "No plan addresses finding", "Disable client traits")
}

func TestMakePlans(t *testing.T) {
	h := newHarness(t, nil)
	code, _, hdr := h.postCSRF("/plans/make", url.Values{"report_id": {"R1"}})
	if code != http.StatusSeeOther || !strings.Contains(hdr.Get("Location"), "ok=planned") || len(h.fb.called("make R1")) != 1 {
		t.Fatalf("make plans: %d %q %v", code, hdr.Get("Location"), h.fb.calls)
	}
	if code, _, _ := h.postCSRF("/plans/make", url.Values{"report_id": {"../x"}}); code != http.StatusUnprocessableEntity {
		t.Fatalf("bad report id status = %d", code)
	}
	if code, _, _ := h.postCSRF("/plans/make", url.Values{"report_id": {"ghost"}}); code != http.StatusNotFound {
		t.Fatalf("missing report status = %d", code)
	}
}

func TestOutputIsEscapedAndRedacted(t *testing.T) {
	h := newHarness(t, nil)
	rep := sampleReport("R2")
	rep.Findings[0].Title = `<script>alert(1)</script> ser.abcdefghijklmnop`
	rep.Findings[0].Repro = `curl 'x' -H "Authorization: Api-Key ABCDEFGH.0123456789abcdef0123456789abcdef"`
	h.fb.reports["R2"] = rep
	h.fb.push(watch.Alert{ID: "AL-x", Change: watch.Change{Kind: "FLAG_UPDATED", Feature: `<img src=x onerror=alert(1)>`}, ReviewURL: "javascript:alert(1)",
		Findings: []model.Finding{{ID: "GC-1", Severity: model.SevHigh, Title: "t"}}})
	_, body, _ := h.get("/report/R2")
	notContains(t, body, "<script>alert(1)", "ser.abcdefghijklmnop", "0123456789abcdef0123456789abcdef")
	contains(t, body, "&lt;script&gt;alert(1)&lt;/script&gt;")
	_, watchPage, _ := h.get("/watch")
	notContains(t, watchPage, "<img src=x", `href="javascript:`)
}

func TestAuditChainBrokenIndicator(t *testing.T) {
	h := newHarness(t, nil)
	h.fb.chainOK, h.fb.chainN = false, 2
	_, body, _ := h.get("/audit")
	contains(t, body, "Chain broken", "entry #2", `role="alert"`, `class="row-broken"`)
	notContains(t, body, "Chain valid")
}

func TestWatchStreamEmitsAlerts(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, h.ts.URL+"/watch/stream", nil)
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type = %q", ct)
	}
	waitFor(t, func() bool { return h.fb.subscribers() == 1 })
	h.fb.push(watch.Alert{ID: "AL-live", At: time.Now(), LatencyMS: 640, ReviewURL: "/plans?finding=GC-9",
		Change:   watch.Change{Kind: "FLAG_UPDATED", Feature: "dark_mode", Environment: "Production"},
		Findings: []model.Finding{{ID: "GC-9", Severity: model.SevHigh, Title: "Forgeable <b>segment</b>"}}})

	sc := bufio.NewScanner(resp.Body)
	var event string
	var data []string
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			data = append(data, strings.TrimPrefix(line, "data: "))
		case line == "" && event != "":
			html := strings.Join(data, "\n")
			if event != "alert" {
				t.Fatalf("event = %q", event)
			}
			contains(t, html, `id="alert-AL-live"`, "Review fix", "640 ms", "dark_mode", "Forgeable &lt;b&gt;segment&lt;/b&gt;", `href="/plans?finding=GC-9"`)
			return
		}
	}
	t.Fatalf("stream ended without an alert: %v", sc.Err())
}

func TestWebhookAndFilesMounts(t *testing.T) {
	var hooked bool
	hook := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hooked = true; w.WriteHeader(http.StatusAccepted) })
	files := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "file:"+r.URL.Path) })
	h := newHarness(t, func(o *Options) { o.Webhook, o.Files = hook, files })

	// Flagsmith is not a browser: no cookie, no CSRF token, foreign Host.
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+WebhookPath, strings.NewReader("{}"))
	req.Host = "host.docker.internal:8787"
	if code, _, _ := h.do(req); code != http.StatusAccepted || !hooked {
		t.Fatalf("webhook not reached: %d", code)
	}
	code, body, _ := h.get("/files/R1.html")
	if code != http.StatusOK || body != "file:/files/R1.html" {
		t.Fatalf("files mount: %d %q", code, body)
	}
	// The exemption covers only the webhook path.
	req, _ = http.NewRequest(http.MethodPost, h.ts.URL+"/run", strings.NewReader(""))
	req.Host = "host.docker.internal:8787"
	if code, _, _ := h.do(req); code != http.StatusForbidden {
		t.Fatalf("foreign host reached /run: %d", code)
	}
}

func TestDashboardShowsNoSecrets(t *testing.T) {
	h := newHarness(t, nil)
	_, body, _ := h.get("/")
	notContains(t, body, "ser.", "Api-Key")
}

func TestSummarizeReportAndWaysIn(t *testing.T) {
	sum := SummarizeReport(sampleReport("R9"))
	if sum.ID != "R9" || sum.WaysIn != 2 || sum.BySeverity["critical"] != 1 {
		t.Fatalf("unexpected summary %+v", sum)
	}
}
