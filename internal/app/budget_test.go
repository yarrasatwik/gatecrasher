package app

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/config"
	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
	"github.com/yarrasatwik/gatecrasher/internal/report"
	"github.com/yarrasatwik/gatecrasher/internal/watch"
)

const budgetClientKey = "ENVKEYacmeshopprod0123456"

// stubLab is a small in-memory Flagsmith plus the shop page, built from the
// recorded responses in tests/fixtures. It counts every request it receives,
// so the tests can compare what the audit says it sent with what arrived.
type stubLab struct {
	srv  *httptest.Server
	hits atomic.Int64
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ReplaceAll(string(b), "REDACTED_PRODUCTION_CLIENT_KEY", budgetClientKey)
	s = strings.ReplaceAll(s, "REDACTED_DEVELOPMENT_CLIENT_KEY", "ENVKEYacmeshopdev01234567")
	return []byte(s)
}

func newStubLab(t *testing.T) *stubLab {
	t.Helper()
	redact.Reset()
	l := &stubLab{}
	flags := fixture(t, "flags_client.json")
	gold := fixture(t, "identity_probe_transient.json")
	plain := []byte(`{"identifier":"x","traits":[],"flags":` + string(flags) + `}`)
	serve := func(w http.ResponseWriter, b []byte) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><script>flagsmith.init({environmentID: "%s"});</script></body></html>`, budgetClientKey)
	})
	mux.HandleFunc("GET /api/v1/flags/", func(w http.ResponseWriter, r *http.Request) { serve(w, flags) })
	mux.HandleFunc("POST /api/v1/identities/", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Traits []struct {
				Key   string `json:"trait_key"`
				Value any    `json:"trait_value"`
			} `json:"traits"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		for _, tr := range body.Traits {
			if tr.Key == "plan" && tr.Value == "gold" {
				serve(w, gold)
				return
			}
		}
		serve(w, plain)
	})
	mux.HandleFunc("GET /api/v1/projects/", func(w http.ResponseWriter, r *http.Request) { serve(w, fixture(t, "projects.json")) })
	mux.HandleFunc("GET /api/v1/environments/", func(w http.ResponseWriter, r *http.Request) { serve(w, fixture(t, "environments.json")) })
	mux.HandleFunc("GET /api/v1/environments/{key}/", func(w http.ResponseWriter, r *http.Request) { serve(w, fixture(t, "environment_settings.json")) })
	mux.HandleFunc("GET /api/v1/environments/{key}/document/", func(w http.ResponseWriter, r *http.Request) { serve(w, fixture(t, "environment_document.json")) })
	mux.HandleFunc("GET /api/v1/environments/{key}/experiments/", func(w http.ResponseWriter, r *http.Request) { serve(w, fixture(t, "experiments.json")) })
	mux.HandleFunc("GET /api/v1/projects/{id}/features/", func(w http.ResponseWriter, r *http.Request) { serve(w, fixture(t, "features.json")) })
	mux.HandleFunc("GET /api/v1/projects/{id}/segments/", func(w http.ResponseWriter, r *http.Request) { serve(w, fixture(t, "segments.json")) })
	l.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.hits.Add(1)
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(l.srv.Close)
	return l
}

func (l *stubLab) app(t *testing.T, mut func(*config.Config)) *App {
	t.Helper()
	host := strings.TrimPrefix(l.srv.URL, "http://")
	dir := t.TempDir()
	cfg := &config.Config{
		TargetURL: l.srv.URL,
		Flagsmith: config.Flagsmith{APIURL: l.srv.URL + "/api/v1/", AllowedAPIHosts: []string{host}, Project: "Acme Shop", Environments: []string{"Production"}},
		StateDir:  filepath.Join(dir, "state"), ReportDir: filepath.Join(dir, "reports"),
		OrgAPIKey: "orgkey.abcdefghijklmnopqrstuvwxyz012345",
		Probes:    config.Probes{RatePerSec: 1e6},
	}
	cfg.Defaults()
	if mut != nil {
		mut(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func fullAudit(a *App, budget int) AuditOptions {
	return AuditOptions{Outside: true, Inside: true, ParitySamples: a.Cfg.ParitySamples(), Budget: budget}
}

func TestStubLabAuditRunsEveryStage(t *testing.T) {
	l := newStubLab(t)
	a := l.app(t, nil)
	r, err := a.Audit(context.Background(), fullAudit(a, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Stats.Incomplete) != 0 || r.Stats.Budget != 0 {
		t.Fatalf("an unbudgeted run must be complete: %+v", r.Stats)
	}
	for _, stage := range []string{"recon", "attack", "map", "verify", "parity"} {
		if r.Stats.StageRequests[stage] == 0 {
			t.Errorf("stage %s sent no requests: %v", stage, r.Stats.StageRequests)
		}
	}
	if r.Stats.ProbesSent != l.hits.Load() {
		t.Fatalf("report says %d requests, stub received %d", r.Stats.ProbesSent, l.hits.Load())
	}
	var sum int64
	for _, n := range r.Stats.StageRequests {
		sum += n
	}
	if sum != r.Stats.ProbesSent {
		t.Fatalf("stage requests %v add up to %d, probes_sent is %d", r.Stats.StageRequests, sum, r.Stats.ProbesSent)
	}
}

func TestBudgetOf50StopsAuditAndMarksStagesIncomplete(t *testing.T) {
	l := newStubLab(t)
	a := l.app(t, nil)
	r, err := a.Audit(context.Background(), fullAudit(a, 50))
	if err != nil {
		t.Fatalf("a budget stop is a result, not an error: %v", err)
	}
	if got := l.hits.Load(); got > 50 {
		t.Fatalf("stub received %d requests with a budget of 50", got)
	}
	if r.Stats.ProbesSent > 50 || r.Stats.Budget != 50 {
		t.Fatalf("probes_sent=%d budget=%d", r.Stats.ProbesSent, r.Stats.Budget)
	}
	if len(r.Stats.Incomplete) == 0 {
		t.Fatal("no stage marked incomplete")
	}
	inc := strings.Join(r.Stats.Incomplete, ",")
	for _, want := range []string{"map", "verify", "parity"} {
		if !strings.Contains(inc, want) {
			t.Errorf("stage %s not marked incomplete: %s", want, inc)
		}
	}
	if note := report.IncompleteNote(r); !strings.Contains(note, "incomplete (budget)") {
		t.Fatalf("note = %q", note)
	}
	if !strings.Contains(strings.Join(r.Notes, "\n"), "incomplete (budget)") {
		t.Fatalf("notes = %v", r.Notes)
	}
}

func TestBudgetStopNeverReportsUncheckedFindingsAsSafe(t *testing.T) {
	l := newStubLab(t)
	a := l.app(t, nil)
	full, err := a.Audit(context.Background(), fullAudit(a, 0))
	if err != nil {
		t.Fatal(err)
	}
	// Enough for recon, attack and map, then three live cross-checks.
	budget := int(full.Stats.StageRequests["recon"] + full.Stats.StageRequests["attack"] + full.Stats.StageRequests["map"] + 3)
	if budget >= int(full.Stats.ProbesSent) {
		t.Fatalf("budget %d does not cut the run (%d)", budget, full.Stats.ProbesSent)
	}
	l.hits.Store(0)
	a = l.app(t, nil) // a fresh process: the project lookups are not cached
	r, err := a.Audit(context.Background(), fullAudit(a, budget))
	if err != nil {
		t.Fatal(err)
	}
	if l.hits.Load() > int64(budget) {
		t.Fatalf("%d requests with a budget of %d", l.hits.Load(), budget)
	}
	inc := strings.Join(r.Stats.Incomplete, ",")
	if !strings.Contains(inc, "verify") || !strings.Contains(inc, "parity") || strings.Contains(inc, "map") {
		t.Fatalf("incomplete = %s, want verify and parity but not map", inc)
	}
	blocked := func(rep *model.Report) int {
		n := 0
		for _, f := range rep.Findings {
			if f.Status == model.StatusBlocked {
				n++
			}
		}
		return n
	}
	if blocked(r) > blocked(full) {
		t.Fatalf("a budget stop produced %d BLOCKED findings (full run %d)", blocked(r), blocked(full))
	}
	// Findings the cut-off cross-check could not confirm say so.
	cut := 0
	for _, f := range r.Findings {
		for _, n := range f.Notes {
			if strings.Contains(n, "request budget") {
				cut++
			}
		}
	}
	if cut == 0 {
		t.Fatal("no finding records that its live check was skipped for lack of budget")
	}
}

func TestConfigMaxRequestsActsAsTheBudget(t *testing.T) {
	l := newStubLab(t)
	a := l.app(t, func(c *config.Config) { c.Probes.MaxRequests = 40 })
	r, err := a.Audit(context.Background(), fullAudit(a, 0))
	if err != nil {
		t.Fatal(err)
	}
	if l.hits.Load() > 40 || r.Stats.Budget != 40 || len(r.Stats.Incomplete) == 0 {
		t.Fatalf("hits=%d budget=%d incomplete=%v", l.hits.Load(), r.Stats.Budget, r.Stats.Incomplete)
	}
	// --budget wins over the config value.
	l.hits.Store(0)
	r, err = a.Audit(context.Background(), fullAudit(a, 25))
	if err != nil {
		t.Fatal(err)
	}
	if l.hits.Load() > 25 || r.Stats.Budget != 25 {
		t.Fatalf("hits=%d budget=%d", l.hits.Load(), r.Stats.Budget)
	}
}

func TestDryRunEstimateSendsNothing(t *testing.T) {
	l := newStubLab(t)
	a := l.app(t, nil)
	e := a.Estimate(fullAudit(a, 0))
	if l.hits.Load() != 0 {
		t.Fatalf("Estimate sent %d requests", l.hits.Load())
	}
	if e.Total <= 0 || len(e.Stages) < 5 || e.Profile != config.ProfileLab {
		t.Fatalf("estimate = %+v", e)
	}
	txt := e.Text()
	for _, want := range []string{"estimated requests", "recon", "attack", "map", "verify", "parity", "total", "profile lab"} {
		if !strings.Contains(txt, want) {
			t.Errorf("estimate text lacks %q:\n%s", want, txt)
		}
	}
}

func TestEstimateShowsWhereABudgetWouldStopTheRun(t *testing.T) {
	l := newStubLab(t)
	a := l.app(t, nil)
	e := a.Estimate(fullAudit(a, 50))
	if !strings.Contains(e.Text(), "budget 50") || !strings.Contains(e.Text(), "incomplete (budget)") {
		t.Fatalf("estimate text:\n%s", e.Text())
	}
}

func within(est, actual int, pct float64) bool {
	return math.Abs(float64(est)-float64(actual)) <= pct*float64(actual)
}

func TestEstimateIsWithinTenPercentOfAStubLabRun(t *testing.T) {
	l := newStubLab(t)
	a := l.app(t, nil)
	cold := a.Estimate(fullAudit(a, 0)) // no earlier report: config and assumptions only
	r, err := a.Audit(context.Background(), fullAudit(a, 0))
	if err != nil {
		t.Fatal(err)
	}
	actual := int(r.Stats.ProbesSent)
	if !within(cold.Total, actual, 0.10) {
		t.Fatalf("cold estimate %d vs actual %d (per stage actual %v)\n%s", cold.Total, actual, r.Stats.StageRequests, cold.Text())
	}
	// With the earlier report on disk the known counts replace the assumptions.
	if _, err := a.SaveReport(r); err != nil {
		t.Fatal(err)
	}
	warm := a.Estimate(fullAudit(a, 0))
	if !within(warm.Total, actual, 0.10) {
		t.Fatalf("warm estimate %d vs actual %d\n%s", warm.Total, actual, warm.Text())
	}
	if warm.Source == "" {
		t.Fatal("a warm estimate must say which report it used")
	}
}

func TestCloudProfileShrinksTheRun(t *testing.T) {
	l := newStubLab(t)
	lab := l.app(t, nil)
	cloud := l.app(t, func(c *config.Config) { c.Profile = config.ProfileCloud })
	rl, err := lab.Audit(context.Background(), fullAudit(lab, 0))
	if err != nil {
		t.Fatal(err)
	}
	rc, err := cloud.Audit(context.Background(), fullAudit(cloud, 0))
	if err != nil {
		t.Fatal(err)
	}
	if rc.Stats.ProbesSent >= rl.Stats.ProbesSent || rc.Stats.StageRequests["parity"] != 200 {
		t.Fatalf("cloud sent %d (parity %d), lab sent %d", rc.Stats.ProbesSent, rc.Stats.StageRequests["parity"], rl.Stats.ProbesSent)
	}
}

func TestHourlyBudgetRollsOverAnHour(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	h := newHourlyBudget(10, func() time.Time { return now })
	if h.remaining() != 10 {
		t.Fatalf("remaining = %d", h.remaining())
	}
	h.record(6)
	now = now.Add(30 * time.Minute)
	h.record(4)
	if h.remaining() != 0 {
		t.Fatalf("remaining = %d, want 0", h.remaining())
	}
	now = now.Add(31 * time.Minute) // the first 6 are now over an hour old
	if h.remaining() != 6 {
		t.Fatalf("remaining = %d, want 6", h.remaining())
	}
	now = now.Add(time.Hour)
	if h.remaining() != 10 {
		t.Fatalf("remaining = %d, want 10", h.remaining())
	}
}

func TestWatchRecheckRespectsRequestsPerHour(t *testing.T) {
	l := newStubLab(t)
	a := l.app(t, func(c *config.Config) { c.Watch.MaxRequestsPerHour = 5 })
	_, err := a.recheckChange(context.Background(), watch.Change{})
	if err == nil || !strings.Contains(err.Error(), "incomplete (budget)") {
		t.Fatalf("a recheck cut by the hourly cap must fail loudly, got %v", err)
	}
	if got := l.hits.Load(); got > 5 {
		t.Fatalf("recheck sent %d requests with 5 per hour", got)
	}
	before := l.hits.Load()
	_, err = a.recheckChange(context.Background(), watch.Change{})
	if err == nil || !strings.Contains(err.Error(), "per hour") {
		t.Fatalf("second recheck err = %v", err)
	}
	if l.hits.Load() != before {
		t.Fatal("a recheck past the hourly cap must send nothing")
	}
}
