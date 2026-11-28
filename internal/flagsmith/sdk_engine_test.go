package flagsmith_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
	"github.com/yarrasatwik/gatecrasher/internal/httpx"
)

func TestSDKEnvironmentFlags(t *testing.T) {
	var key string
	c, api := serve(t, 0, func(w http.ResponseWriter, r *http.Request) {
		key = r.Header.Get("X-Environment-Key")
		if r.URL.Path != "/api/v1/flags/" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(fixture(t, "flags_client"))
	})
	s := flagsmith.NewSDK(c, api, "client-key-1")
	if s.APIURL() != api {
		t.Fatalf("APIURL = %q", s.APIURL())
	}
	flags, ev, err := s.EnvironmentFlags(bg())
	if err != nil {
		t.Fatal(err)
	}
	if key != "client-key-1" || len(flags) != 11 {
		t.Fatalf("key=%q flags=%d", key, len(flags))
	}
	if f := flags["pricing_page"]; !f.Enabled || f.State() != "on: price_high" || f.FeatureID == 0 || f.Type == "" {
		t.Fatalf("pricing_page = %+v", f)
	}
	if flags["premium_export"].State() != "off" {
		t.Fatalf("premium_export = %+v", flags["premium_export"])
	}
	if ev.Kind != "request" || !strings.Contains(ev.Request, "curl -s 'http") || strings.Contains(ev.Request, "client-key-1") ||
		!strings.HasPrefix(ev.Response, "HTTP 200") {
		t.Fatalf("evidence = %+v", ev)
	}
}

func TestSDKEnvironmentFlagsErrors(t *testing.T) {
	c, api := serve(t, 0, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"detail":"Invalid or missing Environment Key"}`)
	})
	flags, ev, err := flagsmith.NewSDK(c, api, "bad-client-key").EnvironmentFlags(bg())
	var se *httpx.StatusError
	if !errors.As(err, &se) || se.Status != 401 || flags != nil {
		t.Fatalf("err = %v", err)
	}
	if !strings.HasPrefix(ev.Response, "HTTP 401") {
		t.Fatalf("evidence = %+v", ev)
	}

	// Transport-level failure leaves the evidence response empty.
	c2, _ := serve(t, 0, func(w http.ResponseWriter, r *http.Request) {})
	_, ev, err = flagsmith.NewSDK(c2, "http://127.0.0.1:1/api/v1/", "k").EnvironmentFlags(bg())
	if err == nil || ev.Response != "" {
		t.Fatalf("expected scope error, ev=%+v err=%v", ev, err)
	}
}

func TestSDKIdentifyTransient(t *testing.T) {
	var got map[string]any
	c, api := serve(t, 0, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/identities/" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write(fixture(t, "identity_probe_transient"))
	})
	s := flagsmith.NewSDK(c, api, "client-key-2")
	res, err := s.Identify(bg(), "gc-probe-fixture-1", map[string]string{"plan": "gold", "a": "b"})
	if err != nil {
		t.Fatal(err)
	}
	if got["transient"] != true || got["identifier"] != "gc-probe-fixture-1" {
		t.Fatalf("body = %+v", got)
	}
	traits := got["traits"].([]any)
	if len(traits) != 2 || traits[0].(map[string]any)["trait_key"] != "a" || traits[1].(map[string]any)["transient"] != true {
		t.Fatalf("traits sorted/transient = %+v", traits)
	}
	if res.Identifier != "gc-probe-fixture-1" || len(res.Traits) != 1 || res.Traits[0].Key != "plan" || len(res.Flags) == 0 {
		t.Fatalf("result = %+v", res)
	}
	if !strings.Contains(res.Evidence.Request, "-X POST") || !strings.Contains(res.Evidence.Request, "-d '") || strings.Contains(res.Evidence.Request, "client-key-2") {
		t.Fatalf("evidence request = %q", res.Evidence.Request)
	}
}

func TestSDKIdentifyRefusesPersistentIdentifiers(t *testing.T) {
	c, api := serve(t, 0, func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request must be sent for a non-probe identifier")
	})
	if _, err := flagsmith.NewSDK(c, api, "k").Identify(bg(), "ceo@acmeshop.dev", nil); err == nil ||
		!strings.Contains(err.Error(), "gc-probe-") {
		t.Fatalf("err = %v", err)
	}
}

func TestSDKIdentifyErrorAndRetry(t *testing.T) {
	// POST identities is marked idempotent: a 503 is retried.
	calls := 0
	c, api := serve(t, 2, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(fixture(t, "identity_probe_not_persisted"))
	})
	res, err := flagsmith.NewSDK(c, api, "k-id").Identify(bg(), "gc-probe-x", nil)
	if err != nil || calls != 2 || res == nil {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
	c2, api2 := serve(t, 0, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) })
	if _, err := flagsmith.NewSDK(c2, api2, "k-id").Identify(bg(), "gc-probe-x", nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestSDKLookupIdentity(t *testing.T) {
	var q string
	c, api := serve(t, 0, func(w http.ResponseWriter, r *http.Request) {
		q = r.URL.RawQuery
		_, _ = w.Write(fixture(t, "identity_lookup_ceo"))
	})
	s := flagsmith.NewSDK(c, api, "k-lookup")
	res, err := s.LookupIdentity(bg(), "ceo@acmeshop.dev")
	if err != nil {
		t.Fatal(err)
	}
	if q != "identifier=ceo%40acmeshop.dev" || res.Identifier != "ceo@acmeshop.dev" || len(res.Traits) != 3 {
		t.Fatalf("q=%q res=%+v", q, res)
	}
	if v := flagsmith.ValueString(res.Traits[0].Value); v != "48200" {
		t.Fatalf("trait value = %q", v)
	}
	c2, api2 := serve(t, 0, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) })
	if _, err := flagsmith.NewSDK(c2, api2, "k-lookup").LookupIdentity(bg(), "x"); err == nil {
		t.Fatal("expected error")
	}
}

func TestFlagHelpers(t *testing.T) {
	for _, c := range []struct {
		v    any
		want string
	}{
		{nil, ""}, {"x", "x"}, {float64(3), "3"}, {1.5, "1.5"}, {true, "true"}, {false, "false"},
		{map[string]any{"a": 1}, `{"a":1}`},
	} {
		if got := flagsmith.ValueString(c.v); got != c.want {
			t.Errorf("ValueString(%v) = %q want %q", c.v, got, c.want)
		}
	}
	base := flagsmith.Flags{
		"a": {Name: "a"}, "b": {Name: "b", Enabled: true, Value: "x"}, "same": {Name: "same", Enabled: true},
	}
	probe := flagsmith.Flags{
		"a": {Name: "a", Enabled: true}, "b": {Name: "b", Enabled: true, Value: "x"}, "same": {Name: "same", Enabled: true},
		"new": {Name: "new", Enabled: true, Value: float64(2)},
	}
	if got := probe.Names(); strings.Join(got, ",") != "a,b,new,same" {
		t.Fatalf("names = %v", got)
	}
	diff := flagsmith.Diff(base, probe)
	if len(diff) != 2 || diff[0].Flag != "a" || diff[0].Before != "off" || diff[0].After != "on" ||
		diff[1].Flag != "new" || diff[1].Before != "off" || diff[1].After != "on: 2" {
		t.Fatalf("diff = %+v", diff)
	}
	if r := flagsmith.Repro("GET", "http://x/flags/", nil); strings.Contains(r, "-X") || !strings.Contains(r, "<CLIENT_KEY>") {
		t.Fatalf("repro = %q", r)
	}
}

func engineFromFixture(t *testing.T) *flagsmith.Engine {
	t.Helper()
	e, err := flagsmith.NewEngine(fixture(t, "environment_document"))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestEngineEvaluatesEnvironmentDocument(t *testing.T) {
	e := engineFromFixture(t)
	if e.Doc.APIKey == "" || !strings.Contains(flagsmith.EngineVersion, "flagsmith-go-client") {
		t.Fatalf("doc/version: %q %q", e.Doc.APIKey, flagsmith.EngineVersion)
	}

	env := e.EvaluateEnvironment()
	if len(env) != 11 {
		t.Fatalf("environment flags = %d (%v)", len(env), env.Names())
	}
	if env["premium_export"].Enabled || env["maintenance_mode"].Enabled {
		t.Fatal("default-off flags must be off with no identity")
	}
	if env["banner_text"].State() != "on: Free shipping over $50" {
		t.Fatalf("banner_text = %q", env["banner_text"].State())
	}
	if got := env["internal_api_url"].State(); got != "on: http://10.0.3.7:8080/admin" {
		t.Fatalf("internal_api_url = %q", got)
	}

	// Segment overrides driven by traits.
	gold := e.Evaluate("gc-probe-a", map[string]string{"plan": "gold"})
	if !gold["premium_export"].Enabled || gold["premium_export"].Reason == "" {
		t.Fatalf("gold plan should unlock premium_export: %+v", gold["premium_export"])
	}
	if gold["admin_panel"].Enabled {
		t.Fatal("plan=gold must not unlock admin_panel")
	}
	admin := e.Evaluate("gc-probe-a", map[string]string{"role": "admin"})
	if !admin["admin_panel"].Enabled || admin["premium_export"].Enabled {
		t.Fatalf("role=admin: %+v", admin["admin_panel"])
	}
	staff := e.Evaluate("gc-probe-a", map[string]string{"email": "x@acmeshop.dev"})
	if !staff["staff_preview"].Enabled {
		t.Fatal("staff email should unlock staff_preview")
	}
	if other := e.Evaluate("gc-probe-a", map[string]string{"email": "x@evil.example"}); other["staff_preview"].Enabled {
		t.Fatal("non-staff email must not unlock staff_preview")
	}

	// The diff between base and forged traits is exactly the forged unlock.
	d := flagsmith.Diff(e.Evaluate("gc-probe-a", nil), gold)
	if len(d) == 0 || d[0].Flag != "premium_export" || d[0].After != "on" {
		t.Fatalf("diff = %+v", d)
	}

	// Determinism for a given identity.
	a := e.Evaluate("gc-probe-same", map[string]string{"plan": "gold"})
	b := e.Evaluate("gc-probe-same", map[string]string{"plan": "gold"})
	for n, f := range a {
		if b[n].State() != f.State() {
			t.Fatalf("non-deterministic %s", n)
		}
	}
}

func TestEngineMultivariateAndPercentageSplit(t *testing.T) {
	e := engineFromFixture(t)
	seen := map[string]int{}
	canary := 0
	const n = 400
	for i := 0; i < n; i++ {
		fl := e.Evaluate("gc-probe-"+strings.Repeat("z", i%7)+string(rune('a'+i%26))+string(rune('A'+i/26)), nil)
		seen[fl["pricing_page"].State()]++
		if fl["early_access_ai"].Enabled {
			canary++
		}
	}
	if len(seen) < 2 {
		t.Fatalf("multivariate flag should spread over variants, got %v", seen)
	}
	if canary == 0 || canary > n/2 {
		t.Fatalf("10%% canary hit %d of %d", canary, n)
	}
}

func TestNewEngineRejectsGarbage(t *testing.T) {
	if _, err := flagsmith.NewEngine(json.RawMessage(`{"feature_states": "no"}`)); err == nil ||
		!strings.Contains(err.Error(), "parse environment document") {
		t.Fatalf("err = %v", err)
	}
}
