package parity_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
	"github.com/yarrasatwik/gatecrasher/internal/httpx"
	"github.com/yarrasatwik/gatecrasher/internal/mapper/testdoc"
	"github.com/yarrasatwik/gatecrasher/internal/parity"
	"github.com/yarrasatwik/gatecrasher/internal/scope"
)

func fixture() (testdoc.Doc, []flagsmith.Segment) {
	cond := func(p, op, v string) testdoc.Rule {
		return testdoc.Rule{Type: "ALL", Rules: []testdoc.Rule{{Type: "ALL", Conds: []testdoc.Cond{{Property: p, Operator: op, Value: v}}}}}
	}
	d := testdoc.Doc{
		APIKey: "envkey",
		Features: []testdoc.Feature{
			{Name: "premium", Enabled: false, Value: "off"},
			{Name: "limit", Enabled: true, Value: 10},
		},
		Segments: []testdoc.Segment{
			{ID: 1, Name: "gold", Rules: []testdoc.Rule{cond("plan", "IN", "gold,platinum")},
				Overrides: []testdoc.Override{{Feature: "premium", Enabled: true, Value: "on"}}},
			{ID: 2, Name: "staff", Rules: []testdoc.Rule{cond("email", "REGEX", `.*@acmeshop\.dev$`)},
				Overrides: []testdoc.Override{{Feature: "limit", Enabled: true, Value: 1000}}},
			{ID: 3, Name: "rollout", Rules: []testdoc.Rule{cond("", "PERCENTAGE_SPLIT", "30")},
				Overrides: []testdoc.Override{{Feature: "premium", Enabled: true, Value: "canary"}}},
		},
	}
	return d, d.AdminSegments()
}

// stubSDK serves POST identities/ from the given engine; tamper may alter the
// flags before they are returned.
func stubSDK(t *testing.T, eng *flagsmith.Engine, tamper func(id string, flags flagsmith.Flags)) *flagsmith.SDK {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Identifier string `json:"identifier"`
			Traits     []struct {
				Key   string `json:"trait_key"`
				Value string `json:"trait_value"`
			} `json:"traits"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || r.Method != http.MethodPost {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		traits := map[string]string{}
		for _, tr := range body.Traits {
			traits[tr.Key] = tr.Value
		}
		flags := eng.Evaluate(body.Identifier, traits)
		if tamper != nil {
			tamper(body.Identifier, flags)
		}
		var out []map[string]any
		for _, name := range flags.Names() {
			f := flags[name]
			out = append(out, map[string]any{"feature": map[string]any{"name": name}, "enabled": f.Enabled, "feature_state_value": f.Value, "reason": f.Reason})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"identifier": body.Identifier, "traits": []any{}, "flags": out})
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	client := httpx.New(scope.MustNew(nil, []string{u.Host}), httpx.WithRetries(0))
	return flagsmith.NewSDK(client, srv.URL+"/api/v1/", "client-key")
}

func TestRunAgreesWithFaithfulLive(t *testing.T) {
	d, segs := fixture()
	eng, err := flagsmith.NewEngine(d.JSON())
	if err != nil {
		t.Fatal(err)
	}
	res, err := parity.Run(context.Background(), eng, stubSDK(t, eng, nil), 300, segs)
	if err != nil {
		t.Fatal(err)
	}
	if res.Checked != 300 || res.Agreed != 300 || res.Errors != 0 || len(res.Mismatches) != 0 {
		t.Fatalf("want 300/300 agreement, got %+v", res)
	}
}

func TestRunReportsMismatches(t *testing.T) {
	d, segs := fixture()
	eng, _ := flagsmith.NewEngine(d.JSON())
	tamper := func(_ string, flags flagsmith.Flags) {
		f := flags["premium"]
		if f.Value == "on" {
			f.Value = "off"
			flags["premium"] = f
		}
	}
	res, err := parity.Run(context.Background(), eng, stubSDK(t, eng, tamper), 300, segs)
	if err != nil {
		t.Fatal(err)
	}
	if res.Checked != 300 || res.Agreed >= 300 || len(res.Mismatches) == 0 {
		t.Fatalf("tampered live API must produce mismatches: %+v", res)
	}
	m := res.Mismatches[0]
	if m.Flag != "premium" || m.Engine != "on:on" || m.Live != "on:off" {
		t.Errorf("mismatch detail: %+v", m)
	}
}

func TestRunCountsLiveErrorsSeparately(t *testing.T) {
	d, segs := fixture()
	eng, _ := flagsmith.NewEngine(d.JSON())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", http.StatusBadRequest) }))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	sdk := flagsmith.NewSDK(httpx.New(scope.MustNew(nil, []string{u.Host}), httpx.WithRetries(0)), srv.URL+"/api/v1/", "k")
	res, err := parity.Run(context.Background(), eng, sdk, 20, segs)
	if err != nil {
		t.Fatal(err)
	}
	if res.Errors != 20 || res.Checked != 0 || res.Agreed != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestRunStopsWhenCancelled(t *testing.T) {
	d, segs := fixture()
	eng, _ := flagsmith.NewEngine(d.JSON())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := parity.Run(ctx, eng, stubSDK(t, eng, nil), 50, segs)
	if err == nil || res.Checked == 50 {
		t.Fatalf("cancelled run should stop early: %+v err=%v", res, err)
	}
}
