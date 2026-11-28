package attacks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/ai"
	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
	"github.com/yarrasatwik/gatecrasher/internal/httpx"
	"github.com/yarrasatwik/gatecrasher/internal/scope"
)

// With a server that never changes a flag, Run sends exactly what
// EstimateRequests predicts.
func TestEstimateRequestsMatchesRunWhenNothingChangesAFlag(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"identifier":"gc-probe-x","traits":[],"flags":[]}`))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	sdk := flagsmith.NewSDK(httpx.New(scope.MustNew(nil, []string{u.Host})), srv.URL+"/api/v1/", "ENVKEYabcdefghijklmnopqr")

	hyp := ai.HeuristicHypotheses([]string{"plan", "beta"}, "shop.example.com")
	opts := Options{MaxCombos: 10, RerollSamples: 30, ClientSetsIdentifier: true, TestIdentities: []string{"a@example.test", "b@example.test"}}
	want := EstimateRequests(opts, hyp)
	if want.Sets <= len(hyp) || want.Reroll != 30 || want.Lookups != 2 || want.Total() != want.Pairs+30+2 {
		t.Fatalf("estimate = %+v for %d hypotheses", want, len(hyp))
	}
	if _, err := New(sdk, opts).Run(context.Background(), flagsmith.Flags{}, hyp); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != int64(want.Total()) {
		t.Fatalf("Run sent %d requests, estimate said %d", hits.Load(), want.Total())
	}
}

func TestEstimateRequestsHonoursDisabledFamilies(t *testing.T) {
	hyp := ai.HeuristicHypotheses(nil, "shop.example.com")
	e := EstimateRequests(Options{MaxHypotheses: -1, RerollSamples: -1, ClientSetsIdentifier: true}, hyp)
	if e.Total() != 0 {
		t.Fatalf("estimate = %+v, want nothing", e)
	}
	e = EstimateRequests(Options{RerollSamples: 100, ClientSetsIdentifier: false, MaxHypotheses: -1}, hyp)
	if e.Reroll != 0 {
		t.Fatalf("re-roll counted although the client cannot choose its identifier: %+v", e)
	}
}
