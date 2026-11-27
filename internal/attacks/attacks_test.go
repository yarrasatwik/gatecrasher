package attacks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/ai"
	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
	"github.com/yarrasatwik/gatecrasher/internal/httpx"
	"github.com/yarrasatwik/gatecrasher/internal/mapper/testdoc"
	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/scope"
)

type lab struct {
	mu                            sync.Mutex
	engine                        *flagsmith.Engine
	blocked, hide, fail, unstable bool
	posts, gets                   int
	active, peak                  atomic.Int32
	ids                           map[string]bool
}

func fixture(t *testing.T, combo, rollout, variants bool) *lab {
	t.Helper()
	d := testdoc.Doc{APIKey: "test-env", Features: []testdoc.Feature{{Name: "premium", Value: "off"}}}
	conds := []testdoc.Cond{{Property: "plan", Operator: "EQUAL", Value: "gold"}}
	if combo {
		conds = append(conds, testdoc.Cond{Property: "role", Operator: "EQUAL", Value: "staff"})
	}
	d.Segments = []testdoc.Segment{{ID: 1, Name: "gold", Rules: []testdoc.Rule{{Type: "ALL", Conds: conds}}, Overrides: []testdoc.Override{{Feature: "premium", Enabled: true, Value: "on"}}}}
	if rollout {
		d.Features = append(d.Features, testdoc.Feature{Name: "canary"})
		d.Segments = append(d.Segments, testdoc.Segment{ID: 2, Name: "rollout", Rules: []testdoc.Rule{{Type: "ALL", Conds: []testdoc.Cond{{Operator: "PERCENTAGE_SPLIT", Value: "50"}}}}, Overrides: []testdoc.Override{{Feature: "canary", Enabled: true}}})
	}
	if variants {
		d.Features = append(d.Features, testdoc.Feature{Name: "price", Enabled: true, Value: "standard", MV: []testdoc.MV{{ID: 1, Value: "low", Percent: 50}, {ID: 2, Value: "high", Percent: 50}}})
	}
	eng, err := flagsmith.NewEngine(d.JSON())
	if err != nil {
		t.Fatal(err)
	}
	return &lab{engine: eng, ids: map[string]bool{}}
}
func (l *lab) sdk(t *testing.T) *flagsmith.SDK {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		active := l.active.Add(1)
		for peak := l.peak.Load(); active > peak; peak = l.peak.Load() {
			if l.peak.CompareAndSwap(peak, active) {
				break
			}
		}
		defer l.active.Add(-1)
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.fail {
			http.Error(w, "private-response", 500)
			return
		}
		var id string
		traits := map[string]string{}
		returned := []flagsmith.Trait{}
		switch {
		case r.URL.Path == "/flags/":
		case r.Method == "GET":
			id = r.URL.Query().Get("identifier")
			l.gets++
			if id != "approved@example.test" {
				t.Errorf("unapproved lookup %q", id)
			}
			if !l.hide {
				returned = append(returned, flagsmith.Trait{Key: "private", Value: "private-value"})
			}
			traits["plan"] = "gold"
		default:
			var b struct {
				Identifier string            `json:"identifier"`
				Transient  bool              `json:"transient"`
				Traits     []flagsmith.Trait `json:"traits"`
			}
			if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
				t.Error(err)
			}
			if !b.Transient || !strings.HasPrefix(b.Identifier, "gc-probe-") {
				t.Error("non-transient probe")
			}
			id = b.Identifier
			l.ids[id] = true
			l.posts++
			for _, tr := range b.Traits {
				if !tr.Transient {
					t.Error("non-transient trait")
				}
				if !l.blocked {
					traits[tr.Key] = flagsmith.ValueString(tr.Value)
				}
			}
			if l.unstable && len(l.ids)%2 == 0 {
				traits = nil
			}
		}
		flags := l.engine.Evaluate(id, traits)
		if r.URL.Path == "/flags/" {
			flags = l.engine.EvaluateEnvironment()
		}
		raw := []any{}
		for _, name := range flags.Names() {
			f := flags[name]
			reason := f.Reason
			if r.Method == "GET" && r.URL.Path != "/flags/" && name == "premium" {
				reason = "IDENTITY_OVERRIDE"
			}
			raw = append(raw, map[string]any{"feature": map[string]any{"name": name}, "enabled": f.Enabled, "feature_state_value": f.Value, "reason": reason})
		}
		if r.URL.Path == "/flags/" {
			_ = json.NewEncoder(w).Encode(raw)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"identifier": id, "traits": returned, "flags": raw})
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return flagsmith.NewSDK(httpx.New(scope.MustNew(nil, []string{u.Host}), httpx.WithRetries(0)), srv.URL+"/", "client-test-key")
}

func TestTraitForgery(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		combo, blocked, unstable bool
		maxCombos, want          int
	}{
		{name: "single", want: 1, maxCombos: -1}, {name: "blocked", blocked: true, maxCombos: -1},
		{name: "needs combination", combo: true, maxCombos: 1, want: 1}, {name: "combinations disabled", combo: true, maxCombos: -1},
		{name: "second fresh identity disagrees", unstable: true, maxCombos: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := fixture(t, tc.combo, false, false)
			l.blocked = tc.blocked
			l.unstable = tc.unstable
			runner := New(l.sdk(t), Options{MaxCombos: tc.maxCombos, RerollSamples: -1})
			hs := []ai.Hypothesis{{TraitKey: "plan", TraitValue: "gold"}, {TraitKey: "role", TraitValue: "staff"}}
			fs, err := runner.Run(context.Background(), l.engine.EvaluateEnvironment(), hs)
			if err != nil {
				t.Fatal(err)
			}
			if len(fs) != tc.want {
				t.Fatalf("got %d findings: %+v", len(fs), fs)
			}
			if len(fs) > 0 {
				f := fs[0]
				if f.Type != model.FTraitForgery || len(f.Evidence) != 2 || !strings.Contains(f.Repro, "<CLIENT_KEY>") {
					t.Fatalf("bad evidence %+v", f)
				}
				st, _, err := runner.Recheck(context.Background(), f)
				if err != nil || st != model.StatusExploitable {
					t.Fatalf("recheck %s %v", st, err)
				}
				l.blocked = true
				st, _, err = runner.Recheck(context.Background(), f)
				if err != nil || st != model.StatusBlocked {
					t.Fatalf("fixed recheck %s %v", st, err)
				}
			}
			if l.peak.Load() > 8 {
				t.Fatalf("too many concurrent requests: %d", l.peak.Load())
			}
		})
	}
}

func TestIdentityLeaksAndRecheck(t *testing.T) {
	for _, hidden := range []bool{false, true} {
		t.Run(map[bool]string{false: "visible", true: "hidden"}[hidden], func(t *testing.T) {
			l := fixture(t, false, false, false)
			l.hide = hidden
			runner := New(l.sdk(t), Options{TestIdentities: []string{"approved@example.test"}, RerollSamples: -1})
			fs, err := runner.Run(context.Background(), l.engine.EvaluateEnvironment(), nil)
			if err != nil {
				t.Fatal(err)
			}
			want := 2
			if hidden {
				want = 1
			}
			if len(fs) != want {
				t.Fatalf("got %+v", fs)
			}
			raw, _ := json.Marshal(fs)
			for _, secret := range []string{"private-value", "approved@example.test"} {
				if strings.Contains(string(raw), secret) {
					t.Fatalf("leaked %s", secret)
				}
			}
			for _, f := range fs {
				st, _, err := runner.Recheck(context.Background(), f)
				if err != nil || st != model.StatusExploitable {
					t.Fatalf("recheck %s %v", st, err)
				}
			}
			denied := New(runner.sdk, Options{})
			st, _, err := denied.Recheck(context.Background(), fs[0])
			if err == nil || st != model.StatusUnknown {
				t.Fatal("unapproved recheck accepted")
			}
		})
	}
}

func TestRerolls(t *testing.T) {
	for _, clientIDs := range []bool{false, true} {
		t.Run(map[bool]string{false: "server IDs", true: "client IDs"}[clientIDs], func(t *testing.T) {
			l := fixture(t, false, true, true)
			runner := New(l.sdk(t), Options{ClientSetsIdentifier: clientIDs, RerollSamples: 200})
			fs, err := runner.Run(context.Background(), l.engine.EvaluateEnvironment(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if !clientIDs {
				if len(fs) != 0 || l.posts != 0 {
					t.Fatal("server IDs rerolled")
				}
				return
			}
			types := map[model.FindingType]bool{}
			for _, f := range fs {
				types[f.Type] = true
				if f.HitRate <= 0 || f.HitRate >= 1 || f.Attempts != 1/f.HitRate || f.ProofID == "" {
					t.Fatalf("invalid statistics %+v", f)
				}
				st, _, err := runner.Recheck(context.Background(), f)
				if err != nil || st != model.StatusExploitable {
					t.Fatalf("reroll recheck: %s %v", st, err)
				}
			}
			if !types[model.FPercentageReroll] || !types[model.FVariantReroll] {
				t.Fatalf("missing rerolls %+v", fs)
			}
		})
	}
}

func TestFailuresAndBounds(t *testing.T) {
	l := fixture(t, false, false, false)
	sdk := l.sdk(t)
	runner := New(sdk, Options{MaxCombos: 10000, RerollSamples: 10000, MaxHypotheses: 10000})
	if runner.opts.MaxCombos != 24 || runner.opts.RerollSamples != 500 || runner.opts.MaxHypotheses != 40 {
		t.Fatal("unbounded work")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runner.Run(ctx, l.engine.EvaluateEnvironment(), []ai.Hypothesis{{TraitKey: "plan", TraitValue: "gold"}}); err == nil {
		t.Fatal("cancellation ignored")
	}
	l.fail = true
	st, proof, err := runner.Recheck(context.Background(), model.Finding{Type: model.FIdentityTraitLeak, ProofID: identityToken("approved@example.test")})
	if st != model.StatusUnknown || err == nil || strings.Contains(proof, "private-response") {
		t.Fatal("failure treated as blocked")
	}
}

func TestExperimentAndStableIDs(t *testing.T) {
	for _, known := range []bool{false, true} {
		t.Run(map[bool]string{false: "unknown experiment", true: "running experiment"}[known], func(t *testing.T) {
			l := fixture(t, false, false, false)
			opts := Options{MaxCombos: -1, RerollSamples: -1}
			if known {
				opts.RunningExperiments = map[string]bool{"premium": true}
			}
			runner := New(l.sdk(t), opts)
			hs := []ai.Hypothesis{{TraitKey: "plan", TraitValue: "gold"}}
			first, err := runner.Run(context.Background(), l.engine.EvaluateEnvironment(), hs)
			if err != nil || len(first) != 1 {
				t.Fatalf("findings=%v error=%v", first, err)
			}
			second, err := runner.Run(context.Background(), l.engine.EvaluateEnvironment(), hs)
			if err != nil || len(second) != 1 {
				t.Fatal(err)
			}
			if first[0].ID != second[0].ID || first[0].ProofID == second[0].ProofID {
				t.Fatal("IDs must be stable while probes must be fresh")
			}
			if known && first[0].Type != model.FExperimentRigging {
				t.Fatal("running experiment was not escalated")
			}
			if !known && !strings.Contains(strings.Join(first[0].Notes, " "), "experiment status unknown") {
				t.Fatal("unknown experiment omitted")
			}
		})
	}
}

func TestScopeRefusal(t *testing.T) {
	sdk := flagsmith.NewSDK(httpx.New(scope.MustNew(nil, []string{"localhost"}), httpx.WithRetries(0)), "http://out-of-scope.invalid/", "test-key")
	runner := New(sdk, Options{RerollSamples: -1})
	fs, err := runner.Run(context.Background(), flagsmith.Flags{}, []ai.Hypothesis{{TraitKey: "plan", TraitValue: "gold"}})
	if err == nil || len(fs) != 0 {
		t.Fatal("out of scope request accepted")
	}
}
