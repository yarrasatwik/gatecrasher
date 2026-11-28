package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

// slowProvider is a fake Messages API. Reply latency shrinks as the request's
// sequence number grows, so completion order is the reverse of arrival order:
// a client that collected results in completion order would scramble them.
type slowProvider struct {
	url      string
	inflight atomic.Int64
	peak     atomic.Int64
	calls    atomic.Int64
}

func newSlowProvider(t *testing.T, base time.Duration, reply func(user string) string) *slowProvider {
	t.Helper()
	redact.Reset()
	p := &slowProvider{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := p.calls.Add(1)
		cur := p.inflight.Add(1)
		defer p.inflight.Add(-1)
		for {
			old := p.peak.Load()
			if cur <= old || p.peak.CompareAndSwap(old, cur) {
				break
			}
		}
		raw, _ := io.ReadAll(r.Body)
		var req messageRequest
		_ = json.Unmarshal(raw, &req)
		time.Sleep(base * time.Duration(max(1, 12-int(n)))) // later calls finish sooner
		_ = json.NewEncoder(w).Encode(map[string]any{"content": []map[string]string{{"type": "text", "text": reply(req.Messages[0].Content)}}})
	}))
	t.Cleanup(ts.Close)
	p.url = ts.URL + "/v1/messages"
	return p
}

func explainReply(user string) string {
	var in findingInput
	_ = json.Unmarshal([]byte(user), &in)
	o := map[string]string{"title": "T " + in.Subject, "what_happened": "what " + in.Subject, "why_it_matters": "why",
		"business_impact": "impact", "fix_summary": "fix"}
	b, _ := json.Marshal(o)
	return string(b)
}

func findings(n int) []model.Finding {
	out := make([]model.Finding, n)
	for i := range out {
		out[i] = model.Finding{Type: model.FTraitForgery, Subject: fmt.Sprintf("flag_%03d", i), Title: "t", Status: model.StatusExploitable}
	}
	return out
}

func TestExplainAllKeepsOrderAndBoundsConcurrency(t *testing.T) {
	for _, limit := range []int{1, 3, 4} {
		t.Run(fmt.Sprint("limit", limit), func(t *testing.T) {
			p := newSlowProvider(t, 4*time.Millisecond, explainReply)
			c := newClient(testAPIKey, "", p.url)
			c.SetConcurrency(limit)
			fs := findings(12)
			out := c.ExplainAll(context.Background(), fs, func(f model.Finding) bool { return f.Subject == "flag_005" })
			if len(out) != len(fs) {
				t.Fatalf("len = %d, want %d", len(out), len(fs))
			}
			for i, f := range fs {
				switch {
				case f.Subject == "flag_005":
					if out[i] != nil {
						t.Fatalf("skipped finding %d was explained", i)
					}
				case out[i] == nil || out[i].Title != "T "+f.Subject || out[i].Source != "ai":
					t.Fatalf("result %d = %+v, want explanation of %s", i, out[i], f.Subject)
				}
			}
			if got := p.peak.Load(); got > int64(limit) {
				t.Fatalf("peak in-flight = %d, limit %d", got, limit)
			}
			if limit > 1 && p.peak.Load() < 2 {
				t.Fatalf("limit %d never ran two calls at once (peak %d)", limit, p.peak.Load())
			}
		})
	}
}

func TestExplainAllIsDeterministicAcrossRuns(t *testing.T) {
	p := newSlowProvider(t, 2*time.Millisecond, explainReply)
	c := newClient(testAPIKey, "", p.url)
	c.SetConcurrency(4)
	var first []string
	for run := 0; run < 3; run++ {
		var titles []string
		for _, e := range c.ExplainAll(context.Background(), findings(10), nil) {
			titles = append(titles, e.Title)
		}
		if run == 0 {
			first = titles
			continue
		}
		if strings.Join(titles, ",") != strings.Join(first, ",") {
			t.Fatalf("run %d order differs:\n%v\n%v", run, titles, first)
		}
	}
}

func bigInventory(n int) *model.PublicInventory {
	inv := &model.PublicInventory{}
	for i := 0; i < n; i++ {
		inv.Flags = append(inv.Flags, model.FlagView{Name: fmt.Sprintf("harmless_%03d", i), Enabled: true, ValueType: "string", RawValue: "hello", Size: 5})
	}
	return inv
}

// classifyReply labels every even-numbered flag PRICING with confidence 0.9.
func classifyReply(user string) string {
	var in classifyInput
	_ = json.Unmarshal([]byte(user), &in)
	var items []map[string]any
	for _, f := range in.Flags {
		var n int
		_, _ = fmt.Sscanf(f.Name, "harmless_%d", &n)
		cat := "HARMLESS"
		if n%2 == 0 {
			cat = "PRICING"
		}
		items = append(items, map[string]any{"flag": f.Name, "category": cat, "confidence": 0.9, "rationale": "r"})
	}
	b, _ := json.Marshal(map[string]any{"classifications": items})
	return string(b)
}

func TestClassifyRunsBatchesInParallelInInventoryOrder(t *testing.T) {
	p := newSlowProvider(t, 4*time.Millisecond, classifyReply)
	c := newClient(testAPIKey, "", p.url)
	c.SetConcurrency(3)
	inv := bigInventory(4*classifyBatch - 3)
	out, mode := c.Classify(context.Background(), inv)
	if !mode.On() {
		t.Fatalf("mode = %s", mode)
	}
	if len(out) != len(inv.Flags) {
		t.Fatalf("len = %d, want %d", len(out), len(inv.Flags))
	}
	for i, cl := range out {
		if cl.Flag != inv.Flags[i].Name {
			t.Fatalf("out[%d] = %s, want %s", i, cl.Flag, inv.Flags[i].Name)
		}
		want := model.CatHarmless
		if i%2 == 0 {
			want = model.CatPricing
		}
		if cl.Category != want {
			t.Fatalf("out[%d] (%s) = %s, want %s: a batch answer landed on the wrong flag", i, cl.Flag, cl.Category, want)
		}
	}
	if got := p.calls.Load(); got != 4 {
		t.Fatalf("calls = %d, want 4 batches", got)
	}
	if p.peak.Load() > 3 || p.peak.Load() < 2 {
		t.Fatalf("peak in-flight = %d, want 2..3", p.peak.Load())
	}
}

func TestClassifyFallsBackWhenAnyBatchFails(t *testing.T) {
	p := newSlowProvider(t, time.Millisecond, func(string) string { return "not json" })
	c := newClient(testAPIKey, "", p.url)
	c.SetConcurrency(4)
	out, mode := c.Classify(context.Background(), bigInventory(2*classifyBatch))
	if mode.On() || len(out) != 2*classifyBatch {
		t.Fatalf("mode = %s, len = %d: expected the deterministic fallback", mode, len(out))
	}
}

func TestSetConcurrencyDefaultsAndClamps(t *testing.T) {
	c := New("", "")
	if c.Concurrency() != DefaultConcurrency {
		t.Fatalf("default = %d", c.Concurrency())
	}
	c.SetConcurrency(-3)
	if c.Concurrency() != DefaultConcurrency {
		t.Fatalf("non-positive must keep the default, got %d", c.Concurrency())
	}
	c.SetConcurrency(2)
	if c.Concurrency() != 2 {
		t.Fatalf("got %d", c.Concurrency())
	}
}
