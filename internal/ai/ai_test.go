package ai

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
	"github.com/yarrasatwik/gatecrasher/internal/scope"
)

const (
	testAPIKey    = "sk-ant-test-0123456789abcdef"
	labSecret     = "acme_live_0123456789abcdef0123456789abcdef"
	entropySecret = "q8Zx3Lk9PwR2tYv7NmB4cJd1"
	clientKey     = "AbCd3fGhJk5mNpQr7StUvW"
)

// stubAnthropic replays canned text replies and records every request.
type stubAnthropic struct {
	mu      sync.Mutex
	replies []string
	bodies  []string
	headers []http.Header
	url     string
}

func newStubAnthropic(t *testing.T, replies ...string) *stubAnthropic {
	t.Helper()
	redact.Reset()
	f := &stubAnthropic{replies: replies}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		i := len(f.bodies)
		f.bodies = append(f.bodies, string(b))
		f.headers = append(f.headers, r.Header.Clone())
		reply := f.replies[min(i, len(f.replies)-1)]
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"content": []map[string]string{{"type": "text", "text": reply}}})
	}))
	t.Cleanup(ts.Close)
	f.url = ts.URL + "/v1/messages"
	return f
}

func (f *stubAnthropic) client() *Client { return newClient(testAPIKey, "", f.url) }

func (f *stubAnthropic) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.bodies)
}

func inventory() *model.PublicInventory {
	return &model.PublicInventory{Flags: []model.FlagView{
		{Name: "payment_config", Enabled: true, ValueType: "json", RawValue: `{"provider":"acmepay","api_secret":"` + labSecret + `","webhook":"https://internal.acmeshop.dev/pay"}`},
		{Name: "banner_text", Enabled: true, ValueType: "string", RawValue: "Free shipping over $50"},
		{Name: "maintenance_mode", ValueType: "null"},
		{Name: "support_note", Enabled: true, ValueType: "string", RawValue: "token " + entropySecret + " do not share"},
		{Name: "partner_portal", Enabled: true, ValueType: "string", RawValue: "see our partner docs"},
	}}
}

func byFlag(cs []model.Classification) map[string]model.Classification {
	m := map[string]model.Classification{}
	for _, c := range cs {
		m[c.Flag] = c
	}
	return m
}

func TestModeStrings(t *testing.T) {
	if got := New("", "").Mode(); got != ModeOff || got.On() {
		t.Fatalf("mode = %q", got)
	}
	var nilClient *Client
	if nilClient.Mode() != ModeOff {
		t.Fatal("nil client must be off")
	}
	if got := New(testAPIKey, "").Mode(); got != "on (claude-sonnet-5-5)" || !got.On() {
		t.Fatalf("mode = %q", got)
	}
	if got := New(testAPIKey, "claude-x").Mode(); got != "on (claude-x)" {
		t.Fatalf("mode = %q", got)
	}
}

func TestAIOffClassifyUsesDeterministicPass(t *testing.T) {
	cs, mode := New("", "").Classify(context.Background(), inventory())
	if mode != ModeOff || len(cs) != 5 {
		t.Fatalf("mode=%q n=%d", mode, len(cs))
	}
	m := byFlag(cs)
	if m["payment_config"].Category != model.CatSecret || m["payment_config"].Method != model.MethodDeterministic {
		t.Fatalf("payment_config = %+v", m["payment_config"])
	}
	for _, n := range []string{"banner_text", "maintenance_mode"} {
		if m[n].Category != model.CatHarmless {
			t.Errorf("%s = %s, want HARMLESS", n, m[n].Category)
		}
	}
}

func TestClassifyAIFencedJSONAndMerge(t *testing.T) {
	reply := "Here you go:\n```json\n" + `{"classifications":[
	 {"flag":"payment_config","category":"HARMLESS","confidence":0.99,"rationale":"looks fine"},
	 {"flag":"banner_text","category":"PRICING","confidence":0.4,"rationale":"mentions $50"},
	 {"flag":"partner_portal","category":"INTERNAL_URL","confidence":0.8,"rationale":"partner portal reference"}
	]}` + "\n```"
	f := newStubAnthropic(t, reply)
	cs, mode := f.client().Classify(context.Background(), inventory())
	if mode != "on (claude-sonnet-5-5)" {
		t.Fatalf("mode = %q", mode)
	}
	m := byFlag(cs)
	if m["payment_config"].Category != model.CatSecret || m["payment_config"].Method != model.MethodDeterministic {
		t.Fatalf("deterministic finding must win over AI HARMLESS: %+v", m["payment_config"])
	}
	if m["banner_text"].Category != model.CatHarmless {
		t.Fatalf("low-confidence AI must not create a finding: %+v", m["banner_text"])
	}
	if p := m["partner_portal"]; p.Category != model.CatInternalURL || p.Method != model.MethodAI {
		t.Fatalf("confident AI finding missing: %+v", p)
	}
	if f.count() != 1 {
		t.Fatalf("requests = %d", f.count())
	}
}

func TestRequestShapeNoTools(t *testing.T) {
	f := newStubAnthropic(t, `{"classifications":[]}`)
	f.client().Classify(context.Background(), inventory())
	h := f.headers[0]
	if h.Get("X-Api-Key") != testAPIKey || h.Get("Anthropic-Version") != "2023-06-01" {
		t.Fatalf("headers = %v", h)
	}
	var req map[string]any
	if err := json.Unmarshal([]byte(f.bodies[0]), &req); err != nil {
		t.Fatal(err)
	}
	if req["model"] != "claude-sonnet-5-5" || req["temperature"] != float64(0) {
		t.Fatalf("model/temperature = %v/%v", req["model"], req["temperature"])
	}
	for _, banned := range []string{"tools", "tool_choice", "mcp_servers"} {
		if _, ok := req[banned]; ok {
			t.Fatalf("request must not contain %q", banned)
		}
	}
	if !strings.Contains(req["system"].(string), "Return ONLY JSON matching this schema. No prose.") {
		t.Fatal("system prompt lacks the JSON-only instruction")
	}
}

func TestInvalidThenValidRetriesOnce(t *testing.T) {
	good := `{"classifications":[{"flag":"partner_portal","category":"INTERNAL_URL","confidence":0.9,"rationale":"x"}]}`
	f := newStubAnthropic(t, "I think this is fine.", good)
	cs, mode := f.client().Classify(context.Background(), inventory())
	if f.count() != 2 || !mode.On() {
		t.Fatalf("requests=%d mode=%q", f.count(), mode)
	}
	if byFlag(cs)["partner_portal"].Method != model.MethodAI {
		t.Fatal("retried reply not used")
	}
	if !strings.Contains(f.bodies[1], "previous reply was rejected") {
		t.Fatal("retry must carry the correction")
	}
}

func TestInvalidTwiceFallsBackWithLabel(t *testing.T) {
	tests := map[string]string{
		"not json":         "nope",
		"bad category":     `{"classifications":[{"flag":"banner_text","category":"BOGUS","confidence":0.9,"rationale":"x"}]}`,
		"confidence range": `{"classifications":[{"flag":"banner_text","category":"PII","confidence":1.5,"rationale":"x"}]}`,
		"unknown flag":     `{"classifications":[{"flag":"nope","category":"PII","confidence":0.9,"rationale":"x"}]}`,
	}
	for name, reply := range tests {
		t.Run(name, func(t *testing.T) {
			f := newStubAnthropic(t, reply)
			cs, mode := f.client().Classify(context.Background(), inventory())
			if f.count() != 2 {
				t.Fatalf("requests = %d, want exactly one retry", f.count())
			}
			if mode.On() || !strings.Contains(string(mode), "AI fallback") {
				t.Fatalf("mode = %q", mode)
			}
			if byFlag(cs)["payment_config"].Method != model.MethodDeterministic {
				t.Fatal("fallback must use the deterministic pass")
			}
		})
	}
}

func TestHTTPErrorFallsBack(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"bad key"}`, http.StatusUnauthorized)
	}))
	defer ts.Close()
	_, mode := newClient(testAPIKey, "", ts.URL+"/v1/messages").Classify(context.Background(), inventory())
	if mode.On() || !strings.Contains(string(mode), "request failed") {
		t.Fatalf("mode = %q", mode)
	}
}

func TestNoRawSecretReachesPrompt(t *testing.T) {
	f := newStubAnthropic(t, `{"classifications":[]}`, `{"hypotheses":[{"trait_key":"plan","trait_value":"gold","why":"x"}]}`,
		`{"title":"t","what_happened":"w","why_it_matters":"y","business_impact":"b","fix_summary":"f"}`,
		`{"title":"t","body":"b","diff":""}`)
	c := f.client()
	redact.Register(clientKey, "CLIENT_KEY")
	inv := inventory()
	inv.Key = clientKey
	c.Classify(context.Background(), inv)
	c.Hypothesize(context.Background(), []string{"premium_export"}, []string{"plan"}, "acmeshop.dev")
	finding := model.Finding{
		ID: "GC-1", Type: model.FSecretExposed, Subject: "payment_config", Title: "Secret in payment_config",
		Evidence: []model.Evidence{{Kind: "request", Request: "curl -H 'X-Environment-Key: " + clientKey + "'", Response: `{"api_secret":"` + labSecret + `"}`}},
		Unlocked: []model.FlagChange{{Flag: "payment_config", Before: "off:", After: "on:" + labSecret}},
	}
	c.Explain(context.Background(), finding)
	c.FixPR(context.Background(), finding, []model.ImpactItem{{File: "app.js", Line: 3, Snippet: `const k = "` + labSecret + `"`, Message: "uses " + entropySecret}})

	if f.count() != 4 {
		t.Fatalf("requests = %d, want 4", f.count())
	}
	for i, body := range f.bodies {
		for _, raw := range []string{labSecret, entropySecret, clientKey, testAPIKey, "0123456789abcdef0123456789abcdef"} {
			if strings.Contains(body, raw) {
				t.Fatalf("request %d contains raw secret %q", i, raw)
			}
		}
	}
	if !strings.Contains(f.bodies[0], "[ACME_LIVE_KEY len=42 prefix=acme") {
		t.Fatalf("secret not replaced by its fingerprint: %s", f.bodies[0])
	}
	if !strings.Contains(f.bodies[0], "internal.acmeshop.dev") {
		t.Fatal("non-secret context (internal URL) must still reach the model")
	}
}

func TestGuardRefusesSecretsAndRegisteredKeys(t *testing.T) {
	f := newStubAnthropic(t, `{}`)
	c := f.client()
	redact.Register(clientKey, "CLIENT_KEY")
	for _, text := range []string{"value " + clientKey, "ser.AbCdEfGhIjKlMnOp12345", "AKIAIOSFODNN7EXAMPLE"} {
		if _, err := c.send(context.Background(), "system", text); !errors.Is(err, ErrSecretInPrompt) {
			t.Fatalf("send(%q) err = %v, want ErrSecretInPrompt", text, err)
		}
	}
	if f.count() != 0 {
		t.Fatalf("guarded prompt reached the network (%d requests)", f.count())
	}
}

func TestEmbeddedPromptsAreCleanAndStrict(t *testing.T) {
	for _, name := range []string{"classify", "hypothesize", "explain", "fix_pr"} {
		p := prompt(name)
		if !strings.Contains(p, "Return ONLY JSON matching this schema. No prose.") {
			t.Errorf("%s lacks the JSON-only instruction", name)
		}
		if err := guard(p); err != nil {
			t.Errorf("%s trips the secret guard", name)
		}
	}
}

func TestClientScopeLockOnlyAllowsAnthropic(t *testing.T) {
	c := New(testAPIKey, "")
	for _, u := range []string{"https://example.com/v1/messages", "https://api.anthropic.com.evil.example/v1/messages"} {
		if _, err := c.http.Do(context.Background(), requestTo(u)); !errors.Is(err, scope.ErrOutOfScope) {
			t.Errorf("%s: err = %v, want out of scope", u, err)
		}
	}
	if err := c.http.Lock().CheckURL("https://api.anthropic.com/v1/messages"); err != nil {
		t.Fatalf("anthropic must be allowed: %v", err)
	}
}

func TestHypothesize(t *testing.T) {
	t.Run("off uses dictionary with domain email", func(t *testing.T) {
		hs, mode := New("", "").Hypothesize(context.Background(), []string{"admin_panel"}, []string{"loyalty_level"}, "https://shop.acmeshop.dev:3030/x")
		if mode != ModeOff || len(hs) == 0 || len(hs) > MaxHypotheses {
			t.Fatalf("mode=%q n=%d", mode, len(hs))
		}
		if hs[0].TraitKey != "loyalty_level" {
			t.Fatalf("bundle trait keys must rank first: %+v", hs[0])
		}
		have := map[string]bool{}
		for _, h := range hs {
			have[h.TraitKey+"="+h.TraitValue] = true
		}
		for _, want := range []string{"plan=gold", "plan=free", "role=admin", "role=staff", "role=internal", "is_beta=true", "tier=premium", "country=US", "internal=true", "employee=true", "email=staff@shop.acmeshop.dev"} {
			if !have[want] {
				t.Errorf("dictionary missing %s", want)
			}
		}
	})
	t.Run("ai valid", func(t *testing.T) {
		f := newStubAnthropic(t, "```\n"+`{"hypotheses":[{"trait_key":"role","trait_value":"admin","why":"admin flag"},{"trait_key":"role","trait_value":"admin","why":"dup"}]}`+"\n```")
		hs, mode := f.client().Hypothesize(context.Background(), []string{"admin_panel"}, nil, "acmeshop.dev")
		if !mode.On() || len(hs) != 1 || hs[0].TraitKey != "role" {
			t.Fatalf("mode=%q hs=%+v", mode, hs)
		}
	})
	t.Run("too many falls back", func(t *testing.T) {
		var items []string
		for i := 0; i < 41; i++ {
			items = append(items, `{"trait_key":"k`+string(rune('a'+i%26))+string(rune('a'+i/26))+`","trait_value":"v","why":"w"}`)
		}
		f := newStubAnthropic(t, `{"hypotheses":[`+strings.Join(items, ",")+`]}`)
		hs, mode := f.client().Hypothesize(context.Background(), nil, nil, "acmeshop.dev")
		if mode.On() || f.count() != 2 || len(hs) == 0 {
			t.Fatalf("mode=%q requests=%d", mode, f.count())
		}
	})
}

func sampleFinding() model.Finding {
	return model.Finding{ID: "GC-1", Type: model.FTraitForgery, Severity: model.SevHigh, Subject: "premium_export", Traits: map[string]string{"plan": "gold"},
		Unlocked: []model.FlagChange{{Flag: "premium_export", Before: "off:", After: "on:"}}}
}

func TestExplain(t *testing.T) {
	good := `{"title":"Anyone can stub a gold plan","what_happened":"A visitor set plan=gold.","why_it_matters":"Traits are client controlled.","business_impact":"Free paid features.","fix_summary":"Disable client traits."}`
	t.Run("ai", func(t *testing.T) {
		e := newStubAnthropic(t, good).client().Explain(context.Background(), sampleFinding())
		if e.Source != "ai" || e.Title == "" {
			t.Fatalf("%+v", e)
		}
	})
	t.Run("over 120 words falls back to template", func(t *testing.T) {
		long := strings.Repeat("word ", 130)
		f := newStubAnthropic(t, `{"title":"t","what_happened":"`+long+`","why_it_matters":"y","business_impact":"b","fix_summary":"f"}`)
		e := f.client().Explain(context.Background(), sampleFinding())
		if e.Source != "template" || f.count() != 2 {
			t.Fatalf("source=%s requests=%d", e.Source, f.count())
		}
	})
	t.Run("off", func(t *testing.T) {
		e := New("", "").Explain(context.Background(), sampleFinding())
		if e.Source != "template" || !strings.Contains(e.WhatHappened, "plan=gold") || !strings.Contains(e.WhatHappened, "premium_export") {
			t.Fatalf("%+v", e)
		}
	})
}

func TestTemplatesCoverEveryTypeWithinWordBudget(t *testing.T) {
	for _, ft := range []model.FindingType{
		model.FTraitForgery, model.FIdentifierForgery, model.FPercentageReroll, model.FVariantReroll, model.FExperimentRigging, model.FIdentityTraitLeak,
		model.FIdentityOverrideLeak, model.FSecretExposed, model.FInternalURL, model.FUnreleasedProduct, model.FPricingLeak,
		model.FPIILeak, model.FSettingClientTraitsOn, model.FSettingSensitiveData, model.FFlagNotServerOnly, model.FSegmentForgeable,
		model.FControlOK,
	} {
		e := templateExplanation(model.Finding{Type: ft, Subject: "x_flag", Traits: map[string]string{"a": "b"}})
		words := 0
		for _, s := range []string{e.Title, e.WhatHappened, e.WhyItMatters, e.BusinessImpact, e.FixSummary} {
			if s == "" || strings.Contains(s, "%!") {
				t.Fatalf("%s: bad template field %q", ft, s)
			}
			words += len(strings.Fields(s))
		}
		if words > MaxExplainWords || e.Source != "template" {
			t.Errorf("%s: words=%d source=%s", ft, words, e.Source)
		}
	}
}

func TestFixPR(t *testing.T) {
	impact := []model.ImpactItem{{File: "app.js", Line: 12, Snippet: "flagsmith.setTrait('plan', v)", Message: "sets plan in browser"}}
	f := sampleFinding()
	t.Run("ai", func(t *testing.T) {
		reply := `{"title":"Send plan from server","body":"Moves plan.","diff":"--- a/app.js\n+++ b/app.js\n@@ -1 +1 @@\n-a\n+b"}`
		d := newStubAnthropic(t, reply).client().FixPR(context.Background(), f, impact)
		if d.Source != "ai" || !strings.HasPrefix(d.Diff, "--- a/app.js") {
			t.Fatalf("%+v", d)
		}
	})
	t.Run("bad diff falls back", func(t *testing.T) {
		fk := newStubAnthropic(t, `{"title":"t","body":"b","diff":"just edit the file"}`)
		d := fk.client().FixPR(context.Background(), f, impact)
		if d.Source != "template" || fk.count() != 2 || !strings.Contains(d.Body, "app.js:12") {
			t.Fatalf("%+v requests=%d", d, fk.count())
		}
	})
	t.Run("off", func(t *testing.T) {
		d := New("", "").FixPR(context.Background(), f, impact)
		if d.Source != "template" || d.Diff != "" || d.Title == "" {
			t.Fatalf("%+v", d)
		}
	})
}

func TestStripFences(t *testing.T) {
	tests := map[string]string{
		"```json\n{\"a\":1}\n```":     `{"a":1}`,
		"```\n{\"a\":1}\n```":         `{"a":1}`,
		"Sure!\n{\"a\":1}\nThanks":    `{"a":1}`,
		"  {\"a\":1}  ":               `{"a":1}`,
		"```json\n[{\"a\":1}]\n```\n": `[{"a":1}]`,
	}
	for in, want := range tests {
		if got := stripFences(in); got != want {
			t.Errorf("stripFences(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReportable(t *testing.T) {
	for cat, want := range map[model.Category]bool{
		model.CatSecret: true, model.CatPII: true, model.CatHarmless: false, model.CatSecurityControl: false,
	} {
		if got := Reportable(model.Classification{Category: cat}); got != want {
			t.Errorf("Reportable(%s) = %v", cat, got)
		}
	}
}
