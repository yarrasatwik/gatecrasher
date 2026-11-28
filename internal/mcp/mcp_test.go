package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

type stubBackend struct {
	r      *model.Report
	audits int
}

func (s *stubBackend) Audit(ctx context.Context, env string) (*model.Report, error) {
	s.audits++
	return s.r, nil
}

func (s *stubBackend) Latest() (*model.Report, error) {
	if s.r == nil {
		return nil, errors.New("none")
	}
	return s.r, nil
}

func sample() *model.Report {
	return &model.Report{Target: "http://localhost:3030", Environment: "Production", AIMode: "off (heuristics)",
		Findings: []model.Finding{
			{ID: "GC-1", Type: model.FTraitForgery, Severity: model.SevHigh, Status: model.StatusExploitable,
				Title: "Forging plan=gold unlocks premium_export", Traits: map[string]string{"plan": "gold"},
				Unlocked: []model.FlagChange{{Flag: "premium_export", Before: "off", After: "on"}},
				Repro:    "curl -s -H 'X-Environment-Key: <CLIENT_KEY>'", FixPlanID: "plan-1"},
			{ID: "GC-2", Type: model.FSettingSensitiveData, Severity: model.SevLow, Status: model.StatusBlocked, Title: "Hide sensitive data is OFF"},
		}}
}

func run(t *testing.T, b Backend, msgs ...string) []map[string]any {
	t.Helper()
	var out strings.Builder
	if err := New(b, "test").Serve(context.Background(), strings.NewReader(strings.Join(msgs, "\n")), &out); err != nil {
		t.Fatal(err)
	}
	var res []map[string]any
	sc := bufio.NewScanner(strings.NewReader(out.String()))
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("bad response %q: %v", sc.Text(), err)
		}
		res = append(res, m)
	}
	return res
}

func text(m map[string]any) string {
	c := m["result"].(map[string]any)["content"].([]any)[0].(map[string]any)
	return c["text"].(string)
}

func TestHandshakeAndTools(t *testing.T) {
	res := run(t, &stubBackend{r: sample()},
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"nope"}`,
		`not json`)
	if len(res) != 4 {
		t.Fatalf("want 4 responses (notification gets none), got %d", len(res))
	}
	if res[0]["result"].(map[string]any)["protocolVersion"] != ProtocolVersion {
		t.Fatal("protocol version")
	}
	tools := res[1]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 3 {
		t.Fatalf("tools: %d", len(tools))
	}
	for _, tl := range tools {
		ann := tl.(map[string]any)["annotations"].(map[string]any)
		if ann["readOnlyHint"] != true {
			t.Fatalf("tool %v is not read-only", tl)
		}
	}
	if res[2]["error"].(map[string]any)["code"].(float64) != -32601 || res[3]["error"].(map[string]any)["code"].(float64) != -32700 {
		t.Fatal("error codes")
	}
}

func TestToolCalls(t *testing.T) {
	b := &stubBackend{r: sample()}
	res := run(t, b,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"gatecrasher_audit","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"gatecrasher_findings","arguments":{"min_severity":"high"}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"gatecrasher_explain","arguments":{"finding_id":"gc-1"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"gatecrasher_explain","arguments":{"finding_id":"GC-9"}}}`)
	if b.audits != 1 || !strings.HasPrefix(text(res[0]), "1 way in · 2 findings") {
		t.Fatalf("audit: %q", text(res[0]))
	}
	if strings.Contains(text(res[1]), "GC-2") || !strings.Contains(text(res[1]), "GC-1") {
		t.Fatalf("min_severity filter: %q", text(res[1]))
	}
	if !strings.Contains(text(res[2]), "premium_export: off → on") || !strings.Contains(text(res[2]), "pending plans: open the web UI to review") {
		t.Fatalf("explain: %q", text(res[2]))
	}
	if res[3]["result"].(map[string]any)["isError"] != true {
		t.Fatal("unknown finding must be a tool error")
	}
}

func TestOutputRedacted(t *testing.T) {
	redact.Register("CQJFFFBP5Hk65U5vDHU3MS", "CLIENT_KEY")
	r := sample()
	r.Findings[0].Title = "leak CQJFFFBP5Hk65U5vDHU3MS"
	res := run(t, &stubBackend{r: r}, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"gatecrasher_findings","arguments":{}}}`)
	if strings.Contains(text(res[0]), "CQJFFFBP5Hk65U5vDHU3MS") {
		t.Fatal("key leaked through MCP output")
	}
}

// leakPatterns match what an agent would need to approve a plan itself.
var leakPatterns = []*regexp.Regexp{
	regexp.MustCompile(`plan-[0-9a-f]{8}`),
	regexp.MustCompile(`[0-9a-f]{12,}`),
}

// TestNoToolOutputRevealsPlanIDsOrHashes calls every tool the server lists,
// with a report that carries plan IDs and hashes in every text field, and
// scans the raw responses.
func TestNoToolOutputRevealsPlanIDsOrHashes(t *testing.T) {
	const planID = "plan-0a1b2c3d"
	const hash = "9f2c4e6a8b0d1f3e5a7c9b1d3f5e7a9c0b2d4f6e8a1c3e5b7d9f0a2c4e6b8d0f"
	leaky := "see " + planID + " (hash " + hash + ", short " + hash[:12] + ")"
	r := sample()
	r.Target, r.Environment, r.AIMode = "http://localhost:3030 "+leaky, "Production "+leaky, "off "+leaky
	r.Notes = []string{leaky}
	for i := range r.Findings {
		f := &r.Findings[i]
		f.FixPlanID = planID
		f.Title += " " + leaky
		f.Subject = leaky
		f.Repro = "curl " + leaky
		f.Traits = map[string]string{"plan": leaky}
		f.Unlocked = []model.FlagChange{{Flag: "premium_export " + leaky, Before: leaky, After: leaky}}
		f.Notes = []string{leaky}
		f.Explanation = &model.Explanation{Title: leaky, WhatHappened: leaky, WhyItMatters: leaky, BusinessImpact: leaky, FixSummary: leaky}
	}
	b := &stubBackend{r: r}
	listed := run(t, b, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	var calls []string
	for _, tl := range listed[0]["result"].(map[string]any)["tools"].([]any) {
		name := tl.(map[string]any)["name"].(string)
		for _, args := range []string{`{}`, `{"finding_id":"GC-1"}`, `{"finding_id":"GC-2"}`,
			`{"finding_id":"` + planID + `"}`, `{"min_severity":"` + hash + `"}`, `{"environment":"` + planID + `"}`} {
			calls = append(calls, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, len(calls)+2, name, args))
		}
	}
	if len(calls) < 3*6 {
		t.Fatalf("expected every listed tool to be exercised, got %d calls", len(calls))
	}
	msgs := append([]string{
		`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":"` + planID + `","method":"` + planID + `"}`,
	}, calls...)
	var out strings.Builder
	if err := New(b, "test").Serve(context.Background(), strings.NewReader(strings.Join(msgs, "\n")), &out); err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(strings.NewReader(out.String()))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	seen, pointed := 0, false
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		// The request ID is echoed back by JSON-RPC; everything the server
		// itself produced is in result and error.
		body, _ := json.Marshal([]any{m["result"], m["error"]})
		seen++
		for _, re := range leakPatterns {
			if hit := re.FindString(string(body)); hit != "" {
				t.Errorf("MCP output reveals %q: %s", hit, body)
			}
		}
		pointed = pointed || strings.Contains(string(body), "pending plans: open the web UI to review")
	}
	if seen != len(msgs) {
		t.Fatalf("got %d responses for %d requests", seen, len(msgs))
	}
	if !pointed {
		t.Fatal("findings with a fix plan must point the agent at the web UI")
	}
}

func TestScrubKeepsProbeIdentifiers(t *testing.T) {
	in := "identifier gc-probe-704a9188-da60-4492-9243-d3aaeb834036 for plan-0a1b2c3d hash 68e3114a71d1"
	want := "identifier gc-probe-704a9188-da60-4492-9243-d3aaeb834036 for [plan withheld] hash [hash withheld]"
	if got := scrub(in); got != want {
		t.Fatalf("scrub = %q, want %q", got, want)
	}
}
