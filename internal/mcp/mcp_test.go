package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
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
	if b.audits != 1 || !strings.HasPrefix(text(res[0]), "1 ways in") {
		t.Fatalf("audit: %q", text(res[0]))
	}
	if strings.Contains(text(res[1]), "GC-2") || !strings.Contains(text(res[1]), "GC-1") {
		t.Fatalf("min_severity filter: %q", text(res[1]))
	}
	if !strings.Contains(text(res[2]), "premium_export: off → on") || !strings.Contains(text(res[2]), "plan-1") {
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
