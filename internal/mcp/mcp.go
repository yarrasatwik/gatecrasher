// Package mcp exposes Gatecrasher to coding agents (Claude Code, Cursor, …)
// as a Model Context Protocol server over stdio. It is read-only by design:
// agents can run an audit, list findings and get explanations, but every
// change to Flagsmith still goes through Gatecrasher's human approval flow.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

// ProtocolVersion is the MCP revision this server implements.
const ProtocolVersion = "2025-06-18"

// Backend is what the server needs from the Gatecrasher app.
type Backend interface {
	// Audit runs a read-only audit of env ("" = default) and returns it.
	Audit(ctx context.Context, env string) (*model.Report, error)
	// Latest returns the most recent saved report.
	Latest() (*model.Report, error)
}

// Server is a stdio MCP server.
type Server struct {
	b       Backend
	version string
	mu      sync.Mutex
}

// New returns a server for b; version is reported in serverInfo.
func New(b Backend, version string) *Server { return &Server{b: b, version: version} }

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Serve reads newline-delimited JSON-RPC messages from r and writes
// responses to w until r is exhausted or ctx is cancelled.
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	enc := json.NewEncoder(w)
	for sc.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			s.write(enc, response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}})
			continue
		}
		if len(req.ID) == 0 { // notification: no response
			continue
		}
		result, rerr := s.handle(ctx, req)
		s.write(enc, response{JSONRPC: "2.0", ID: req.ID, Result: result, Error: rerr})
	}
	return sc.Err()
}

func (s *Server) write(enc *json.Encoder, r response) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = enc.Encode(r)
}

func (s *Server) handle(ctx context.Context, req request) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		return map[string]any{
			"protocolVersion": ProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "gatecrasher", "version": s.version},
			"instructions": "Gatecrasher audits the user's own Flagsmith setup for flags users can unlock and data they can read. " +
				"Tools are read-only; fixes require a human to approve them in Gatecrasher.",
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": tools()}, nil
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, &rpcError{-32602, "invalid params"}
		}
		text, err := s.call(ctx, p.Name, p.Arguments)
		if err != nil {
			return toolResult(redact.String(err.Error()), true), nil
		}
		return toolResult(redact.String(text), false), nil
	}
	return nil, &rpcError{-32601, "method not found: " + req.Method}
}

func toolResult(text string, isErr bool) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": isErr}
}

func tools() []map[string]any {
	obj := func(props map[string]any, required ...string) map[string]any {
		m := map[string]any{"type": "object", "properties": props}
		if len(required) > 0 {
			m["required"] = required
		}
		return m
	}
	ro := map[string]any{"readOnlyHint": true, "destructiveHint": false, "openWorldHint": false}
	return []map[string]any{
		{"name": "gatecrasher_audit", "title": "Audit Flagsmith",
			"description": "Run a read-only Gatecrasher audit (outside view + inside map) of the configured Flagsmith project and return every way in, ranked by severity.",
			"inputSchema": obj(map[string]any{"environment": map[string]any{"type": "string", "description": "Environment name; defaults to the configured production environment."}}),
			"annotations": ro},
		{"name": "gatecrasher_findings", "title": "Latest findings",
			"description": "Return the findings of the most recent Gatecrasher report without sending any request to Flagsmith.",
			"inputSchema": obj(map[string]any{"min_severity": map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low", "info"}}}),
			"annotations": ro},
		{"name": "gatecrasher_explain", "title": "Explain a finding",
			"description": "Explain one finding in plain English: what happened, why it matters, how to reproduce it, and the fix plan to approve.",
			"inputSchema": obj(map[string]any{"finding_id": map[string]any{"type": "string", "description": "Finding ID such as GC-688647D2."}}, "finding_id"),
			"annotations": ro},
	}
}

func (s *Server) call(ctx context.Context, name string, args map[string]any) (string, error) {
	str := func(k string) string { v, _ := args[k].(string); return strings.TrimSpace(v) }
	switch name {
	case "gatecrasher_audit":
		r, err := s.b.Audit(ctx, str("environment"))
		if err != nil {
			return "", err
		}
		return Summary(r, model.SevInfo), nil
	case "gatecrasher_findings":
		r, err := s.b.Latest()
		if err != nil {
			return "", fmt.Errorf("no report yet: run gatecrasher_audit first (%w)", err)
		}
		min := model.SevInfo
		if v := str("min_severity"); v != "" {
			if min, err = model.ParseSeverity(v); err != nil {
				return "", err
			}
		}
		return Summary(r, min), nil
	case "gatecrasher_explain":
		r, err := s.b.Latest()
		if err != nil {
			return "", err
		}
		id := str("finding_id")
		for _, f := range r.Findings {
			if strings.EqualFold(f.ID, id) {
				return Explain(f), nil
			}
		}
		return "", fmt.Errorf("finding %q not found in the latest report", id)
	}
	return "", fmt.Errorf("unknown tool %q", name)
}

// Summary renders a token-efficient text summary of a report.
func Summary(r *model.Report, min model.Severity) string {
	var b strings.Builder
	open := 0
	for _, f := range r.Findings {
		if f.Status == model.StatusExploitable && f.Type != model.FControlOK {
			open++
		}
	}
	fmt.Fprintf(&b, "%d ways in · %s · env %s · AI %s\n", open, r.Target, r.Environment, r.AIMode)
	for _, f := range r.Findings {
		if f.Severity < min || f.Type == model.FControlOK {
			continue
		}
		fmt.Fprintf(&b, "- [%s] %s %s — %s", strings.ToUpper(f.Severity.String()), f.ID, f.Status, f.Title)
		if f.FixPlanID != "" {
			fmt.Fprintf(&b, " (fix plan %s)", f.FixPlanID)
		}
		b.WriteByte('\n')
	}
	b.WriteString("Fixes are applied only after a human approves them: gatecrasher plan, then approve in the CLI or web UI.\n")
	return b.String()
}

// Explain renders one finding for an agent.
func Explain(f model.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s [%s] %s — %s\n", f.ID, strings.ToUpper(f.Severity.String()), f.Type, f.Title)
	if e := f.Explanation; e != nil {
		fmt.Fprintf(&b, "What happened: %s\nWhy it matters: %s\nBusiness impact: %s\nFix: %s\n", e.WhatHappened, e.WhyItMatters, e.BusinessImpact, e.FixSummary)
	}
	if len(f.Traits) > 0 {
		fmt.Fprintf(&b, "Forged input: %v\n", f.Traits)
	}
	for _, u := range f.Unlocked {
		fmt.Fprintf(&b, "Changes %s: %s → %s\n", u.Flag, u.Before, u.After)
	}
	if f.Repro != "" {
		fmt.Fprintf(&b, "Reproduce: %s\n", f.Repro)
	}
	if f.FixPlanID != "" {
		fmt.Fprintf(&b, "Fix plan: %s (needs human approval)\n", f.FixPlanID)
	}
	return b.String()
}
