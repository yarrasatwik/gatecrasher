package ai

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

func TestCLIArgsDisableEverything(t *testing.T) {
	args := cliArgs("claude-sonnet-5-5", "/tmp/system.md")
	i := slices.Index(args, "--tools")
	if i < 0 || args[i+1] != "" {
		t.Fatalf("tools must be explicitly empty: %v", args)
	}
	for _, want := range []string{"-p", "--strict-mcp-config", "--no-session-persistence", "--setting-sources", "--system-prompt-file"} {
		if !slices.Contains(args, want) {
			t.Errorf("missing %s in %v", want, args)
		}
	}
}

// stubCLI writes a tiny script standing in for the claude binary. It echoes
// a canned JSON reply and records its stdin so tests can inspect the prompt.
func stubCLI(t *testing.T, reply string) (bin, stdinFile string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell stub needs a POSIX shell")
	}
	dir := t.TempDir()
	stdinFile = filepath.Join(dir, "stdin.txt")
	bin = filepath.Join(dir, "claude")
	script := "#!/bin/sh\ncat > '" + stdinFile + "'\ncat <<'EOF'\n" + reply + "\nEOF\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, stdinFile
}

func TestClaudeCodeExplain(t *testing.T) {
	reply := `{"is_error":false,"result":"{\"title\":\"t\",\"what_happened\":\"w\",\"why_it_matters\":\"y\",\"business_impact\":\"b\",\"fix_summary\":\"f\"}"}`
	bin, stdin := stubCLI(t, reply)
	c, err := NewClaudeCode(bin, "")
	if err != nil {
		t.Fatal(err)
	}
	if !c.Mode().On() || !strings.Contains(string(c.Mode()), "Claude Code") {
		t.Fatalf("mode %q", c.Mode())
	}
	redact.Register("CQJFFFBP5Hk65U5vDHU3MS", "CLIENT_KEY")
	f := model.Finding{ID: "GC-1", Type: model.FTraitForgery, Title: "Forging plan=gold unlocks premium_export",
		Repro: "curl -H 'X-Environment-Key: CQJFFFBP5Hk65U5vDHU3MS'"}
	e := c.Explain(context.Background(), f)
	if e == nil || e.Source != "ai" || e.WhatHappened != "w" {
		t.Fatalf("explanation %+v", e)
	}
	sent, _ := os.ReadFile(stdin)
	if strings.Contains(string(sent), "CQJFFFBP5Hk65U5vDHU3MS") {
		t.Fatal("raw key reached the Claude Code prompt")
	}
}

func TestClaudeCodeRefusesBatchWrapper(t *testing.T) {
	if _, err := NewClaudeCode(`C:\tools\claude.cmd`, ""); err == nil {
		t.Fatal("a .cmd wrapper must be refused")
	}
}

func TestClaudeCodeErrorFallsBack(t *testing.T) {
	bin, _ := stubCLI(t, `{"is_error":true,"subtype":"error_max_turns","result":""}`)
	c, _ := NewClaudeCode(bin, "")
	e := c.Explain(context.Background(), model.Finding{ID: "GC-1", Type: model.FSecretExposed, Title: "x"})
	if e == nil || e.Source != "template" {
		t.Fatalf("want template fallback, got %+v", e)
	}
}
