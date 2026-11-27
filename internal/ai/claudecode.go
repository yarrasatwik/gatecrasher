package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// cliTimeout bounds one Claude Code call.
const cliTimeout = 3 * time.Minute

// NewClaudeCode builds a Client that talks to Claude through a signed-in
// Claude Code CLI ("claude -p") instead of an API key. Every call runs with
// all tools disabled, no MCP servers, no settings files and no session
// persistence, from an empty working directory — the model can only read
// the redacted prompt and answer with text, exactly like the API path.
// binary is the claude executable ("" = look it up on PATH).
func NewClaudeCode(binary, model string) (*Client, error) {
	if binary == "" {
		p, err := exec.LookPath("claude")
		if err != nil {
			return nil, errors.New("claude-code AI provider: the claude CLI is not on PATH")
		}
		binary = nativeBinary(p)
	}
	if ext := strings.ToLower(filepath.Ext(binary)); ext == ".cmd" || ext == ".bat" {
		// cmd.exe re-parses arguments (empty values vanish), which could
		// silently re-enable tools; refuse rather than risk it.
		return nil, fmt.Errorf("claude-code AI provider: %s is a batch wrapper; point to the native claude executable", filepath.Base(binary))
	}
	if model == "" {
		model = DefaultModel
	}
	return &Client{model: model, cli: binary}, nil
}

// nativeBinary resolves npm's Windows wrapper (claude.cmd) to the native
// claude.exe it launches, so arguments reach Claude Code unmodified.
func nativeBinary(p string) string {
	if runtime.GOOS != "windows" {
		return p
	}
	exe := filepath.Join(filepath.Dir(p), "node_modules", "@anthropic-ai", "claude-code", "bin", "claude.exe")
	if _, err := os.Stat(exe); err == nil {
		return exe
	}
	return p
}

// cliResult is the JSON object "claude -p --output-format json" prints.
type cliResult struct {
	IsError bool   `json:"is_error"`
	Result  string `json:"result"`
	Subtype string `json:"subtype"`
}

// cliArgs returns the locked-down argument list for one call.
func cliArgs(model, systemFile string) []string {
	return []string{
		"-p",
		"--model", model,
		"--output-format", "json",
		"--tools", "", // no built-in tools at all
		"--strict-mcp-config",   // no MCP servers
		"--setting-sources", "", // ignore user/project/local settings (no hooks)
		"--no-session-persistence",
		"--system-prompt-file", systemFile,
	}
}

func (c *Client) sendCLI(ctx context.Context, system, user string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, cliTimeout)
	defer cancel()
	dir, err := os.MkdirTemp("", "gatecrasher-ai-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	sysFile := filepath.Join(dir, "system.md")
	if err := os.WriteFile(sysFile, []byte(system), 0o600); err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, c.cli, cliArgs(c.model, sysFile)...)
	cmd.Dir = dir // empty: nothing for Claude Code to discover
	cmd.Stdin = strings.NewReader(user)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return "", fmt.Errorf("claude code: %v: %s", err, msg)
	}
	var res cliResult
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		return "", fmt.Errorf("claude code: unexpected output: %w", err)
	}
	if res.IsError {
		return "", fmt.Errorf("claude code returned an error (%s)", res.Subtype)
	}
	return res.Result, nil
}
