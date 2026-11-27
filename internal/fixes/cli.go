package fixes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

// cliBridge executes plan operations through the Flagsmith CLI when it
// supports them. The applier falls back to the Admin API otherwise.
type cliBridge interface {
	// Supports reports whether the CLI can execute the operation.
	Supports(op model.Operation) bool
	// Run executes the operation with body as its payload.
	Run(ctx context.Context, op model.Operation, body map[string]any) error
}

// cliCommands maps operation kinds to the CLI subcommand that executes
// them. A subcommand counts as supported only if `flagsmith --help` lists it.
var cliCommands = map[string]string{
	OpEnvPatch:     "update-environment",
	OpFeaturePatch: "update-feature",
}

type runFunc func(ctx context.Context, name string, args, env []string) ([]byte, error)

// ExecCLI drives the `flagsmith` binary. Credentials reach it through env
// (for example the CLI's own API-key variable), never through arguments.
type ExecCLI struct {
	binary   string
	env      []string
	run      runFunc
	commands map[string]bool
}

// NewExecCLI locates the Flagsmith CLI on PATH and inspects `--help` to see
// which operations it supports. It returns an error when the binary is not
// installed, so callers can simply keep using the Admin API.
func NewExecCLI(ctx context.Context, env []string) (*ExecCLI, error) {
	bin, err := exec.LookPath("flagsmith")
	if err != nil {
		return nil, fmt.Errorf("flagsmith CLI not found on PATH: %w", err)
	}
	return newExecCLI(ctx, bin, env, execRun)
}

func newExecCLI(ctx context.Context, bin string, env []string, run runFunc) (*ExecCLI, error) {
	help, err := run(ctx, bin, []string{"--help"}, env)
	if err != nil {
		return nil, fmt.Errorf("flagsmith --help: %w", err)
	}
	return &ExecCLI{binary: bin, env: env, run: run, commands: supportedCommands(string(help))}, nil
}

func supportedCommands(help string) map[string]bool {
	out := map[string]bool{}
	for _, cmd := range cliCommands {
		if regexp.MustCompile(`(?m)(^|[\s,|])` + regexp.QuoteMeta(cmd) + `($|[\s,|])`).MatchString(help) {
			out[cmd] = true
		}
	}
	return out
}

// Supports implements cliBridge.
func (c *ExecCLI) Supports(op model.Operation) bool {
	cmd, ok := cliCommands[op.Kind]
	return ok && c.commands[cmd]
}

// Run implements cliBridge: `flagsmith <subcommand> --json --path <admin
// path> --data <json body>`.
func (c *ExecCLI) Run(ctx context.Context, op model.Operation, body map[string]any) error {
	cmd, ok := cliCommands[op.Kind]
	if !ok || !c.commands[cmd] {
		return fmt.Errorf("flagsmith CLI does not support %s", op.Kind)
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	out, err := c.run(ctx, c.binary, []string{cmd, "--json", "--path", op.Path, "--data", string(data)}, c.env)
	if err != nil {
		return fmt.Errorf("flagsmith %s: %w", cmd, err)
	}
	if t := bytes.TrimSpace(out); len(t) > 0 && !json.Valid(t) {
		return fmt.Errorf("flagsmith %s: expected JSON output, got %q", cmd, redact.String(string(truncateBytes(t, 120))))
	}
	return nil
}

func truncateBytes(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

func execRun(ctx context.Context, name string, args, env []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if env != nil {
		cmd.Env = env
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := redact.String(string(truncateBytes(bytes.TrimSpace(stderr.Bytes()), 300)))
		return nil, errors.New(err.Error() + ": " + msg)
	}
	return stdout.Bytes(), nil
}
