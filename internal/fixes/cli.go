package fixes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

// cliBridge executes plan operations through the Flagsmith CLI. The applier
// falls back to the Admin API when the CLI is unavailable or fails.
type cliBridge interface {
	// Supports reports whether the CLI can execute the operation.
	Supports(op model.Operation) bool
	// Run executes the operation with body as its payload.
	Run(ctx context.Context, op model.Operation, body map[string]any) error
}

type runFunc func(ctx context.Context, name string, args, env []string, stdin io.Reader) ([]byte, error)

// ExecCLI drives the official Flagsmith CLI v2 (github.com/Flagsmith/
// flagsmith-cli), verified against v2.0.0:
//
//   - turning client traits off uses the dedicated command
//     `flagsmith environment update <env-key> --allow-client-traits=false`;
//   - every other Admin API change uses `flagsmith api api/v1/<path> -X PATCH
//     --input -` with the JSON body on stdin.
//
// Credentials reach the CLI only through its documented environment
// variables (FLAGSMITH_API_KEY and the per-host FLAGSMITH_API_KEY_<host>
// form for self-hosted instances), never through arguments.
type ExecCLI struct {
	binary  string
	base    string // API origin, e.g. http://localhost:8000
	project string // project ID, scopes `environment update`
	env     []string
	run     runFunc
	help    string
}

// NewExecCLI locates the Flagsmith CLI on PATH and prepares it for apiURL
// (the Admin API base, e.g. http://localhost:8000/api/v1/) with the
// organisation API key. It returns an error when the binary is missing, so
// callers simply keep using the Admin API.
func NewExecCLI(ctx context.Context, apiURL, orgKey string, projectID int) (*ExecCLI, error) {
	bin, err := exec.LookPath("flagsmith")
	if err != nil {
		return nil, fmt.Errorf("flagsmith CLI not found on PATH: %w", err)
	}
	return newExecCLI(ctx, bin, apiURL, orgKey, projectID, execRun)
}

func newExecCLI(ctx context.Context, bin, apiURL, orgKey string, projectID int, run runFunc) (*ExecCLI, error) {
	u, err := url.Parse(apiURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid API URL %q", apiURL)
	}
	base := u.Scheme + "://" + u.Host
	env := append(os.Environ(),
		"FLAGSMITH_API_URL="+base,
		"FLAGSMITH_NO_INPUT=1",
		"FLAGSMITH_API_KEY="+orgKey,
		cliKeyVar(u)+"="+orgKey,
	)
	c := &ExecCLI{binary: bin, base: base, project: fmt.Sprint(projectID), env: env, run: run}
	help, err := run(ctx, bin, []string{"--help"}, env, nil)
	if err != nil {
		return nil, fmt.Errorf("flagsmith --help: %w", err)
	}
	c.help = string(help)
	if !strings.Contains(c.help, "api ") || !strings.Contains(c.help, "environment") {
		return nil, errors.New("flagsmith CLI does not offer the api/environment commands (need CLI v2)")
	}
	return c, nil
}

// cliKeyVar is the CLI's per-host credential variable: host and port
// appended, "-" doubled, "." and ":" written as "_".
func cliKeyVar(u *url.URL) string {
	h := strings.NewReplacer("-", "__", ".", "_", ":", "_").Replace(u.Host)
	return "FLAGSMITH_API_KEY_" + h
}

// Supports implements cliBridge: every Admin API patch can go through the CLI.
func (c *ExecCLI) Supports(op model.Operation) bool {
	return op.Path != "" && (op.Method == "" || strings.EqualFold(op.Method, "PATCH"))
}

// Run implements cliBridge.
func (c *ExecCLI) Run(ctx context.Context, op model.Operation, body map[string]any) error {
	if args, ok := c.environmentUpdate(op, body); ok {
		_, err := c.exec(ctx, args, nil)
		return err
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	path := "api/v1/" + strings.TrimLeft(op.Path, "/")
	_, err = c.exec(ctx, []string{"api", path, "-X", "PATCH", "--input", "-", "--json"}, bytes.NewReader(data))
	return err
}

// environmentUpdate maps {"allow_client_traits": bool} on an environment to
// the CLI's dedicated command.
func (c *ExecCLI) environmentUpdate(op model.Operation, body map[string]any) ([]string, bool) {
	v, ok := body["allow_client_traits"].(bool)
	if !ok || len(body) != 1 || !strings.HasPrefix(op.Path, "environments/") {
		return nil, false
	}
	key := strings.Trim(strings.TrimPrefix(op.Path, "environments/"), "/")
	if key == "" || strings.Contains(key, "/") {
		return nil, false
	}
	return []string{"environment", "update", key, fmt.Sprintf("--allow-client-traits=%t", v),
		"--project", c.project, "--yes", "--json"}, true
}

func (c *ExecCLI) exec(ctx context.Context, args []string, stdin io.Reader) ([]byte, error) {
	out, err := c.run(ctx, c.binary, args, c.env, stdin)
	if err != nil {
		return nil, fmt.Errorf("flagsmith %s: %w", args[0], err)
	}
	if t := bytes.TrimSpace(out); len(t) > 0 && !json.Valid(t) {
		return nil, fmt.Errorf("flagsmith %s: expected JSON output, got %q", args[0], redact.String(string(truncateBytes(t, 160))))
	}
	return out, nil
}

func truncateBytes(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

func execRun(ctx context.Context, name string, args, env []string, stdin io.Reader) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	cmd.Stdin = stdin
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := redact.String(string(truncateBytes(bytes.TrimSpace(stderr.Bytes()), 300)))
		return nil, errors.New(err.Error() + ": " + msg)
	}
	return stdout.Bytes(), nil
}
