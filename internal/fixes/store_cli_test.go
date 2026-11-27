package fixes

import (
	"context"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

func TestStoreSaveGetListAtomic(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(id string, at time.Time) *model.PlanRecord {
		p := model.Plan{ID: id, CreatedAt: at, Environment: "Production", BeforeSnapshot: map[string]any{"a": true}}
		p.Hash = p.ComputeHash()
		return &model.PlanRecord{Plan: p, State: model.PlanPending}
	}
	now := time.Now().UTC()
	for i, id := range []string{"plan-0000000b", "plan-0000000a"} {
		if err := s.Save(mk(id, now.Add(time.Duration(-i)*time.Hour))); err != nil {
			t.Fatal(err)
		}
	}
	recs, err := s.List()
	if err != nil || len(recs) != 2 || recs[0].Plan.ID != "plan-0000000a" {
		t.Fatalf("list = %v err=%v", recs, err)
	}
	r := mk("plan-0000000a", now)
	r.State = model.PlanRejected
	if err := s.Save(r); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get("plan-0000000a")
	if got.State != model.PlanRejected {
		t.Fatalf("overwrite failed: %s", got.State)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(filepath.Join(dir, "plans", "plan-0000000a.json"))
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %v", fi.Mode().Perm())
		}
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "plans"))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
	if _, err := s.Get("plan-ffffffff"); !errors.Is(err, ErrPlanNotFound) {
		t.Fatalf("missing plan: %v", err)
	}
	for _, bad := range []string{"../x", "plan-1", "plan-ZZZZZZZZ", ""} {
		if _, err := s.Get(bad); err == nil || errors.Is(err, ErrPlanNotFound) {
			t.Fatalf("id %q must be rejected as invalid, got %v", bad, err)
		}
	}
}

// cliHelp is the top-level help of the real Flagsmith CLI v2.0.0 (abridged).
const cliHelp = "Available Commands:\n  api          Call the Flagsmith API\n  environment  Manage environments\n  feature      Manage features\n"

type cliCall struct {
	args  []string
	env   []string
	stdin string
}

func stubRun(calls *[]cliCall, reply string) runFunc {
	return func(_ context.Context, _ string, args, env []string, stdin io.Reader) ([]byte, error) {
		c := cliCall{args: args, env: env}
		if stdin != nil {
			b, _ := io.ReadAll(stdin)
			c.stdin = string(b)
		}
		*calls = append(*calls, c)
		if len(args) == 1 && args[0] == "--help" {
			return []byte(cliHelp), nil
		}
		return []byte(reply), nil
	}
}

func TestCLIEnvironmentUpdateUsesDedicatedCommand(t *testing.T) {
	var calls []cliCall
	cli, err := newExecCLI(t.Context(), "flagsmith", "http://localhost:8000/api/v1/", "abcdefgh.0123456789abcdefghijklmnopqrstuv", 7, stubRun(&calls, `{"ok":true}`))
	if err != nil {
		t.Fatal(err)
	}
	op := model.Operation{Kind: OpEnvPatch, Method: "PATCH", Path: "environments/envKEY123/"}
	if !cli.Supports(op) {
		t.Fatal("environment patch must be supported")
	}
	if err := cli.Run(t.Context(), op, map[string]any{"allow_client_traits": false}); err != nil {
		t.Fatal(err)
	}
	last := calls[len(calls)-1]
	if got := strings.Join(last.args, " "); got != "environment update envKEY123 --allow-client-traits=false --project 7 --yes --json" {
		t.Fatalf("command = %s", got)
	}
	env := strings.Join(last.env, "\n")
	for _, want := range []string{"FLAGSMITH_API_URL=http://localhost:8000", "FLAGSMITH_API_KEY_localhost_8000=", "FLAGSMITH_NO_INPUT=1"} {
		if !strings.Contains(env, want) {
			t.Errorf("env missing %s", want)
		}
	}
	for _, a := range last.args {
		if strings.Contains(a, "abcdefgh.") {
			t.Fatal("API key passed as an argument")
		}
	}
}

func TestCLIOtherPatchesUseAPICommandWithStdin(t *testing.T) {
	var calls []cliCall
	cli, _ := newExecCLI(t.Context(), "flagsmith", "http://localhost:8000/api/v1/", "k", 7, stubRun(&calls, `{"id":3}`))
	op := model.Operation{Kind: OpFeaturePatch, Method: "PATCH", Path: "projects/7/features/3/"}
	if err := cli.Run(t.Context(), op, map[string]any{"is_server_key_only": true}); err != nil {
		t.Fatal(err)
	}
	last := calls[len(calls)-1]
	if got := strings.Join(last.args, " "); got != "api api/v1/projects/7/features/3/ -X PATCH --input - --json" {
		t.Fatalf("command = %s", got)
	}
	if last.stdin != `{"is_server_key_only":true}` {
		t.Fatalf("stdin = %s", last.stdin)
	}
}

func TestCLIKeyVarForSelfHosted(t *testing.T) {
	u, _ := url.Parse("https://flagsmith-staging.com:8000/api/v1/")
	if got := cliKeyVar(u); got != "FLAGSMITH_API_KEY_flagsmith__staging_com_8000" {
		t.Fatalf("got %s", got)
	}
}

func TestCLIRejectsNonJSONOutputAndOldCLI(t *testing.T) {
	var calls []cliCall
	cli, _ := newExecCLI(t.Context(), "flagsmith", "http://localhost:8000/api/v1/", "k", 7, stubRun(&calls, "Done!"))
	if err := cli.Run(t.Context(), model.Operation{Kind: OpFeaturePatch, Path: "projects/7/features/3/"}, map[string]any{"x": 1}); err == nil {
		t.Fatal("non-JSON output accepted")
	}
	old := func(_ context.Context, _ string, _ []string, _ []string, _ io.Reader) ([]byte, error) {
		return []byte("Commands: update-environment"), nil
	}
	if _, err := newExecCLI(t.Context(), "flagsmith", "http://localhost:8000/api/v1/", "k", 7, old); err == nil {
		t.Fatal("a CLI without api/environment commands must be rejected")
	}
}
