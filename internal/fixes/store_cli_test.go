package fixes

import (
	"context"
	"errors"
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

func TestCLISupportDetectionAndRun(t *testing.T) {
	var calls [][]string
	run := func(_ context.Context, name string, args, _ []string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		if len(args) == 1 && args[0] == "--help" {
			return []byte("Usage: flagsmith <command>\n\nCommands:\n  get\n  update-environment   patch an environment\n"), nil
		}
		return []byte(`{"ok":true}`), nil
	}
	cli, err := newExecCLI(t.Context(), "flagsmith", nil, run)
	if err != nil {
		t.Fatal(err)
	}
	env := model.Operation{Kind: OpEnvPatch, Path: "environments/k/"}
	if !cli.Supports(env) || cli.Supports(model.Operation{Kind: OpFeaturePatch}) || cli.Supports(model.Operation{Kind: OpManual}) {
		t.Fatal("support detection wrong")
	}
	if err := cli.Run(t.Context(), env, map[string]any{"allow_client_traits": false}); err != nil {
		t.Fatal(err)
	}
	last := strings.Join(calls[len(calls)-1], " ")
	if last != `flagsmith update-environment --json --path environments/k/ --data {"allow_client_traits":false}` {
		t.Fatalf("command = %s", last)
	}
	if err := cli.Run(t.Context(), model.Operation{Kind: OpFeaturePatch}, nil); err == nil {
		t.Fatal("unsupported operation must not run")
	}
}

func TestCLIRejectsNonJSONOutput(t *testing.T) {
	run := func(_ context.Context, _ string, args, _ []string) ([]byte, error) {
		if args[0] == "--help" {
			return []byte("update-feature"), nil
		}
		return []byte("Done!"), nil
	}
	cli, _ := newExecCLI(t.Context(), "flagsmith", nil, run)
	if err := cli.Run(t.Context(), model.Operation{Kind: OpFeaturePatch}, map[string]any{"x": 1}); err == nil {
		t.Fatal("non-JSON output accepted")
	}
}
