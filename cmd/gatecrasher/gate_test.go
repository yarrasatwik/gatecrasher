package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/audit"
	"github.com/yarrasatwik/gatecrasher/internal/fixes"
	"github.com/yarrasatwik/gatecrasher/internal/model"
)

const (
	prodPlan = "plan-0a1b2c3d"
	devPlan  = "plan-4e5f6071"
)

// fakeGate simulates a session: env holds the environment variables, tty
// says whether stdin and stdout are terminals, input is what gets typed.
func fakeGate(env map[string]string, stdinTTY, stdoutTTY bool, input string) (*gate, *bytes.Buffer) {
	out := &bytes.Buffer{}
	return &gate{
		getenv:    func(k string) string { return env[k] },
		stdinTTY:  func() bool { return stdinTTY },
		stdoutTTY: func() bool { return stdoutTTY },
		in:        bufio.NewReader(strings.NewReader(input)),
		out:       out,
	}, out
}

// workspace writes a config and two pending plans (Production and
// Development) into a temp dir and returns the config path and state dir.
func workspace(t *testing.T) (cfgPath, stateDir string) {
	t.Helper()
	dir := t.TempDir()
	stateDir = filepath.Join(dir, "state")
	cfgPath = filepath.Join(dir, "gatecrasher.yaml")
	cfg := "allowed_domains: [localhost]\n" +
		"flagsmith:\n  api_url: http://localhost:8000/api/v1/\n  allowed_api_hosts: [\"localhost:8000\"]\n" +
		"  environments: [Development, Production]\n" +
		"ai: \"off\"\n" +
		"state_dir: '" + filepath.ToSlash(stateDir) + "'\n" +
		"report_dir: '" + filepath.ToSlash(filepath.Join(dir, "reports")) + "'\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := fixes.NewStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []model.Plan{
		{ID: prodPlan, Environment: "Production", Production: true, Title: "Disable client traits"},
		{ID: devPlan, Environment: "Development", Title: "Disable client traits"},
	} {
		p.CreatedAt = time.Unix(1700000000, 0).UTC()
		p.TargetObject = "environment:" + p.Environment
		p.Operations = []model.Operation{{Kind: "env.patch", Description: "Turn off allow_client_traits", Automatic: true,
			Method: "PATCH", Path: "environments/KEY/", Body: map[string]any{"allow_client_traits": false}}}
		p.Hash = p.ComputeHash()
		if err := st.Save(&model.PlanRecord{Plan: p, State: model.PlanPending}); err != nil {
			t.Fatal(err)
		}
	}
	return cfgPath, stateDir
}

func planState(t *testing.T, stateDir, id string) *model.PlanRecord {
	t.Helper()
	st, err := fixes.NewStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := st.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func last4(t *testing.T, stateDir, id string) string {
	t.Helper()
	h := planState(t, stateDir, id).Plan.Hash
	return h[len(h)-4:]
}

// wantRefused asserts err is a gate refusal that points at both ways a
// person can approve, and that the plan is still pending.
func wantRefused(t *testing.T, err error, stateDir, id string, wants ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("approval was accepted; it must be refused")
	}
	var ge *gateError
	if !errors.As(err, &ge) {
		t.Fatalf("want a gate refusal, got %T: %v", err, err)
	}
	for _, w := range append([]string{"gatecrasher serve", "real terminal"}, wants...) {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("refusal %q does not mention %q", err.Error(), w)
		}
	}
	if rec := planState(t, stateDir, id); rec.State != model.PlanPending || rec.Approval != nil {
		t.Fatalf("plan must stay pending after a refusal, got %s", rec.State)
	}
}

func TestApprovePipedStdinRefusedForProduction(t *testing.T) {
	cfg, state := workspace(t)
	// Piped stdin carrying exactly what a person would type.
	g, _ := fakeGate(nil, false, true, "Production\n"+last4(t, state, prodPlan)+"\n")
	err := approve(context.Background(), []string{prodPlan, "-config", cfg}, g)
	wantRefused(t, err, state, prodPlan, "stdin is not a terminal")

	// Through the real entry point the process exits non-zero.
	old := newGate
	newGate = func() *gate { return g }
	defer func() { newGate = old }()
	if code := run(context.Background(), []string{"approve", prodPlan, "-config", cfg}); code == exitOK {
		t.Fatalf("exit code = %d, want non-zero", code)
	}
	if rec := planState(t, state, prodPlan); rec.State != model.PlanPending {
		t.Fatalf("the Production plan is %s, want pending", rec.State)
	}
}

func TestApproveRedirectedStdoutRefusedForProduction(t *testing.T) {
	cfg, state := workspace(t)
	g, _ := fakeGate(nil, true, false, "Production\n"+last4(t, state, prodPlan)+"\n")
	err := approve(context.Background(), []string{prodPlan, "-config", cfg}, g)
	wantRefused(t, err, state, prodPlan, "stdout is not a terminal")
}

func TestApproveConfirmFlagRefusedForProduction(t *testing.T) {
	cfg, state := workspace(t)
	for _, tty := range []bool{false, true} {
		g, _ := fakeGate(nil, tty, tty, "")
		err := approve(context.Background(), []string{prodPlan, "--confirm", "Production", "-config", cfg}, g)
		wantRefused(t, err, state, prodPlan, "--confirm")
	}
}

func TestApproveRefusedInAgentAndCISessionsEvenWithATerminal(t *testing.T) {
	for _, name := range []string{"CI", "CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CURSOR_TRACE_ID", "GITHUB_ACTIONS", "GATECRASHER_AGENT"} {
		t.Run(name, func(t *testing.T) {
			cfg, state := workspace(t)
			g, _ := fakeGate(map[string]string{name: "1"}, true, true, "Production\n"+last4(t, state, prodPlan)+"\n")
			err := approve(context.Background(), []string{prodPlan, "-config", cfg}, g)
			wantRefused(t, err, state, prodPlan, name)
		})
	}
}

func TestApproveProductionInteractiveNeedsNameAndHashSuffix(t *testing.T) {
	cfg, state := workspace(t)
	suffix := last4(t, state, prodPlan)
	wrong := "zzzz"
	for name, input := range map[string]string{
		"nothing typed":     "\n",
		"wrong environment": "Development\n" + suffix + "\n",
		"wrong case":        "production\n" + suffix + "\n",
		"no hash suffix":    "Production\n\n",
		"wrong hash suffix": "Production\n" + wrong + "\n",
		"input ends early":  "Production",
	} {
		t.Run(name, func(t *testing.T) {
			g, _ := fakeGate(nil, true, true, input)
			if err := approve(context.Background(), []string{prodPlan, "-config", cfg}, g); err == nil {
				t.Fatal("approved without the full typed confirmation")
			}
			if rec := planState(t, state, prodPlan); rec.State != model.PlanPending {
				t.Fatalf("state = %s, want pending", rec.State)
			}
		})
	}

	g, out := fakeGate(nil, true, true, "Production\n"+suffix+"\n")
	if err := approve(context.Background(), []string{prodPlan, "--by", "release-manager", "-config", cfg}, g); err != nil {
		t.Fatal(err)
	}
	full := planState(t, state, prodPlan).Plan.Hash
	if !strings.Contains(out.String(), full) {
		t.Errorf("the prompt must show the plan hash on screen:\n%s", out.String())
	}
	rec := planState(t, state, prodPlan)
	if rec.State != model.PlanApproved || rec.Approval.Channel != "tty" || rec.Approval.ConfirmedEnvironment != "Production" {
		t.Fatalf("approval = %+v (state %s)", rec.Approval, rec.State)
	}
	if rec.Approval.OSUser == "" || !rec.Approval.ByClaimed || rec.Approval.By != "release-manager" {
		t.Fatalf("a --by name that is not the OS user must be recorded as claimed: %+v", rec.Approval)
	}

	lg, err := audit.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	if ok, at, err := lg.Verify(); !ok || err != nil {
		t.Fatalf("audit chain broken at %d: %v", at, err)
	}
	entries, err := lg.Entries()
	if err != nil {
		t.Fatal(err)
	}
	last := entries[len(entries)-1]
	var d map[string]any
	if err := last.Decode(&d); err != nil {
		t.Fatal(err)
	}
	if last.Action != audit.ActionApprove || d["channel"] != "tty" || d["claimed_by"] != "release-manager" || d["os_user"] != rec.Approval.OSUser {
		t.Fatalf("audit entry = %s %v", last.Action, d)
	}
	if _, verified := d["by"]; verified {
		t.Fatalf("a claimed name must not be recorded as a verified approver: %v", d)
	}
	refusals := 0
	for _, e := range entries {
		if e.Action == audit.ActionRefuse {
			refusals++
		}
	}
	if refusals == 0 {
		t.Fatal("failed confirmations must be written to the audit log")
	}
}

func TestApproveDevelopmentStillWorksWithConfirm(t *testing.T) {
	cfg, state := workspace(t)
	// No terminal and an agent session: allowed, because Development is not protected.
	g, _ := fakeGate(map[string]string{"CLAUDECODE": "1", "CI": "true"}, false, false, "")
	if err := approve(context.Background(), []string{devPlan, "--confirm", "Staging", "-config", cfg}, g); err == nil {
		t.Fatal("--confirm naming another environment must be rejected")
	}
	if err := approve(context.Background(), []string{devPlan, "--confirm", "Development", "-config", cfg}, g); err != nil {
		t.Fatal(err)
	}
	rec := planState(t, state, devPlan)
	if rec.State != model.PlanApproved || rec.Approval.Channel != "cli" {
		t.Fatalf("approval = %+v (state %s)", rec.Approval, rec.State)
	}
}

func TestFixAllRefusesProtectedPlansWithoutATerminal(t *testing.T) {
	cfg, state := workspace(t)
	// Reject the Development plan so fix-all only has the Production one.
	st, err := fixes.NewStore(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Reject(devPlan, "test", "not part of this test"); err != nil {
		t.Fatal(err)
	}
	for name, g := range map[string]func() *gate{
		"piped stdin": func() *gate {
			g, _ := fakeGate(nil, false, true, "Production\n"+last4(t, state, prodPlan)+"\n")
			return g
		},
		"agent session with a terminal": func() *gate {
			g, _ := fakeGate(map[string]string{"CLAUDECODE": "1"}, true, true, "Production\n"+last4(t, state, prodPlan)+"\n")
			return g
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := fixAll(context.Background(), []string{"-config", cfg}, g())
			wantRefused(t, err, state, prodPlan)
			old := newGate
			newGate = g
			defer func() { newGate = old }()
			if code := run(context.Background(), []string{"fix-all", "-config", cfg}); code == exitOK {
				t.Fatalf("fix-all exit code = %d, want non-zero", code)
			}
		})
	}
}

func TestGateSessionDetection(t *testing.T) {
	g, _ := fakeGate(map[string]string{"CI": ""}, true, true, "")
	if err := g.refusal("Production", false); err != nil {
		t.Fatalf("an empty variable is not an agent session: %v", err)
	}
	if g.channel() != "tty" {
		t.Fatalf("channel = %q, want tty", g.channel())
	}
	g, _ = fakeGate(map[string]string{"GATECRASHER_AGENT": "0"}, true, true, "")
	if err := g.refusal("Production", false); err == nil {
		t.Fatal("any non-empty value marks an agent session")
	}
	if g.channel() != "cli" {
		t.Fatalf("channel = %q, want cli", g.channel())
	}
}
