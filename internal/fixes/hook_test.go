package fixes

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// hookRepo creates a temp git repo and returns a function that runs the
// pre-commit hook against whatever is staged.
func hookRepo(t *testing.T) (dir string, run func() (string, error)) {
	t.Helper()
	for _, bin := range []string{"sh", "git"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available", bin)
		}
	}
	hook, err := filepath.Abs(filepath.Join("..", "..", ".githooks", "pre-commit"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(hook); err != nil {
		t.Fatal(err)
	}
	dir = t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")
	return dir, func() (string, error) {
		cmd := exec.Command("sh", filepath.ToSlash(hook))
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
}

func stage(t *testing.T, dir, rel, content string) {
	t.Helper()
	writeFile(t, dir, rel, content)
	cmd := exec.Command("git", "add", "-f", rel)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}
}

func TestPreCommitHookBlocksSecretsAndStateFiles(t *testing.T) {
	// Stub credentials are assembled at run time so this file itself passes
	// the hook.
	rep := strings.Repeat
	cases := []struct {
		name, file, content string
	}{
		{"env file", ".env", "A=1\n"},
		{"env local", "cfg/.env.local", "A=1\n"},
		{"state dir", ".gatecrasher/plans/plan-00000001.json", "{}\n"},
		{"lab state", "lab/.state.json", "{}\n"},
		{"server key", "notes.txt", "key = ser." + rep("a1", 12) + "\n"},
		{"org key", "notes.txt", "key=" + rep("AbCdEfGh", 1) + "." + rep("0123456789abcdef", 2) + "\n"},
		{"acme live", "notes.txt", "k: acme_live_" + rep("0123456789abcdef", 2) + "\n"},
		{"anthropic", "notes.txt", "k: sk-ant" + "-api03-" + rep("x", 20) + "\n"},
		{"aws", "notes.txt", "k: AKIA" + rep("A", 16) + "\n"},
		{"github", "notes.txt", "k: ghp" + "_" + rep("a", 36) + "\n"},
		{"pem", "notes.txt", "-----BEGIN " + "RSA PRIVATE KEY-----\nabc\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, run := hookRepo(t)
			stage(t, dir, tc.file, tc.content)
			out, err := run()
			if err == nil {
				t.Fatalf("hook allowed %s; output: %s", tc.name, out)
			}
			if !strings.Contains(out, "blocked") || strings.Contains(out, "0123456789abcdef") || strings.Contains(out, "AKIA"+rep("A", 16)) {
				t.Fatalf("output must name the problem without echoing secrets: %q", out)
			}
		})
	}
}

func TestPreCommitHookAllowsNormalChanges(t *testing.T) {
	dir, run := hookRepo(t)
	stage(t, dir, ".env.example", "GATECRASHER_ORG_API_KEY=\n")
	stage(t, dir, "main.go", "package main\n// user.firstNameAndLastNameOfCustomer\nvar plan = \"ser\"\n")
	stage(t, dir, "docs/readme.md", "Server keys start with `ser.` and org keys look like `XXXXXXXX.<32 chars>`.\n")
	stage(t, dir, "fixture.txt", "ser."+strings.Repeat("a1", 12)+" gatecrasher:allow-secret\n")
	if out, err := run(); err != nil {
		t.Fatalf("hook blocked a clean commit: %v\n%s", err, out)
	}
}
