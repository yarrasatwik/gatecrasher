package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/report/reporttest"
)

// dryRun runs `gatecrasher audit <args> --dry-run` against a server that
// counts every request, and returns what the command printed.
func dryRun(t *testing.T, extra ...string) (out string, hits int64, err error) {
	t.Helper()
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { n.Add(1) }))
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")
	dir := t.TempDir()
	cfg := fmt.Sprintf("target_url: %s\nflagsmith:\n  api_url: %s/api/v1/\n  allowed_api_hosts: [%q]\n  project: Acme Shop\nstate_dir: %s\nreport_dir: %s\n",
		srv.URL, srv.URL, host, filepath.Join(dir, "state"), filepath.Join(dir, "reports"))
	p := filepath.Join(dir, "g.yaml")
	if werr := os.WriteFile(p, []byte(cfg), 0o600); werr != nil {
		t.Fatal(werr)
	}
	t.Setenv("GATECRASHER_ORG_API_KEY", "orgkey.abcdefghijklmnopqrstuvwxyz012345")
	t.Setenv("GATECRASHER_API_URL", "")
	t.Setenv("GATECRASHER_TARGET_URL", "")
	old := os.Stdout
	rd, wr, _ := os.Pipe()
	os.Stdout = wr
	done := make(chan string)
	go func() { b, _ := io.ReadAll(rd); done <- string(b) }()
	args := append([]string{"--config", p, "--dry-run"}, extra...)
	err = cmdAudit(context.Background(), args)
	wr.Close()
	os.Stdout = old
	return <-done, n.Load(), err
}

func TestAuditDryRunPrintsTheEstimateAndSendsNothing(t *testing.T) {
	out, hits, err := dryRun(t)
	if err != nil {
		t.Fatal(err)
	}
	if hits != 0 {
		t.Fatalf("--dry-run sent %d requests", hits)
	}
	for _, want := range []string{"estimated requests", "profile lab", "parity 1000", "recon", "attack", "map", "verify", "parity", "total", "no budget"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestAuditDryRunHonoursProfileAndBudget(t *testing.T) {
	out, hits, err := dryRun(t, "--profile", "cloud", "--budget", "50")
	if err != nil {
		t.Fatal(err)
	}
	if hits != 0 {
		t.Fatalf("sent %d requests", hits)
	}
	for _, want := range []string{"profile cloud", "parity 200", "re-roll 100", "budget 50", "incomplete (budget)"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestAuditDryRunJSON(t *testing.T) {
	out, _, err := dryRun(t, "--json", "--parity", "40")
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		DryRun bool   `json:"dry_run"`
		Total  int    `json:"total"`
		Prof   string `json:"profile"`
		Stages []struct {
			Stage    string `json:"stage"`
			Requests int    `json:"requests"`
		} `json:"stages"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v in %q", err, out)
	}
	sum := 0
	parity := 0
	for _, s := range got.Stages {
		sum += s.Requests
		if s.Stage == "parity" {
			parity = s.Requests
		}
	}
	if !got.DryRun || got.Total != sum || got.Total == 0 || parity != 40 || got.Prof != "lab" {
		t.Fatalf("estimate json = %+v (%s)", got, out)
	}
}

func TestAuditRejectsBadBudgetAndProfile(t *testing.T) {
	if _, _, err := dryRun(t, "--budget", "-3"); err == nil {
		t.Fatal("negative budget accepted")
	}
	if _, _, err := dryRun(t, "--profile", "staging"); err == nil {
		t.Fatal("unknown profile accepted")
	}
}

func TestSummaryNeverCallsAnIncompleteRunSafe(t *testing.T) {
	r := reporttest.SampleReport()
	r.Findings = nil
	r.RootCauses = nil
	r.Stats.ProbesSent, r.Stats.Budget = 50, 50
	r.Stats.Incomplete = []string{"map", "parity"}
	out := summaryText(r, nil)
	if strings.Contains(out, "no exploitable root cause") {
		t.Fatalf("an incomplete run reads as safe:\n%s", out)
	}
	for _, want := range []string{"incomplete (budget)", "map, parity", "50 of 50 requests"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}
	r.Stats.Incomplete, r.Stats.Budget = nil, 0
	if !strings.Contains(summaryText(r, nil), "no exploitable root cause") {
		t.Fatal("a complete clean run should still say so")
	}
}
