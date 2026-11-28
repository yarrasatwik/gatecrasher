package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/report/reporttest"
)

func TestBudgetStopIsShownInEveryReportFormat(t *testing.T) {
	r := reporttest.SampleReport()
	r.Stats.ProbesSent = 50
	r.Stats.Budget = 50
	r.Stats.Incomplete = []string{"map", "verify", "parity"}
	r.Stats.StageRequests = map[string]int64{"recon": 5, "attack": 45}

	md := render(t, func(b *bytes.Buffer) error { return WriteMarkdown(b, r) })
	for _, want := range []string{"incomplete (budget)", "map, verify, parity", "Request budget: 50 of 50 used", "attack: 45 requests"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q", want)
		}
	}

	h := render(t, func(b *bytes.Buffer) error { return WriteHTML(b, r) })
	for _, want := range []string{"incomplete (budget)", "map, verify, parity", "50 of 50 used"} {
		if !strings.Contains(h, want) {
			t.Errorf("html lacks %q", want)
		}
	}

	var js bytes.Buffer
	if err := WriteJSON(&js, r); err != nil {
		t.Fatal(err)
	}
	var back struct {
		Stats struct {
			Budget     int64    `json:"request_budget"`
			Incomplete []string `json:"incomplete_stages"`
			Probes     int64    `json:"probes_sent"`
		} `json:"stats"`
	}
	if err := json.Unmarshal(js.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if back.Stats.Budget != 50 || len(back.Stats.Incomplete) != 3 || back.Stats.Probes != 50 {
		t.Fatalf("json stats = %+v", back.Stats)
	}
}

func TestCompleteRunShowsNoIncompleteNotice(t *testing.T) {
	r := reporttest.SampleReport()
	md := render(t, func(b *bytes.Buffer) error { return WriteMarkdown(b, r) })
	h := render(t, func(b *bytes.Buffer) error { return WriteHTML(b, r) })
	if strings.Contains(md, "incomplete (budget)") || strings.Contains(h, "incomplete (budget)") {
		t.Fatal("a complete run must not claim to be incomplete")
	}
}

func TestIncompleteNote(t *testing.T) {
	r := reporttest.SampleReport()
	if IncompleteNote(r) != "" {
		t.Fatal("note for a complete report")
	}
	r.Stats.Incomplete = []string{"recon"}
	got := IncompleteNote(r)
	if !strings.Contains(got, "incomplete (budget): recon") || !strings.Contains(got, "not reported as safe") {
		t.Fatalf("note = %q", got)
	}
}
