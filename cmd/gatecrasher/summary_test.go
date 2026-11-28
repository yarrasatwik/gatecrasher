package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/app"
	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/report"
)

// The CLI headline shows both numbers, and they are the numbers in the JSON
// report: ways_in (exploitable root causes) and finding_count.
func TestCLIHeadlineMatchesJSON(t *testing.T) {
	raw, err := os.ReadFile("../../examples/acme-shop/report.json")
	if err != nil {
		t.Fatal(err)
	}
	var r model.Report
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	app.AssignRootCauses(&r)

	var full, compact bytes.Buffer
	if err := report.WriteJSON(&full, &r); err != nil {
		t.Fatal(err)
	}
	if err := report.WriteCompactJSON(&compact, &r); err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string][]byte{"report JSON": full.Bytes(), "--json": compact.Bytes()} {
		var got struct {
			WaysIn       *int `json:"ways_in"`
			FindingCount *int `json:"finding_count"`
			RootCauses   []struct {
				Exploitable bool `json:"exploitable"`
			} `json:"root_causes"`
		}
		if err := json.Unmarshal(doc, &got); err != nil {
			t.Fatal(err)
		}
		if got.WaysIn == nil || got.FindingCount == nil {
			t.Fatalf("%s lacks ways_in or finding_count", name)
		}
		exploitable := 0
		for _, c := range got.RootCauses {
			if c.Exploitable {
				exploitable++
			}
		}
		if exploitable != *got.WaysIn {
			t.Fatalf("%s: ways_in %d but %d exploitable root causes", name, *got.WaysIn, exploitable)
		}
		want := fmt.Sprintf("%d ways in · %d findings", *got.WaysIn, *got.FindingCount)
		out := summaryText(&r, nil)
		if !strings.Contains(out, want) {
			t.Fatalf("CLI summary lacks the headline %q matching the %s:\n%s", want, name, out)
		}
	}
	out := summaryText(&r, nil)
	if !strings.Contains(out, "3 ways in · 17 findings") {
		t.Fatalf("recorded lab report headline wrong:\n%s", out)
	}
	for _, want := range []string{"Production lets clients set traits", "payment_config is served to browsers and contains a live secret", "way in"} {
		if !strings.Contains(out, want) {
			t.Errorf("CLI summary does not group under root cause %q", want)
		}
	}
}
