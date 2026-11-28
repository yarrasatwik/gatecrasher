package report

import (
	"bytes"
	"encoding/json"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
	"github.com/yarrasatwik/gatecrasher/internal/report/reporttest"
)

func render(t *testing.T, w func(*bytes.Buffer) error) string {
	t.Helper()
	var buf bytes.Buffer
	if err := w(&buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	return buf.String()
}

func TestSampleCoversEveryFindingType(t *testing.T) {
	seen := map[model.FindingType]bool{}
	for _, f := range reporttest.SampleReport().Findings {
		seen[f.Type] = true
	}
	for _, c := range catalog {
		if !seen[c.Type] {
			t.Errorf("sample report lacks finding type %s", c.Type)
		}
	}
}

func TestFinalize(t *testing.T) {
	r := reporttest.SampleReport()
	r.SchemaVersion, r.Tool = "", ""
	r.Findings[0], r.Findings[len(r.Findings)-1] = r.Findings[len(r.Findings)-1], r.Findings[0]
	Finalize(r)
	if r.SchemaVersion != model.SchemaVersion || r.Tool != ToolName {
		t.Fatalf("schema/tool = %q/%q", r.SchemaVersion, r.Tool)
	}
	for i := 1; i < len(r.Findings); i++ {
		if r.Findings[i-1].Severity < r.Findings[i].Severity {
			t.Fatalf("findings not sorted by severity at %d", i)
		}
	}
	total := 0
	for _, s := range []string{"info", "low", "medium", "high", "critical"} {
		n, ok := r.Stats.BySeverity[s]
		if !ok {
			t.Errorf("BySeverity missing %q", s)
		}
		total += n
	}
	if total != len(r.Findings) {
		t.Fatalf("BySeverity sums to %d, want %d", total, len(r.Findings))
	}
	if r.Stats.BySeverity["critical"] != 2 {
		t.Errorf("critical = %d, want 2", r.Stats.BySeverity["critical"])
	}
}

func TestWaysIn(t *testing.T) {
	r := reporttest.SampleReport()
	want := len(r.Findings) - 1 // CONTROL_OK is not a way in
	if got := WaysIn(r); got != want {
		t.Fatalf("WaysIn = %d, want %d", got, want)
	}
}

func TestWriteJSONRoundTrip(t *testing.T) {
	r := reporttest.SampleReport()
	out := render(t, func(b *bytes.Buffer) error { return WriteJSON(b, r) })
	var back model.Report
	if err := json.Unmarshal([]byte(out), &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.ID != r.ID || len(back.Findings) != len(r.Findings) || back.SchemaVersion != model.SchemaVersion {
		t.Fatalf("round trip lost data: %+v", back.ID)
	}
	if !strings.Contains(out, "\n  \"findings\"") {
		t.Fatal("output is not indented")
	}
	if strings.Contains(out, "RawValue") {
		t.Fatal("raw values must never be serialised")
	}
}

func TestWriteCompactJSON(t *testing.T) {
	r := reporttest.SampleReport()
	full := render(t, func(b *bytes.Buffer) error { return WriteJSON(b, r) })
	out := render(t, func(b *bytes.Buffer) error { return WriteCompactJSON(b, r) })
	if len(out)*4 > len(full) {
		t.Errorf("compact output %d bytes is not much smaller than full %d", len(out), len(full))
	}
	for _, banned := range []string{"evidence", "repro", "curl", "what_happened"} {
		if strings.Contains(out, banned) {
			t.Errorf("compact output contains %q", banned)
		}
	}
	var got struct {
		ID       string         `json:"id"`
		WaysIn   int            `json:"ways_in"`
		Counts   map[string]int `json:"counts"`
		Findings []struct {
			ID, Sev, Type, Subject, Status, Title string
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ID != r.ID || got.WaysIn != WaysIn(r) || len(got.Findings) != len(r.Findings) {
		t.Fatalf("unexpected summary: %+v", got)
	}
	first := got.Findings[0]
	if first.Sev != "critical" || first.ID == "" || first.Type == "" || first.Subject == "" || first.Status == "" || first.Title == "" {
		t.Fatalf("first finding incomplete: %+v", first)
	}
	if got.Counts["critical"] != 2 {
		t.Errorf("counts = %v", got.Counts)
	}
	if strings.Contains(strings.TrimSpace(out), "\n") {
		t.Error("compact output must be a single line")
	}
}

func TestWriteMarkdown(t *testing.T) {
	r := reporttest.SampleReport()
	out := render(t, func(b *bytes.Buffer) error { return WriteMarkdown(b, r) })
	for _, want := range []string{
		"# Gatecrasher security report",
		"**17 ways in**",
		"## Findings",
		"### [CRITICAL] A live payment key is public",
		"curl -s -H 'X-Environment-Key: <CLIENT_KEY>'",
		"<details><summary>Evidence: request</summary>",
		"## Environment security settings",
		"✗ Allowed",
		"✓ Blocked",
		"## Reachability map",
		"## Before and after",
		"✓ BLOCKED",
		"## Method and scope",
		"Engine parity: 12/12",
		"plan `plan-0001`",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	for _, f := range r.Findings {
		if !strings.Contains(out, f.ID) {
			t.Errorf("markdown missing finding %s", f.ID)
		}
	}
}

func TestMarkdownFenceAndCell(t *testing.T) {
	if got := fence("a ``` b", "sh"); !strings.HasPrefix(got, "````sh\n") {
		t.Errorf("fence did not lengthen: %q", got)
	}
	if got := mdCell("a|b\nc"); got != `a\|b c` {
		t.Errorf("mdCell = %q", got)
	}
}

func TestWriteHTML(t *testing.T) {
	r := reporttest.SampleReport()
	out := render(t, func(b *bytes.Buffer) error { return WriteHTML(b, r) })

	for _, want := range []string{
		"<!doctype html>", `<html lang="en">`, `name="viewport"`, "prefers-color-scheme: dark",
		"<main", "<nav", "<header", "<footer", `class="skip"`, ":focus-visible",
		`<span class="n">17</span>`, "ways in",
		"Findings, ranked by severity", "Environment security settings", "Reachability map",
		"Before and after", "Method and scope",
		"&lt;CLIENT_KEY&gt;", "<details>", "live-probe", "flagsmith-engine", "ai", "deterministic",
		`href="/plans#plan-0001"`, "✗ Allowed", "✓ Blocked", "12/12 probes agree",
		"web/src/features/admin.js:42", "@media print",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("html missing %q", want)
		}
	}
	for _, f := range r.Findings {
		if !strings.Contains(out, `id="`+f.ID+`"`) {
			t.Errorf("html missing card for %s", f.ID)
		}
	}
	assertSelfContained(t, out)
	assertHeadingOrder(t, out)
	assertSectionOrder(t, out)
}

func assertSelfContained(t *testing.T, out string) {
	t.Helper()
	for _, banned := range []string{`src="http`, `href="http`, "url(http", "@import", "<link ", "<img "} {
		if strings.Contains(out, banned) {
			t.Errorf("html is not self-contained: found %q", banned)
		}
	}
	if n := strings.Count(out, "<script"); n != 1 {
		t.Errorf("want exactly one inline script, got %d", n)
	}
}

func assertHeadingOrder(t *testing.T, out string) {
	t.Helper()
	level := 0
	for _, m := range regexp.MustCompile(`<h([1-6])[ >]`).FindAllStringSubmatch(out, -1) {
		n := int(m[1][0] - '0')
		if level != 0 && n > level+1 {
			t.Errorf("heading level jumps from h%d to h%d", level, n)
		}
		level = n
	}
}

func assertSectionOrder(t *testing.T, out string) {
	t.Helper()
	last := -1
	for _, id := range []string{`id="summary"`, `id="findings"`, `id="settings"`, `id="reachability"`, `id="before-after"`, `id="method"`} {
		i := strings.Index(out, id)
		if i < 0 || i < last {
			t.Errorf("section %s missing or out of order", id)
		}
		last = i
	}
}

func TestHTMLEscapesEverything(t *testing.T) {
	r := reporttest.SampleReport()
	payload := `<script>alert(1)</script>`
	r.Project = payload
	r.Findings[0].Title = payload
	r.Findings[0].Subject = payload
	r.Findings[0].Explanation = nil
	r.Findings[0].Repro = payload
	r.Findings[0].Evidence[0].Response = payload
	r.Settings[0].Environment = payload
	out := render(t, func(b *bytes.Buffer) error { return WriteHTML(b, r) })
	if strings.Contains(out, payload) {
		t.Fatal("unescaped payload in html output")
	}
	if n := strings.Count(out, "<script"); n != 1 {
		t.Fatalf("injected script tag: %d script tags", n)
	}
}

func TestHTMLMinimalReport(t *testing.T) {
	r := &model.Report{ID: "empty", AIMode: "off (heuristics)"}
	out := render(t, func(b *bytes.Buffer) error { return WriteHTML(b, r) })
	for _, want := range []string{`<span class="n">0</span>`, "No findings.", "No environment settings were read.", "No reachable states were mapped."} {
		if !strings.Contains(out, want) {
			t.Errorf("minimal html missing %q", want)
		}
	}
	if strings.Contains(out, `id="before-after"`) {
		t.Error("before/after section should be omitted when empty")
	}
}

func TestWriteSARIFStructure(t *testing.T) {
	r := reporttest.SampleReport()
	out := render(t, func(b *bytes.Buffer) error { return WriteSARIF(b, r) })
	var log struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID               string                          `json:"id"`
						Name             string                          `json:"name"`
						ShortDescription struct{ Text string }           `json:"shortDescription"`
						FullDescription  struct{ Text string }           `json:"fullDescription"`
						Help             struct{ Text, Markdown string } `json:"help"`
						Default          struct{ Level string }          `json:"defaultConfiguration"`
						Properties       map[string]any                  `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID       string                `json:"ruleId"`
				RuleIndex    int                   `json:"ruleIndex"`
				Level        string                `json:"level"`
				Message      struct{ Text string } `json:"message"`
				Fingerprints map[string]string     `json:"partialFingerprints"`
				Locations    []struct {
					Physical struct {
						Artifact struct{ URI string }    `json:"artifactLocation"`
						Region   struct{ StartLine int } `json:"region"`
					} `json:"physicalLocation"`
					Logical []struct{ Name, Kind string } `json:"logicalLocations"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &log); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if log.Version != "2.1.0" || !strings.Contains(log.Schema, "sarif-2.1.0") || len(log.Runs) != 1 {
		t.Fatalf("bad envelope: %q %q runs=%d", log.Version, log.Schema, len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "Gatecrasher" {
		t.Errorf("driver = %q", run.Tool.Driver.Name)
	}
	if len(run.Tool.Driver.Rules) != len(catalog) {
		t.Fatalf("rules = %d, want %d", len(run.Tool.Driver.Rules), len(catalog))
	}
	scores := map[string]bool{"9.5": true, "8.0": true, "5.5": true, "3.0": true, "0.0": true}
	for _, rule := range run.Tool.Driver.Rules {
		if rule.ID == "" || rule.Name == "" || rule.ShortDescription.Text == "" || rule.FullDescription.Text == "" || rule.Help.Markdown == "" {
			t.Errorf("rule %q incomplete", rule.ID)
		}
		if s, _ := rule.Properties["security-severity"].(string); !scores[s] {
			t.Errorf("rule %s security-severity = %v", rule.ID, rule.Properties["security-severity"])
		}
		if l := rule.Default.Level; l != "error" && l != "warning" && l != "note" {
			t.Errorf("rule %s level %q", rule.ID, l)
		}
	}
	if len(run.Results) != len(r.Findings)-1 {
		t.Fatalf("results = %d, want %d (CONTROL_OK omitted)", len(run.Results), len(r.Findings)-1)
	}
	byID := map[string]string{}
	for _, f := range r.Findings {
		byID[f.ID] = f.Subject
	}
	var sawImpact, sawFallback bool
	for _, res := range run.Results {
		rule := run.Tool.Driver.Rules[res.RuleIndex]
		if rule.ID != res.RuleID {
			t.Errorf("ruleIndex %d points at %s, result is %s", res.RuleIndex, rule.ID, res.RuleID)
		}
		if res.Message.Text == "" || res.Level == "" {
			t.Errorf("result %s lacks message/level", res.RuleID)
		}
		id := res.Fingerprints["gatecrasherFindingId/v1"]
		if _, ok := byID[id]; !ok {
			t.Errorf("unknown fingerprint %q", id)
		}
		if len(res.Locations) == 0 {
			t.Fatalf("result %s has no locations", res.RuleID)
		}
		for _, loc := range res.Locations {
			uri := loc.Physical.Artifact.URI
			if uri == "" || strings.HasPrefix(uri, "/") || strings.Contains(uri, "://") || strings.Contains(uri, "..") || strings.Contains(uri, "\\") {
				t.Errorf("bad artifact uri %q", uri)
			}
			if loc.Physical.Region.StartLine < 1 {
				t.Errorf("startLine %d < 1", loc.Physical.Region.StartLine)
			}
			if len(loc.Logical) != 1 || loc.Logical[0].Kind != "member" || loc.Logical[0].Name != byID[id] {
				t.Errorf("logical location = %+v, want member %q", loc.Logical, byID[id])
			}
			switch uri {
			case "web/src/features/admin.js":
				sawImpact = loc.Physical.Region.StartLine == 42
			case "web/src/export.js":
				sawFallback = loc.Physical.Region.StartLine == 7
			}
		}
	}
	if !sawImpact || !sawFallback {
		t.Errorf("impact locations not mapped (admin=%v export=%v)", sawImpact, sawFallback)
	}
	if !strings.Contains(out, "flagsmith/Production/payments_config") {
		t.Error("missing pseudo-file fallback location")
	}
}

func TestSARIFSeverityMapping(t *testing.T) {
	tests := []struct {
		sev   model.Severity
		score string
		level string
	}{
		{model.SevCritical, "9.5", "error"},
		{model.SevHigh, "8.0", "error"},
		{model.SevMedium, "5.5", "warning"},
		{model.SevLow, "3.0", "note"},
		{model.SevInfo, "0.0", "note"},
	}
	for _, tc := range tests {
		if got := securityScore(tc.sev); got != tc.score {
			t.Errorf("%s score = %s, want %s", tc.sev, got, tc.score)
		}
		if got := sarifLevel(tc.sev); got != tc.level {
			t.Errorf("%s level = %s, want %s", tc.sev, got, tc.level)
		}
	}
}

func TestSARIFOmitsBlockedAndHandlesUnknownType(t *testing.T) {
	r := reporttest.SampleReport()
	r.Findings[0].Status = model.StatusBlocked
	r.Findings = append(r.Findings, model.Finding{ID: "GC-NEW", Type: "BRAND_NEW", Subject: "x y", Severity: model.SevLow, Status: model.StatusExploitable, Title: "new"})
	out := render(t, func(b *bytes.Buffer) error { return WriteSARIF(b, r) })
	if strings.Contains(out, r.Findings[0].ID) {
		t.Error("blocked finding must not be a SARIF result")
	}
	if !strings.Contains(out, `"ruleId": "BRAND_NEW"`) || !strings.Contains(out, "flagsmith/Production/x%20y") {
		t.Error("unknown type not rendered with rule and escaped fallback uri")
	}
}

func TestImpactLocations(t *testing.T) {
	f := model.Finding{
		Notes:    []string{"impact: a/b.js:3", "impact: ./c.js:9", "impact: /abs.js:1", "impact: ../up.js:2", "impact: d.js:0", "impact: a\\w.js:5", "unrelated"},
		Evidence: []model.Evidence{{Note: "impact: a/b.js:3"}},
	}
	got := impactLocations(f)
	want := []codeLocation{{"a/b.js", 3}, {"c.js", 9}, {"a/w.js", 5}}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("loc %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestRedactionSafetyNet(t *testing.T) {
	redact.Reset()
	t.Cleanup(redact.Reset)
	const key = "zq9-SAMPLE-CLIENT-KEY-77"
	const secret = "p&ss<w0rd>-SAMPLE-SECRET"
	redact.Register(key, "CLIENT_KEY")
	redact.Register(secret, "SECRET")

	r := reporttest.SampleReport()
	r.Target = "http://localhost:3000/?k=" + key
	r.Notes = append(r.Notes, "leaked "+secret)
	r.Inventory.KeyFingerprint = key
	r.Inventory.Key = key
	r.Inventory.Flags[0].Preview = secret
	r.Reachability[0].Value = secret
	r.BeforeAfter[0].Proof = key
	f := &r.Findings[0]
	f.Title = "title " + key
	f.Subject = "subject-" + secret
	f.Repro = "curl -H 'X-Environment-Key: " + key + "' --data " + secret
	f.Evidence = []model.Evidence{{Kind: "request", Request: "GET " + key, Response: secret, Note: key + secret}}
	f.Explanation.WhatHappened = secret
	f.Explanation.FixSummary = key
	f.Notes = []string{"impact: " + key + ".js:3"}
	f.Traits = map[string]string{"k": secret, key: "v"}
	f.FixPlanID = key

	outputs := map[string]string{
		"json":    render(t, func(b *bytes.Buffer) error { return WriteJSON(b, r) }),
		"compact": render(t, func(b *bytes.Buffer) error { return WriteCompactJSON(b, r) }),
		"md":      render(t, func(b *bytes.Buffer) error { return WriteMarkdown(b, r) }),
		"html":    render(t, func(b *bytes.Buffer) error { return WriteHTML(b, r) }),
		"sarif":   render(t, func(b *bytes.Buffer) error { return WriteSARIF(b, r) }),
	}
	for name, out := range outputs {
		for _, leaked := range []string{key, secret, html.EscapeString(secret), strings.ReplaceAll(secret, "&", `&`)} {
			if strings.Contains(out, leaked) {
				t.Errorf("%s output leaks %q", name, leaked)
			}
		}
	}
	if !strings.Contains(r.Findings[0].Title, key) {
		t.Error("writers must not mutate the caller's report")
	}
}

func TestWriteAll(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reports")
	r := reporttest.SampleReport()
	paths, err := WriteAll(dir, r)
	if err != nil {
		t.Fatalf("WriteAll: %v", err)
	}
	if len(paths) != 8 {
		t.Fatalf("wrote %d files, want 8", len(paths))
	}
	for _, ext := range []string{"json", "md", "html", "sarif"} {
		latest, err := os.ReadFile(filepath.Join(dir, "latest."+ext))
		if err != nil {
			t.Fatalf("latest.%s: %v", ext, err)
		}
		copyOf, err := os.ReadFile(filepath.Join(dir, r.ID+"."+ext))
		if err != nil {
			t.Fatalf("%s.%s: %v", r.ID, ext, err)
		}
		if len(latest) == 0 || !bytes.Equal(latest, copyOf) {
			t.Errorf("latest.%s and %s.%s differ or are empty", ext, r.ID, ext)
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".report-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestWriteAllSanitisesID(t *testing.T) {
	dir := t.TempDir()
	r := reporttest.SampleReport()
	r.ID = "../evil id"
	if _, err := WriteAll(dir, r); err != nil {
		t.Fatalf("WriteAll: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "_evil_id.json")); err != nil {
		t.Fatalf("sanitised copy missing: %v", err)
	}
}
