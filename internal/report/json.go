package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

// WriteJSON writes the canonical report as indented JSON (the schema other
// stages and tools consume). Output is redacted and finalized.
func WriteJSON(w io.Writer, r *model.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(prepare(r)); err != nil {
		return fmt.Errorf("write json report: %w", err)
	}
	return nil
}

// compactFinding is the minimal per-finding record of the compact summary.
type compactFinding struct {
	ID      string `json:"id"`
	Sev     string `json:"sev"`
	Type    string `json:"type"`
	Subject string `json:"subject"`
	Status  string `json:"status"`
	Title   string `json:"title"`
	Fix     string `json:"fix,omitempty"`
	Cause   string `json:"root_cause"`
}

// compactCause is one root cause of the compact summary.
type compactCause struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	FindingIDs  []string `json:"finding_ids"`
	Exploitable bool     `json:"exploitable"`
}

// compactChange is one before/after row of the compact summary.
type compactChange struct {
	ID     string `json:"id"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// compactReport is the token-efficient `--json` summary: no evidence, no
// repro, no explanations, only what an agent needs to decide what to open.
type compactReport struct {
	Schema   string           `json:"schema"`
	ID       string           `json:"id"`
	Env      string           `json:"env,omitempty"`
	AI       string           `json:"ai"`
	WaysIn   int              `json:"ways_in"`
	Found    int              `json:"finding_count"`
	Review   int              `json:"needs_review"`
	Causes   []compactCause   `json:"root_causes"`
	Counts   map[string]int   `json:"counts"`
	Findings []compactFinding `json:"findings"`
	Verified []compactChange  `json:"verified,omitempty"`
	// Requests is the number of requests sent; Incomplete lists the stages
	// the request budget stopped ("incomplete (budget)").
	Requests   int64    `json:"requests"`
	Incomplete []string `json:"incomplete_stages,omitempty"`
}

// WriteCompactJSON writes the minimal machine-readable summary used by every
// CLI `--json` flag: ids, severities, types, subjects, statuses, one-line
// titles and counts, without evidence. Items with status NEEDS_REVIEW are
// AI-only suggestions: they are listed but are in none of the counts.
func WriteCompactJSON(w io.Writer, r *model.Report) error {
	p := prepare(r)
	out := compactReport{
		Schema:   p.SchemaVersion,
		ID:       p.ID,
		Env:      p.Environment,
		AI:       p.AIMode,
		WaysIn:   p.WaysIn,
		Found:    p.FindingCount,
		Review:   p.ReviewCount,
		Causes:   make([]compactCause, 0, len(p.RootCauses)),
		Counts:   p.Stats.BySeverity,
		Findings: make([]compactFinding, 0, len(p.Findings)),
		Requests: p.Stats.ProbesSent, Incomplete: p.Stats.Incomplete,
	}
	for _, f := range p.Findings {
		cf := compactFinding{
			ID:      f.ID,
			Sev:     f.Severity.String(),
			Type:    string(f.Type),
			Subject: f.Subject,
			Status:  string(f.Status),
			Title:   oneLine(headline(f), 120),
			Fix:     f.FixPlanID,
			Cause:   f.RootCause,
		}
		out.Findings = append(out.Findings, cf)
	}
	for _, c := range p.RootCauses {
		out.Causes = append(out.Causes, compactCause{ID: c.ID, Title: oneLine(c.Title, 120), Severity: c.Severity.String(), FindingIDs: c.FindingIDs, Exploitable: c.Exploitable})
	}
	for _, v := range p.BeforeAfter {
		out.Verified = append(out.Verified, compactChange{ID: v.FindingID, Before: string(v.Before), After: string(v.After)})
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("write compact json report: %w", err)
	}
	return nil
}
