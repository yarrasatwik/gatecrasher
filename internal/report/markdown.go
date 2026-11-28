package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

// WriteMarkdown writes the report as GitHub-flavoured Markdown.
func WriteMarkdown(w io.Writer, r *model.Report) error {
	p := prepare(r)
	var b strings.Builder
	mdHeader(&b, p)
	mdFindings(&b, p)
	mdReview(&b, p)
	mdSettings(&b, p)
	mdReachability(&b, p)
	mdBeforeAfter(&b, p)
	mdMethod(&b, p)
	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("write markdown report: %w", err)
	}
	return nil
}

func mdHeader(b *strings.Builder, p *model.Report) {
	fmt.Fprintf(b, "# Gatecrasher security report\n\n")
	fmt.Fprintf(b, "**%s** · report `%s` · %s\n\n", HeadlineOf(p.WaysIn, p.FindingCount), p.ID, p.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"))
	var chips []string
	for _, s := range severityOrder() {
		chips = append(chips, fmt.Sprintf("%s %d", s, p.Stats.BySeverity[s.String()]))
	}
	fmt.Fprintf(b, "%s\n\n", strings.Join(chips, " · "))
	fmt.Fprintf(b, "- Target: %s\n- Environment: %s\n- AI mode: %s\n\n", mdInline(p.Target), mdInline(p.Environment), mdInline(p.AIMode))
}

func mdFindings(b *strings.Builder, p *model.Report) {
	b.WriteString("## Findings by root cause\n\n")
	groups := GroupByRootCause(p)
	if len(groups) == 0 {
		b.WriteString("No findings.\n\n")
		return
	}
	b.WriteString("A root cause is one thing to fix. A way in is a root cause that is exploitable now.\n\n")
	for _, g := range groups {
		fmt.Fprintf(b, "### Root cause: %s\n\n", mdInline(g.Cause.Title))
		fmt.Fprintf(b, "`%s` · %s · %s · %s\n\n", g.Cause.ID, strings.ToUpper(g.Cause.Severity.String()), g.Kind, plural(len(g.Findings), "finding"))
		for _, f := range g.Findings {
			mdFinding(b, f)
		}
	}
}

func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// mdFinding writes one finding under its root cause.
func mdFinding(b *strings.Builder, f model.Finding) {
	fmt.Fprintf(b, "#### [%s] %s\n\n", strings.ToUpper(f.Severity.String()), mdInline(headline(f)))
	fmt.Fprintf(b, "`%s` · `%s` · subject `%s` · %s · detected by %s\n\n", f.ID, f.Type, f.Subject, statusWord(f.Status), methods(f))
	mdExplanation(b, f)
	if f.Repro != "" {
		b.WriteString("**Reproduce**\n\n")
		b.WriteString(fence(f.Repro, "sh"))
	}
	for _, e := range f.Evidence {
		mdEvidence(b, e)
	}
	if fx := fixText(f); fx != "" {
		fmt.Fprintf(b, "**Fix:** %s", mdInline(fx))
		if f.FixPlanID != "" {
			fmt.Fprintf(b, " (plan `%s`)", f.FixPlanID)
		}
		b.WriteString("\n\n")
	}
}

// mdReview lists what only the AI suggested, apart from the findings.
func mdReview(b *strings.Builder, p *model.Report) {
	items := reviewItems(p)
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(b, "## Claude suggests reviewing (%d)\n\n%s\n\n", len(items), reviewNote)
	for _, f := range items {
		fmt.Fprintf(b, "- **%s** (`%s` · `%s` · subject `%s`)", mdInline(f.Title), f.ID, f.Type, f.Subject)
		if why := aiReason(f); why != "" {
			fmt.Fprintf(b, " Claude's reason: %s", mdInline(why))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
}

func methods(f model.Finding) string {
	if len(f.DetectedBy) == 0 {
		return "unspecified"
	}
	parts := make([]string, len(f.DetectedBy))
	for i, m := range f.DetectedBy {
		parts[i] = string(m)
	}
	return strings.Join(parts, ", ")
}

func mdExplanation(b *strings.Builder, f model.Finding) {
	e := f.Explanation
	if e == nil {
		if f.Title != "" {
			fmt.Fprintf(b, "%s\n\n", mdInline(f.Title))
		}
		return
	}
	for _, kv := range [][2]string{{"What happened", e.WhatHappened}, {"Why it matters", e.WhyItMatters}, {"Business impact", e.BusinessImpact}} {
		if kv[1] != "" {
			fmt.Fprintf(b, "**%s.** %s\n\n", kv[0], mdInline(kv[1]))
		}
	}
}

func mdEvidence(b *strings.Builder, e model.Evidence) {
	fmt.Fprintf(b, "<details><summary>Evidence: %s</summary>\n\n", mdInline(e.Kind))
	if e.Request != "" {
		b.WriteString("Request\n\n" + fence(e.Request, ""))
	}
	if e.Response != "" {
		b.WriteString("Response\n\n" + fence(e.Response, ""))
	}
	if e.Note != "" {
		fmt.Fprintf(b, "%s\n\n", mdInline(e.Note))
	}
	b.WriteString("</details>\n\n")
}

func mdSettings(b *strings.Builder, p *model.Report) {
	b.WriteString("## Environment security settings\n\n")
	if len(p.Settings) == 0 {
		b.WriteString("No settings were read.\n\n")
		return
	}
	b.WriteString("| Environment | Client traits | Sensitive data hidden | Server-only flags | Client-visible flags |\n|---|---|---|---|---|\n")
	for _, s := range p.Settings {
		tm, tw := tri(s.AllowClientTraits, false, "Allowed", "Blocked")
		hm, hw := tri(s.HideSensitiveData, true, "Hidden", "Visible")
		fmt.Fprintf(b, "| %s | %s %s | %s %s | %d | %d |\n", mdCell(s.Environment), tm, tw, hm, hw, len(s.ServerOnlyFlags), len(s.ClientVisible))
	}
	b.WriteString("\n")
}

func mdReachability(b *strings.Builder, p *model.Report) {
	b.WriteString("## Reachability map\n\n")
	if len(p.Reachability) == 0 {
		b.WriteString("No reachable states were mapped.\n\n")
		return
	}
	b.WriteString("| Flag | Reachable value | Via | Engine-verified | Live-verified |\n|---|---|---|---|---|\n")
	for _, r := range p.Reachability {
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s |\n", mdCell(r.Flag), mdCell(reachValue(r)), mdCell(reachVia(r)), yesNo(r.EngineVerified), liveWord(r.LiveVerified))
	}
	b.WriteString("\n")
}

func reachValue(r model.Reachable) string {
	state := "disabled"
	if r.Enabled {
		state = "enabled"
	}
	if r.Value != "" {
		return state + ", value " + r.Value
	}
	return state
}

func mdBeforeAfter(b *strings.Builder, p *model.Report) {
	if len(p.BeforeAfter) == 0 {
		return
	}
	b.WriteString("## Before and after\n\n| Finding | Before | After | Proof |\n|---|---|---|---|\n")
	for _, v := range p.BeforeAfter {
		fmt.Fprintf(b, "| %s (`%s`) | %s | %s | %s |\n", mdCell(v.Title), v.FindingID, statusWord(v.Before), statusWord(v.After), mdCell(v.Proof))
	}
	b.WriteString("\n")
}

func mdMethod(b *strings.Builder, p *model.Report) {
	b.WriteString("## Method and scope\n\n")
	b.WriteString("Scope (the only hosts contacted):\n\n")
	for _, s := range p.Scope {
		fmt.Fprintf(b, "- `%s`\n", s)
	}
	fmt.Fprintf(b, "\n- Probes sent: %d\n- Duration: %s\n", p.Stats.ProbesSent, humanDuration(p.Stats.DurationMS))
	stages := make([]string, 0, len(p.Stats.StageMS))
	for k := range p.Stats.StageMS {
		stages = append(stages, k)
	}
	sort.Strings(stages)
	for _, k := range stages {
		fmt.Fprintf(b, "  - %s: %s\n", k, humanDuration(p.Stats.StageMS[k]))
	}
	if p.Stats.ParityChecked > 0 {
		fmt.Fprintf(b, "- Engine parity: %d/%d\n", p.Stats.ParityAgreed, p.Stats.ParityChecked)
	}
	fmt.Fprintf(b, "- Engine: %s\n- Tool: %s %s\n", engineVersion(), p.Tool, p.Version)
	for _, n := range p.Notes {
		fmt.Fprintf(b, "- Note: %s\n", mdInline(n))
	}
}

// fence wraps text in a code fence long enough not to be closed by its content.
func fence(text, lang string) string {
	ticks := "```"
	for strings.Contains(text, ticks) {
		ticks += "`"
	}
	return ticks + lang + "\n" + strings.TrimRight(text, "\n") + "\n" + ticks + "\n\n"
}

// mdInline neutralises line breaks in inline text.
func mdInline(s string) string { return strings.Join(strings.Fields(s), " ") }

// mdCell makes s safe inside a table cell.
func mdCell(s string) string {
	return strings.ReplaceAll(mdInline(s), "|", "\\|")
}
