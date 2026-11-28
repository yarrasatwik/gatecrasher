package report

import (
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

var pageTmpl = template.Must(template.New("report").Parse(htmlTemplate))

type chipView struct {
	Name  string
	Class string
	Count int
}

type paragraphView struct{ Label, Text string }

type findingView struct {
	model.Finding
	SevName     string
	SevClass    string
	Headline    string
	StatusWord  string
	StatusClass string
	Methods     []string
	Paragraphs  []paragraphView
	Fix         string
	Locations   []string
}

// groupView is one root cause with its finding cards.
type groupView struct {
	ID, Title, SevName, SevClass, Kind, Count string
	Findings                                  []findingView
}

// reviewView is one AI-only suggestion.
type reviewView struct {
	ID, Title, Type, Subject, Reason string
}

type settingView struct {
	Environment, Traits, TraitsClass, Hidden, HiddenClass string
	ServerOnly, ClientVisible                             int
}

type reachView struct {
	Flag, Value, Via, Engine, EngineClass, Live, LiveClass string
}

type changeView struct {
	ID, Title, Before, BeforeClass, After, AfterClass, Proof string
}

type htmlView struct {
	R              *model.Report
	WaysIn         int
	FindingCount   int
	Groups         []groupView
	Chips          []chipView
	Findings       []findingView
	Review         []reviewView
	ReviewNote     string
	Settings       []settingView
	Reach          []reachView
	BeforeAfter    []changeView
	Duration       string
	Stages         []string
	Parity         string
	AgreeText      string
	EngineVersion  string
	Generated      string
	GeneratedHuman string
}

// WriteHTML writes the report as one self-contained HTML file: inline CSS,
// no external requests, light and dark themes, and print styles.
func WriteHTML(w io.Writer, r *model.Report) error {
	p := prepare(r)
	if err := pageTmpl.Execute(w, buildHTMLView(p)); err != nil {
		return fmt.Errorf("write html report: %w", err)
	}
	return nil
}

func buildHTMLView(p *model.Report) htmlView {
	v := htmlView{
		R:              p,
		WaysIn:         p.WaysIn,
		FindingCount:   p.FindingCount,
		Duration:       humanDuration(p.Stats.DurationMS),
		EngineVersion:  engineVersion(),
		Generated:      p.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		GeneratedHuman: p.CreatedAt.UTC().Format("2 Jan 2006, 15:04 UTC"),
	}
	for _, s := range severityOrder() {
		v.Chips = append(v.Chips, chipView{Name: titleCase(s.String()), Class: s.String(), Count: p.Stats.BySeverity[s.String()]})
	}
	for _, f := range p.Findings {
		if f.Status == model.StatusNeedsReview {
			v.Review = append(v.Review, reviewView{ID: f.ID, Title: f.Title, Type: string(f.Type), Subject: f.Subject, Reason: aiReason(f)})
			continue
		}
		v.Findings = append(v.Findings, buildFindingView(f))
	}
	v.ReviewNote = reviewNote
	for _, g := range GroupByRootCause(p) {
		gv := groupView{ID: g.Cause.ID, Title: g.Cause.Title, SevName: titleCase(g.Cause.Severity.String()),
			SevClass: g.Cause.Severity.String(), Kind: g.Kind, Count: plural(len(g.Findings), "finding")}
		for _, f := range g.Findings {
			gv.Findings = append(gv.Findings, buildFindingView(f))
		}
		v.Groups = append(v.Groups, gv)
	}
	for _, s := range p.Settings {
		v.Settings = append(v.Settings, buildSettingView(s))
	}
	for _, rc := range p.Reachability {
		v.Reach = append(v.Reach, buildReachView(rc))
	}
	for _, row := range p.BeforeAfter {
		v.BeforeAfter = append(v.BeforeAfter, changeView{
			ID: row.FindingID, Title: row.Title, Proof: row.Proof,
			Before: statusWord(row.Before), BeforeClass: statusClass(row.Before),
			After: statusWord(row.After), AfterClass: statusClass(row.After),
		})
	}
	v.Stages = stageLabels(p.Stats.StageMS)
	if p.Stats.ParityChecked > 0 {
		v.Parity = fmt.Sprintf("%d/%d probes agree with the engine", p.Stats.ParityAgreed, p.Stats.ParityChecked)
	}
	if p.Stats.AIHeuristicAgree != nil {
		v.AgreeText = fmt.Sprintf("%.0f%%", *p.Stats.AIHeuristicAgree*100)
	}
	return v
}

func buildFindingView(f model.Finding) findingView {
	fv := findingView{
		Finding:     f,
		SevName:     titleCase(f.Severity.String()),
		SevClass:    f.Severity.String(),
		Headline:    headline(f),
		StatusWord:  statusWord(f.Status),
		StatusClass: statusClass(f.Status),
		Fix:         fixText(f),
	}
	for _, m := range f.DetectedBy {
		fv.Methods = append(fv.Methods, string(m))
	}
	fv.Paragraphs = paragraphs(f)
	for _, c := range impactLocations(f) {
		fv.Locations = append(fv.Locations, fmt.Sprintf("%s:%d", c.File, c.Line))
	}
	return fv
}

// paragraphs returns the plain-English explanation of a finding: the
// explanation sections when present, otherwise the finding title.
func paragraphs(f model.Finding) []paragraphView {
	e := f.Explanation
	if e == nil {
		if f.Title == "" {
			return nil
		}
		return []paragraphView{{"What happened", f.Title}}
	}
	var out []paragraphView
	for _, kv := range [][2]string{{"What happened", e.WhatHappened}, {"Why it matters", e.WhyItMatters}, {"Business impact", e.BusinessImpact}} {
		if strings.TrimSpace(kv[1]) != "" {
			out = append(out, paragraphView{kv[0], kv[1]})
		}
	}
	if len(out) == 0 && f.Title != "" {
		out = append(out, paragraphView{"What happened", f.Title})
	}
	return out
}

func buildSettingView(s model.EnvSettings) settingView {
	tm, tw := tri(s.AllowClientTraits, false, "Allowed (clients can write traits)", "Blocked")
	hm, hw := tri(s.HideSensitiveData, true, "Hidden", "Visible to clients")
	return settingView{
		Environment: s.Environment,
		Traits:      tm + " " + tw, TraitsClass: markClass(tm),
		Hidden: hm + " " + hw, HiddenClass: markClass(hm),
		ServerOnly: len(s.ServerOnlyFlags), ClientVisible: len(s.ClientVisible),
	}
}

func buildReachView(r model.Reachable) reachView {
	engine, live := yesNo(r.EngineVerified), liveWord(r.LiveVerified)
	return reachView{
		Flag: r.Flag, Value: reachValue(r), Via: reachVia(r),
		Engine: engine, EngineClass: markClass(engine),
		Live: live, LiveClass: markClass(live),
	}
}

// markClass maps a leading check/cross/other mark to a CSS class.
func markClass(s string) string {
	switch {
	case strings.HasPrefix(s, "✓"):
		return "ok"
	case strings.HasPrefix(s, "✗"):
		return "no"
	default:
		return "unk"
	}
}

func statusClass(s model.Status) string {
	switch s {
	case model.StatusBlocked:
		return "good"
	case model.StatusExploitable, model.StatusHidden:
		return "bad"
	default:
		return "unk"
	}
}

func stageLabels(ms map[string]int64) []string {
	keys := make([]string, 0, len(ms))
	for k := range ms {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = k + " " + humanDuration(ms[k])
	}
	return out
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
