package report

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/severity"
)

const (
	sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifInfo   = "https://github.com/yarrasatwik/gatecrasher"
	// fingerprintKey names the stable per-finding fingerprint GitHub uses to
	// track an alert across runs.
	fingerprintKey = "gatecrasherFindingId/v1"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	EndTimeUTC          string `json:"endTimeUtc,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifText struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     sarifText      `json:"shortDescription"`
	FullDescription      sarifText      `json:"fullDescription"`
	Help                 sarifText      `json:"help"`
	DefaultConfiguration sarifConfig    `json:"defaultConfiguration"`
	Properties           map[string]any `json:"properties"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Locations           []sarifLocation   `json:"locations"`
	Properties          map[string]any    `json:"properties"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical  `json:"physicalLocation"`
	LogicalLocations []sarifLogical `json:"logicalLocations,omitempty"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifLogical struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind"`
}

// securityScore maps a severity to GitHub's numeric security-severity.
func securityScore(s model.Severity) string {
	switch s {
	case model.SevCritical:
		return "9.5"
	case model.SevHigh:
		return "8.0"
	case model.SevMedium:
		return "5.5"
	case model.SevLow:
		return "3.0"
	default:
		return "0.0"
	}
}

// sarifLevel maps a severity to a SARIF result level.
func sarifLevel(s model.Severity) string {
	switch s {
	case model.SevCritical, model.SevHigh:
		return "error"
	case model.SevMedium:
		return "warning"
	default:
		return "note"
	}
}

// resultLevel is the SARIF level of one finding. A HIDDEN finding is still
// open, so it is always reported as a warning: never dropped like a BLOCKED
// one and never passed.
func resultLevel(f model.Finding) string {
	if f.Status == model.StatusHidden {
		return "warning"
	}
	return sarifLevel(f.Severity)
}

// WriteSARIF writes the report as SARIF 2.1.0 for GitHub code scanning.
//
// One rule exists per finding type. Results cover every finding that is a
// vulnerability: CONTROL_OK findings are not problems and BLOCKED findings
// are fixed, so both are omitted and the matching alerts close on upload.
// HIDDEN findings are still open and stay in the results as warnings.
// Each result has a logical location (the flag) and a physical location: the
// repo file and line from an "impact: path:line" note when present, otherwise
// the stable pseudo-file flagsmith/<environment>/<flag>.
func WriteSARIF(w io.Writer, r *model.Report) error {
	p := prepare(r)
	rules, index := buildRules(p)
	results := make([]sarifResult, 0, len(p.Findings))
	for _, f := range p.Findings {
		if f.Type == model.FControlOK || f.Status == model.StatusBlocked {
			continue
		}
		results = append(results, buildResult(p, f, index[f.Type]))
	}
	log := sarifLog{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name: ToolName, Version: p.Version, InformationURI: sarifInfo, Rules: rules,
			}},
			Results:     results,
			Invocations: []sarifInvocation{{ExecutionSuccessful: true, EndTimeUTC: p.CreatedAt.UTC().Format("2006-01-02T15:04:05Z")}},
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(log); err != nil {
		return fmt.Errorf("write sarif report: %w", err)
	}
	return nil
}

// buildRules returns one rule per finding type (the catalog plus any
// unknown type present in the report) and each type's rule index.
func buildRules(p *model.Report) ([]sarifRule, map[model.FindingType]int) {
	worst := map[model.FindingType]model.Severity{}
	for _, f := range p.Findings {
		if f.Type == model.FControlOK {
			continue
		}
		if s, ok := worst[f.Type]; !ok || f.Severity > s {
			worst[f.Type] = f.Severity
		}
	}
	infos := append([]ruleInfo{}, catalog...)
	for _, f := range p.Findings {
		if _, _, ok := lookupRule(f.Type); !ok && !hasRule(infos, f.Type) {
			infos = append(infos, ruleInfo{f.Type, string(f.Type), "Gatecrasher finding " + string(f.Type), "Gatecrasher finding " + string(f.Type), "See the finding's fix plan."})
		}
	}
	rules := make([]sarifRule, len(infos))
	index := make(map[model.FindingType]int, len(infos))
	for i, c := range infos {
		sev, ok := worst[c.Type]
		if !ok {
			bare := model.Finding{Type: c.Type}
			severity.Assign(&bare)
			sev = bare.Severity
		}
		index[c.Type] = i
		rules[i] = sarifRule{
			ID:               string(c.Type),
			Name:             c.Name,
			ShortDescription: sarifText{Text: c.Short},
			FullDescription:  sarifText{Text: c.Full},
			Help: sarifText{
				Text:     c.Full + "\n\nFix: " + c.Fix,
				Markdown: "**" + c.Short + "**\n\n" + c.Full + "\n\n**Fix:** " + c.Fix,
			},
			DefaultConfiguration: sarifConfig{Level: sarifLevel(sev)},
			Properties: map[string]any{
				"security-severity": securityScore(sev),
				"tags":              []string{"security", "feature-flags", "flagsmith"},
				"precision":         "high",
			},
		}
	}
	return rules, index
}

func hasRule(infos []ruleInfo, t model.FindingType) bool {
	for _, i := range infos {
		if i.Type == t {
			return true
		}
	}
	return false
}

func buildResult(p *model.Report, f model.Finding, ruleIndex int) sarifResult {
	msg := headline(f)
	if f.Explanation != nil && f.Explanation.WhatHappened != "" {
		msg += ": " + f.Explanation.WhatHappened
	}
	return sarifResult{
		RuleID:              string(f.Type),
		RuleIndex:           ruleIndex,
		Level:               resultLevel(f),
		Message:             sarifText{Text: oneLine(msg, 500)},
		PartialFingerprints: map[string]string{fingerprintKey: f.ID},
		Locations:           locationsFor(p, f),
		Properties: map[string]any{
			"security-severity": securityScore(f.Severity),
			"status":            string(f.Status),
			"confirmed":         f.Confirmed,
		},
	}
}

// locationsFor returns at least one location for f: code locations from
// impact analysis, or the flag's pseudo-file as a fallback.
func locationsFor(p *model.Report, f model.Finding) []sarifLocation {
	env := firstNonEmpty(f.Environment, p.Environment, "unknown")
	logical := []sarifLogical{{Name: f.Subject, FullyQualifiedName: env + "/" + f.Subject, Kind: "member"}}
	var locs []sarifLocation
	for _, c := range impactLocations(f) {
		locs = append(locs, sarifLocation{
			PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: escapePath(c.File)}, Region: sarifRegion{StartLine: c.Line}},
			LogicalLocations: logical,
		})
	}
	if len(locs) == 0 {
		uri := "flagsmith/" + url.PathEscape(env) + "/" + url.PathEscape(firstNonEmpty(f.Subject, "unknown"))
		locs = append(locs, sarifLocation{
			PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: uri}, Region: sarifRegion{StartLine: 1}},
			LogicalLocations: logical,
		})
	}
	return locs
}

func escapePath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
