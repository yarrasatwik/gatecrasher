package ai

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

// MaxExplainWords is the word budget for an explanation (spec §9).
const MaxExplainWords = 120

// PRDraft is a drafted pull request. Source is "ai" or "template". The diff
// is a suggestion for a human to review; nothing applies it automatically.
type PRDraft struct {
	Title  string `json:"title"`
	Body   string `json:"body"`
	Diff   string `json:"diff"`
	Source string `json:"source"`
}

type findingInput struct {
	Type        model.FindingType  `json:"type"`
	Severity    string             `json:"severity"`
	Title       string             `json:"title"`
	Subject     string             `json:"subject"`
	Category    model.Category     `json:"category,omitempty"`
	Environment string             `json:"environment,omitempty"`
	Traits      map[string]string  `json:"forged_traits,omitempty"`
	Unlocked    []model.FlagChange `json:"unlocked,omitempty"`
	HitRate     float64            `json:"hit_rate,omitempty"`
	Evidence    []evidenceInput    `json:"evidence,omitempty"`
}

type evidenceInput struct {
	Kind     string `json:"kind"`
	Request  string `json:"request,omitempty"`
	Response string `json:"response,omitempty"`
	Note     string `json:"note,omitempty"`
}

func newFindingInput(f model.Finding) findingInput {
	in := findingInput{
		Type: f.Type, Severity: f.Severity.String(), Title: scrubText(f.Title), Subject: scrubText(f.Subject),
		Category: f.Category, Environment: f.Environment, HitRate: f.HitRate,
	}
	if len(f.Traits) > 0 {
		in.Traits = map[string]string{}
		for k, v := range f.Traits {
			in.Traits[scrubText(k)] = scrubText(v)
		}
	}
	for _, u := range f.Unlocked {
		in.Unlocked = append(in.Unlocked, model.FlagChange{Flag: scrubText(u.Flag), Before: scrubText(u.Before), After: scrubText(u.After)})
	}
	for i, e := range f.Evidence {
		if i >= 3 {
			break
		}
		in.Evidence = append(in.Evidence, evidenceInput{
			Kind: e.Kind, Request: truncateRunes(scrubText(e.Request), 300),
			Response: truncateRunes(scrubText(e.Response), 300), Note: truncateRunes(scrubText(e.Note), 300),
		})
	}
	return in
}

type explainOutput struct {
	Title          string `json:"title"`
	WhatHappened   string `json:"what_happened"`
	WhyItMatters   string `json:"why_it_matters"`
	BusinessImpact string `json:"business_impact"`
	FixSummary     string `json:"fix_summary"`
}

// Explain writes a plain-English explanation of a confirmed finding. When
// the AI is off or fails, a deterministic template is used and Source is
// "template"; Source is "ai" only for validated model output.
func (c *Client) Explain(ctx context.Context, f model.Finding) *model.Explanation {
	if !c.enabled() {
		return templateExplanation(f)
	}
	var out *model.Explanation
	err := c.ask(ctx, prompt("explain"), marshal(newFindingInput(f)), func(raw string) error {
		var o explainOutput
		if err := decodeJSON(raw, &o); err != nil {
			return err
		}
		e, err := validateExplanation(o)
		out = e
		return err
	})
	if err != nil {
		return templateExplanation(f)
	}
	return out
}

func validateExplanation(o explainOutput) (*model.Explanation, error) {
	fields := []string{o.Title, o.WhatHappened, o.WhyItMatters, o.BusinessImpact, o.FixSummary}
	words := 0
	for _, s := range fields {
		if strings.TrimSpace(s) == "" {
			return nil, errors.New("explanation field is empty")
		}
		words += len(strings.Fields(s))
	}
	if words > MaxExplainWords {
		return nil, fmt.Errorf("explanation has %d words, limit is %d", words, MaxExplainWords)
	}
	r := redact.String
	return &model.Explanation{
		Title: r(o.Title), WhatHappened: r(o.WhatHappened), WhyItMatters: r(o.WhyItMatters),
		BusinessImpact: r(o.BusinessImpact), FixSummary: r(o.FixSummary), Source: "ai",
	}, nil
}

type fixInput struct {
	Finding findingInput `json:"finding"`
	Impact  []impactItem `json:"impact"`
}

type impactItem struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet"`
	Message string `json:"message"`
	Breaks  bool   `json:"breaks"`
}

type fixOutput struct {
	Title string `json:"title"`
	Body  string `json:"body"`
	Diff  string `json:"diff"`
}

// FixPR drafts a pull request for a finding and the code places it affects.
// With the AI off or failing, a deterministic template without a diff is used.
func (c *Client) FixPR(ctx context.Context, f model.Finding, impact []model.ImpactItem) *PRDraft {
	if !c.enabled() {
		return templatePR(f, impact)
	}
	in := fixInput{Finding: newFindingInput(f)}
	for _, it := range impact {
		in.Impact = append(in.Impact, impactItem{File: redact.String(it.File), Line: it.Line, Snippet: scrubText(it.Snippet), Message: scrubText(it.Message), Breaks: it.Breaks})
	}
	var out *PRDraft
	err := c.ask(ctx, prompt("fix_pr"), marshal(in), func(raw string) error {
		var o fixOutput
		if err := decodeJSON(raw, &o); err != nil {
			return err
		}
		d, err := validatePR(o)
		out = d
		return err
	})
	if err != nil {
		return templatePR(f, impact)
	}
	return out
}

func validatePR(o fixOutput) (*PRDraft, error) {
	title, body := strings.TrimSpace(o.Title), strings.TrimSpace(o.Body)
	switch {
	case title == "" || len(title) > 120:
		return nil, errors.New("title missing or longer than 120 characters")
	case body == "" || len(body) > 8000:
		return nil, errors.New("body missing or too long")
	}
	diff := strings.TrimSpace(o.Diff)
	if diff != "" && !strings.HasPrefix(diff, "---") && !strings.HasPrefix(diff, "diff ") {
		return nil, errors.New("diff is not a unified diff")
	}
	if diff != "" {
		diff += "\n"
	}
	return &PRDraft{Title: redact.String(title), Body: redact.String(body), Diff: redact.String(diff), Source: "ai"}, nil
}

func sortedTraits(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + m[k]
	}
	return strings.Join(parts, ", ")
}
