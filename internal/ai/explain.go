package ai

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/patch"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

// MaxExplainWords is the word budget for an explanation (spec §9).
const MaxExplainWords = 120

// PRDraft is a drafted pull request. Source is "ai" or "template". The diff
// is a suggestion for a human to review; nothing applies it automatically.
type PRDraft struct {
	Title string `json:"title"`
	Body  string `json:"body"`
	Diff  string `json:"diff"`
	// DiffNote says why Diff is empty when the drafter was given source files.
	DiffNote string `json:"diff_note,omitempty"`
	Source   string `json:"source"`
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

// ExplainAll explains findings in parallel, at most Concurrency() calls at a
// time. The result is index-aligned with fs, so the output order never
// depends on which call finishes first. Findings for which skip returns true
// get a nil entry; skip may be nil.
func (c *Client) ExplainAll(ctx context.Context, fs []model.Finding, skip func(model.Finding) bool) []*model.Explanation {
	out := make([]*model.Explanation, len(fs))
	forEach(len(fs), c.Concurrency(), func(i int) {
		if skip != nil && skip(fs[i]) {
			return
		}
		out[i] = c.Explain(ctx, fs[i])
	})
	return out
}

// forEach runs fn(0..n-1) with at most limit calls in flight and returns
// when all have finished. Each fn writes only to its own index.
func forEach(n, limit int, fn func(i int)) {
	if limit < 1 {
		limit = 1
	}
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		sem <- struct{}{}
		wg.Add(1)
		go func(i int) {
			defer func() { <-sem; wg.Done() }()
			fn(i)
		}(i)
	}
	wg.Wait()
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
	Files   []fileInput  `json:"files,omitempty"`
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
	return c.fixPR(ctx, f, impact, nil, false)
}

// fileInput is one source file shown to the drafter, already redacted.
type fileInput struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// FixPRFiles is FixPR with the full content of the affected files (and the
// related server file). Each file is bounded (patch.MaxFiles, MaxFileLines,
// MaxFileBytes), must be an eligible path, and is redacted before it is
// sent. The returned diff is set only when it was verified to apply to those
// files and to touch nothing else; otherwise Diff is empty and DiffNote says
// why. Nothing is written anywhere.
func (c *Client) FixPRFiles(ctx context.Context, f model.Finding, impact []model.ImpactItem, files []model.SourceFile) *PRDraft {
	return c.fixPR(ctx, f, impact, files, true)
}

func (c *Client) fixPR(ctx context.Context, f model.Finding, impact []model.ImpactItem, files []model.SourceFile, withFiles bool) *PRDraft {
	if !c.enabled() {
		return templatePR(f, impact)
	}
	in := fixInput{Finding: newFindingInput(f)}
	for _, it := range impact {
		in.Impact = append(in.Impact, impactItem{File: redact.String(it.File), Line: it.Line, Snippet: scrubText(it.Snippet), Message: scrubText(it.Message), Breaks: it.Breaks})
	}
	var sent []model.SourceFile
	if withFiles {
		for _, sf := range files {
			if len(sent) == patch.MaxFiles || !patch.Eligible(sf.Path) || !patch.WithinLimits(sf.Content) {
				continue
			}
			sent = append(sent, sf)
			in.Files = append(in.Files, fileInput{Path: sf.Path, Content: scrubFull("", sf.Content)})
		}
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
	if withFiles {
		out.Diff, out.DiffNote = verifyDiff(sent, out.Diff)
	}
	return out
}

// verifyDiff returns the canonical diff when it applies to files, or "" and
// a note saying why it is not shown.
func verifyDiff(files []model.SourceFile, diff string) (string, string) {
	if len(files) == 0 {
		return "", "no diff: the affected files were not available in the app repo"
	}
	if strings.TrimSpace(diff) == "" {
		return "", "no diff was produced for this fix"
	}
	res, err := patch.Apply(files, diff)
	switch {
	case err == nil:
		return redact.String(res.Diff), ""
	case errors.Is(err, patch.ErrOutsideFiles):
		return "", "diff touched a file that was not provided; not shown"
	}
	return "", "diff did not apply; not shown"
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
