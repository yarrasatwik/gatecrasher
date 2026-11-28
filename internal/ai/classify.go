package ai

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
	"github.com/yarrasatwik/gatecrasher/internal/secrets"
)

// MinAIConfidence is the confidence at which an AI classification is passed
// on at all. It never creates a finding on its own: a classification only
// the AI made is a NEEDS_REVIEW suggestion until a deterministic rule or a
// human confirms it (see app.adjudicate).
const MinAIConfidence = 0.7

type flagInput struct {
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	ValueType string `json:"value_type"`
	Size      int    `json:"size"`
	Value     string `json:"value"`
}

type classifyInput struct {
	Flags []flagInput `json:"flags"`
}

type classifyOutput struct {
	Classifications []struct {
		Flag       string         `json:"flag"`
		Category   model.Category `json:"category"`
		Confidence float64        `json:"confidence"`
		Rationale  string         `json:"rationale"`
	} `json:"classifications"`
}

// Reportable reports whether a classification should create a finding:
// anything that is not HARMLESS and not a SECURITY_CONTROL. Security controls
// (admin gates, kill switches) are context for the attack stages, not leaks.
func Reportable(c model.Classification) bool {
	return c.Category != model.CatHarmless && c.Category != model.CatSecurityControl
}

// Classify sorts every flag of the inventory into a category. The
// deterministic pass always runs; when the AI is on, its answers are merged:
// the deterministic result wins whenever it is not HARMLESS; otherwise an AI
// answer with confidence >= 0.7 is returned with Method "ai", which marks it
// as an unconfirmed suggestion for the caller. Each result names the Method
// that produced it.
func (c *Client) Classify(ctx context.Context, inv *model.PublicInventory) ([]model.Classification, Mode) {
	det := make([]model.Classification, len(inv.Flags))
	for i, f := range inv.Flags {
		det[i] = secrets.Classify(f)
	}
	if !c.enabled() {
		return det, ModeOff
	}
	ai, err := c.classifyAI(ctx, inv)
	if err != nil {
		return det, fallbackMode(describe(err))
	}
	return merge(det, ai), c.Mode()
}

// classifyBatch is how many flags one classification call carries. A larger
// inventory is split into batches that run in parallel.
const classifyBatch = 25

func (c *Client) classifyAI(ctx context.Context, inv *model.PublicInventory) (map[string]model.Classification, error) {
	var batches [][]model.FlagView
	for i := 0; i < len(inv.Flags); i += classifyBatch {
		batches = append(batches, inv.Flags[i:min(i+classifyBatch, len(inv.Flags))])
	}
	if len(batches) == 0 {
		batches = [][]model.FlagView{nil}
	}
	results := make([]map[string]model.Classification, len(batches))
	errs := make([]error, len(batches))
	forEach(len(batches), c.Concurrency(), func(i int) {
		results[i], errs[i] = c.classifyBatchAI(ctx, batches[i])
	})
	out := map[string]model.Classification{}
	for i := range batches { // batch order, not completion order
		if errs[i] != nil {
			return nil, errs[i]
		}
		for k, v := range results[i] {
			out[k] = v
		}
	}
	return out, nil
}

func (c *Client) classifyBatchAI(ctx context.Context, flags []model.FlagView) (map[string]model.Classification, error) {
	in := classifyInput{Flags: make([]flagInput, len(flags))}
	known := map[string]bool{}
	for i, f := range flags {
		known[f.Name] = true
		in.Flags[i] = flagInput{Name: redact.String(f.Name), Enabled: f.Enabled, ValueType: f.ValueType, Size: f.Size, Value: scrub(f.Name, f.RawValue)}
	}
	out := map[string]model.Classification{}
	err := c.ask(ctx, prompt("classify"), marshal(in), func(raw string) error {
		var o classifyOutput
		if err := decodeJSON(raw, &o); err != nil {
			return err
		}
		res := map[string]model.Classification{}
		for _, it := range o.Classifications {
			if !known[it.Flag] {
				return fmt.Errorf("unknown flag %q", it.Flag)
			}
			if !it.Category.Valid() {
				return fmt.Errorf("invalid category %q", it.Category)
			}
			if math.IsNaN(it.Confidence) || it.Confidence < 0 || it.Confidence > 1 {
				return errors.New("confidence outside 0..1")
			}
			res[it.Flag] = model.Classification{
				Flag: it.Flag, Category: it.Category, Confidence: it.Confidence,
				Rationale: truncateRunes(redact.String(it.Rationale), 200), Method: model.MethodAI,
			}
		}
		out = res
		return nil
	})
	return out, err
}

// merge applies the spec §8.2 rule: the deterministic result wins when it is
// reportable; otherwise a confident reportable AI answer is used.
func merge(det []model.Classification, ai map[string]model.Classification) []model.Classification {
	out := make([]model.Classification, len(det))
	for i, d := range det {
		out[i] = d
		a, ok := ai[d.Flag]
		if !ok || Reportable(d) {
			continue
		}
		if Reportable(a) && a.Confidence >= MinAIConfidence {
			out[i] = a
		}
	}
	return out
}

// describe turns an AI failure into a short label for the Mode string.
func describe(err error) string {
	switch {
	case errors.Is(err, ErrSecretInPrompt):
		return "prompt blocked by secret guard"
	case errors.Is(err, errInvalid):
		return "invalid response after retry"
	default:
		return "request failed"
	}
}
