package ai

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

// MaxHypotheses is the most trait guesses one call may return (spec §8.3).
const MaxHypotheses = 40

var traitKeyRe = regexp.MustCompile(`^[A-Za-z0-9_.\-]{1,64}$`)

// Hypothesis is one ranked guess of a trait a visitor might forge.
type Hypothesis struct {
	TraitKey   string `json:"trait_key"`
	TraitValue string `json:"trait_value"`
	Why        string `json:"why"`
}

type hypothesizeInput struct {
	FlagNames    []string `json:"flag_names"`
	TraitKeys    []string `json:"trait_keys_in_bundle"`
	TargetDomain string   `json:"target_domain"`
}

type hypothesizeOutput struct {
	Hypotheses []Hypothesis `json:"hypotheses"`
}

// Hypothesize proposes up to 40 ranked (trait_key, trait_value) pairs to
// probe. It sees only flag names, bundle trait keys and the target domain.
// With the AI off, or after a failed AI call, it returns the built-in
// dictionary (spec §8.3) and the Mode says so.
func (c *Client) Hypothesize(ctx context.Context, flagNames, traitKeys []string, domain string) ([]Hypothesis, Mode) {
	if !c.enabled() {
		return heuristicHypotheses(traitKeys, domain), ModeOff
	}
	in := hypothesizeInput{FlagNames: redactAll(flagNames), TraitKeys: redactAll(traitKeys), TargetDomain: redact.String(domain)}
	var out []Hypothesis
	err := c.ask(ctx, prompt("hypothesize"), marshal(in), func(raw string) error {
		var o hypothesizeOutput
		if err := decodeJSON(raw, &o); err != nil {
			return err
		}
		hs, err := validateHypotheses(o.Hypotheses)
		out = hs
		return err
	})
	if err != nil {
		return heuristicHypotheses(traitKeys, domain), fallbackMode(describe(err))
	}
	return out, c.Mode()
}

func validateHypotheses(in []Hypothesis) ([]Hypothesis, error) {
	if len(in) == 0 {
		return nil, errors.New("no hypotheses")
	}
	if len(in) > MaxHypotheses {
		return nil, fmt.Errorf("%d hypotheses exceeds the limit of %d", len(in), MaxHypotheses)
	}
	seen := map[string]bool{}
	out := make([]Hypothesis, 0, len(in))
	for _, h := range in {
		h.TraitKey, h.TraitValue = strings.TrimSpace(h.TraitKey), strings.TrimSpace(h.TraitValue)
		if !traitKeyRe.MatchString(h.TraitKey) || h.TraitValue == "" || len(h.TraitValue) > 128 {
			return nil, errors.New("hypothesis with invalid trait_key or trait_value")
		}
		id := h.TraitKey + "\x00" + h.TraitValue
		if seen[id] {
			continue
		}
		seen[id] = true
		h.Why = truncateRunes(redact.String(h.Why), 200)
		out = append(out, h)
	}
	return out, nil
}

func redactAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = redact.String(s)
	}
	return out
}
