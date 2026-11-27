package flagsmith

import (
	"encoding/json"
	"fmt"

	"github.com/Flagsmith/flagsmith-go-client/v5/flagengine"
	"github.com/Flagsmith/flagsmith-go-client/v5/flagengine/engine_eval"
	"github.com/Flagsmith/flagsmith-go-client/v5/flagengine/environments"
	"github.com/Flagsmith/flagsmith-go-client/v5/trait"
)

// EngineVersion records the pinned official SDK whose engine we use.
const EngineVersion = "github.com/Flagsmith/flagsmith-go-client/v5 v5.7.0"

// Engine evaluates flags offline with Flagsmith's own evaluation engine
// (the same code the official Go SDK uses for local evaluation).
type Engine struct {
	ctx engine_eval.EngineEvaluationContext
	Doc environments.EnvironmentModel
}

// NewEngine parses an environment document.
func NewEngine(doc json.RawMessage) (*Engine, error) {
	var env environments.EnvironmentModel
	if err := json.Unmarshal(doc, &env); err != nil {
		return nil, fmt.Errorf("parse environment document: %w", err)
	}
	return &Engine{ctx: engine_eval.MapEnvironmentDocumentToEvaluationContext(&env), Doc: env}, nil
}

// Evaluate returns the flags an identity with these traits would receive.
func (e *Engine) Evaluate(identifier string, traits map[string]string) Flags {
	ts := make([]*trait.Trait, 0, len(traits))
	for k, v := range traits {
		ts = append(ts, &trait.Trait{TraitKey: k, TraitValue: v})
	}
	ec := engine_eval.MapContextAndIdentityDataToContext(e.ctx, identifier, ts)
	res := flagengine.GetEvaluationResult(&ec)
	return fromResult(res)
}

// EvaluateEnvironment returns flags with no identity (the /flags/ view).
func (e *Engine) EvaluateEnvironment() Flags {
	ec := engine_eval.RemoveIdentityFromContext(&e.ctx)
	return fromResult(flagengine.GetEvaluationResult(&ec))
}

func fromResult(res engine_eval.EvaluationResult) Flags {
	out := make(Flags, len(res.Flags))
	for name, fr := range res.Flags {
		if fr == nil {
			continue
		}
		out[name] = Flag{Name: name, Enabled: fr.Enabled, Value: normalise(fr.Value), Reason: fr.Reason, Variant: fr.Variant}
	}
	return out
}

// normalise maps engine values to the JSON-decoded shapes the live API
// returns (numbers as float64), so engine and live States are comparable.
func normalise(v any) any {
	switch t := v.(type) {
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case int32:
		return float64(t)
	case float32:
		return float64(t)
	}
	return v
}
