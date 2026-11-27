package recon

import (
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
	"github.com/yarrasatwik/gatecrasher/internal/secrets"
)

// previewMax is the longest redacted preview recon records for a flag value.
const previewMax = 80

// flagView converts an SDK flag into the inventory representation. Secrets
// found in the value are registered with redact before the preview is made,
// so the preview and every later log line are safe. RawValue stays in memory.
func flagView(f flagsmith.Flag) model.FlagView {
	vt, size := describe(f.Value)
	registerSecrets(f.Name, f.Value)
	return model.FlagView{
		Name:      f.Name,
		FeatureID: f.FeatureID,
		Type:      f.Type,
		Enabled:   f.Enabled,
		ValueType: vt,
		Preview:   preview(f.Value),
		Size:      size,
		RawValue:  f.Value,
	}
}

// describe returns the value type (null|bool|number|string|json) and size in
// bytes. A string that holds a JSON object or array counts as json.
func describe(v any) (string, int) {
	switch t := v.(type) {
	case nil:
		return "null", 0
	case bool:
		return "bool", len(flagsmith.ValueString(t))
	case float64:
		return "number", len(flagsmith.ValueString(t))
	case string:
		if isJSONContainer(t) {
			return "json", len(t)
		}
		return "string", len(t)
	default:
		return "json", len(flagsmith.ValueString(t))
	}
}

func isJSONContainer(s string) bool {
	t := strings.TrimSpace(s)
	if len(t) < 2 || (t[0] != '{' && t[0] != '[') {
		return false
	}
	return json.Valid([]byte(t))
}

func registerSecrets(name string, v any) {
	for _, sig := range secrets.Scan(name, v) {
		if sig.Secret != "" {
			redact.Register(sig.Secret, "SECRET")
		}
	}
}

// preview renders the value on one line, redacted and at most previewMax runes.
func preview(v any) string {
	s := redact.String(strings.Join(strings.Fields(flagsmith.ValueString(v)), " "))
	if utf8.RuneCountInString(s) <= previewMax {
		return s
	}
	r := []rune(s)
	return string(r[:previewMax-1]) + "…"
}
