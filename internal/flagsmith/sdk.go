// Package flagsmith wraps the three Flagsmith surfaces Gatecrasher uses:
// the public Flags/Identities SDK API (client key, transient identities
// only), the Admin API (organisation API key) and the environment document.
// Field names were verified against self-hosted Flagsmith 2.295.2 — see
// docs/api-verification.md.
package flagsmith

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/yarrasatwik/gatecrasher/internal/httpx"
	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

// Flag is one evaluated flag as returned by the SDK API.
type Flag struct {
	Name           string `json:"name"`
	FeatureID      int    `json:"feature_id"`
	Type           string `json:"type"`
	Enabled        bool   `json:"enabled"`
	Value          any    `json:"value"`
	Reason         string `json:"reason,omitempty"`
	Variant        string `json:"variant,omitempty"`
	FeatureSegment *int   `json:"feature_segment,omitempty"`
}

// State is a compact comparable rendering: "on", "off", or "on: <value>".
func (f Flag) State() string {
	s := "off"
	if f.Enabled {
		s = "on"
	}
	if v := ValueString(f.Value); v != "" {
		return s + ": " + v
	}
	return s
}

// ValueString renders a flag value deterministically.
func ValueString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%g", t)
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

// Flags is a name-indexed flag set.
type Flags map[string]Flag

// Names returns the sorted flag names.
func (fs Flags) Names() []string {
	out := make([]string, 0, len(fs))
	for n := range fs {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Diff returns every flag whose State differs between base and probe.
func Diff(base, probe Flags) []model.FlagChange {
	var out []model.FlagChange
	for _, n := range probe.Names() {
		p := probe[n]
		b, ok := base[n]
		if !ok || b.State() != p.State() {
			out = append(out, model.FlagChange{Flag: n, Before: b.State(), After: p.State()})
		}
	}
	return out
}

// Trait is a trait in an identity response.
type Trait struct {
	Key       string `json:"trait_key"`
	Value     any    `json:"trait_value"`
	Transient bool   `json:"transient,omitempty"`
}

// IdentityResult is an identities endpoint response.
type IdentityResult struct {
	Identifier string
	Traits     []Trait
	Flags      Flags
	Evidence   model.Evidence
}

// SDK is a client for the public SDK API using a client-side key.
type SDK struct {
	http *httpx.Client
	api  string
	key  string
}

// NewSDK builds an SDK client. The key is registered for redaction.
func NewSDK(c *httpx.Client, apiURL, clientKey string) *SDK {
	redact.Register(clientKey, "CLIENT_KEY")
	return &SDK{http: c, api: apiURL, key: clientKey}
}

// APIURL returns the API base URL.
func (s *SDK) APIURL() string { return s.api }

type rawFlag struct {
	Feature struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"feature"`
	Value          any     `json:"feature_state_value"`
	Enabled        bool    `json:"enabled"`
	Reason         string  `json:"reason"`
	Variant        *string `json:"variant"`
	FeatureSegment *int    `json:"feature_segment"`
}

func toFlags(raw []rawFlag) Flags {
	out := make(Flags, len(raw))
	for _, r := range raw {
		f := Flag{Name: r.Feature.Name, FeatureID: r.Feature.ID, Type: r.Feature.Type, Enabled: r.Enabled, Value: r.Value, Reason: r.Reason, FeatureSegment: r.FeatureSegment}
		if r.Variant != nil {
			f.Variant = *r.Variant
		}
		out[f.Name] = f
	}
	return out
}

func (s *SDK) hdr() map[string]string { return map[string]string{"X-Environment-Key": s.key} }

// EnvironmentFlags calls GET /flags/ (what an anonymous visitor sees).
func (s *SDK) EnvironmentFlags(ctx context.Context) (Flags, model.Evidence, error) {
	u := httpx.JoinURL(s.api, "flags/")
	var raw []rawFlag
	resp, err := s.http.JSON(ctx, httpx.Request{URL: u, Header: s.hdr()}, &raw)
	ev := evidence("GET", u, nil, resp)
	if err != nil {
		return nil, ev, err
	}
	return toFlags(raw), ev, nil
}

// Identify evaluates flags for a TRANSIENT identity with the given traits.
// Every trait is also marked transient. Nothing is persisted in Flagsmith
// (verified: a later GET for the identifier returns no traits).
func (s *SDK) Identify(ctx context.Context, identifier string, traits map[string]string) (*IdentityResult, error) {
	if !strings.HasPrefix(identifier, "gc-probe-") {
		return nil, fmt.Errorf("refusing to probe non-transient-prefixed identifier %q (must start with gc-probe-)", identifier)
	}
	keys := make([]string, 0, len(traits))
	for k := range traits {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ts := make([]map[string]any, 0, len(traits))
	for _, k := range keys {
		ts = append(ts, map[string]any{"trait_key": k, "trait_value": traits[k], "transient": true})
	}
	body := map[string]any{"identifier": identifier, "traits": ts, "transient": true}
	u := httpx.JoinURL(s.api, "identities/")
	var raw struct {
		Identifier string    `json:"identifier"`
		Traits     []Trait   `json:"traits"`
		Flags      []rawFlag `json:"flags"`
	}
	resp, err := s.http.JSON(ctx, httpx.Request{Method: "POST", URL: u, Header: s.hdr(), Body: body, Idempotent: true}, &raw)
	ev := evidence("POST", u, body, resp)
	if err != nil {
		return nil, err
	}
	return &IdentityResult{Identifier: raw.Identifier, Traits: raw.Traits, Flags: toFlags(raw.Flags), Evidence: ev}, nil
}

// LookupIdentity performs a read-only GET identities/?identifier=. Callers
// MUST restrict identifier to configured test identities.
func (s *SDK) LookupIdentity(ctx context.Context, identifier string) (*IdentityResult, error) {
	u := httpx.JoinURL(s.api, "identities/") + "?identifier=" + url.QueryEscape(identifier)
	var raw struct {
		Identifier string    `json:"identifier"`
		Traits     []Trait   `json:"traits"`
		Flags      []rawFlag `json:"flags"`
	}
	resp, err := s.http.JSON(ctx, httpx.Request{URL: u, Header: s.hdr()}, &raw)
	ev := evidence("GET", u, nil, resp)
	if err != nil {
		return nil, err
	}
	return &IdentityResult{Identifier: raw.Identifier, Traits: raw.Traits, Flags: toFlags(raw.Flags), Evidence: ev}, nil
}

// Repro returns a copy-pasteable curl with the key shown as <CLIENT_KEY>.
func Repro(method, u string, body any) string {
	var b strings.Builder
	b.WriteString("curl -s")
	if method != "" && method != "GET" {
		b.WriteString(" -X " + method)
	}
	b.WriteString(" '" + u + "' -H 'X-Environment-Key: <CLIENT_KEY>'")
	if body != nil {
		j, _ := json.Marshal(body)
		b.WriteString(" -H 'Content-Type: application/json' -d '" + string(j) + "'")
	}
	return redact.String(b.String())
}

func evidence(method, u string, body any, resp *httpx.Response) model.Evidence {
	ev := model.Evidence{Kind: "request", Request: Repro(method, u, body)}
	if resp != nil {
		r := string(resp.Body)
		if len(r) > 1500 {
			r = r[:1500] + "…"
		}
		ev.Response = fmt.Sprintf("HTTP %d %s", resp.Status, redact.String(r))
	}
	return ev
}
