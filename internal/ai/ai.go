// Package ai is Gatecrasher's optional Claude integration (spec §8.2, §9).
// The model has no tools and no credentials: it receives only redacted data
// and returns JSON that is validated before use. Without an API key, or when
// the model's output fails validation twice, deterministic heuristics take
// over and the result is labelled with the Mode it was produced in.
package ai

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/httpx"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
	"github.com/yarrasatwik/gatecrasher/internal/scope"
)

// DefaultModel is used when no model is configured.
const DefaultModel = "claude-sonnet-5-5"

const (
	anthropicHost    = "api.anthropic.com"
	anthropicURL     = "https://api.anthropic.com/v1/messages"
	anthropicVersion = "2023-06-01"
	maxOutputTokens  = 4096
	requestTimeout   = 90 * time.Second
)

//go:embed prompts/*.md
var promptFS embed.FS

// Mode labels how an AI-assisted result was produced.
type Mode string

// ModeOff is the label when no API key is configured.
const ModeOff Mode = "off (heuristics)"

// On reports whether the result came from the model.
func (m Mode) On() bool { return strings.HasPrefix(string(m), "on") }

// String returns the label shown in reports.
func (m Mode) String() string { return string(m) }

func fallbackMode(reason string) Mode {
	return Mode("off (heuristics; AI fallback: " + redact.String(reason) + ")")
}

// Sentinel errors.
var (
	// ErrSecretInPrompt is returned when a prompt still contains secret material.
	ErrSecretInPrompt = errors.New("refusing to send prompt: it contains secret or key material")
	errInvalid        = errors.New("AI output failed validation")
)

// Client talks to the Anthropic Messages API. A nil Client, or one built
// without an API key, runs in "AI off" mode.
type Client struct {
	key      string
	model    string
	endpoint string
	http     *httpx.Client
	// cli, when set, is the path of a signed-in Claude Code binary used
	// instead of the Messages API (claude -p, every tool disabled).
	cli string
}

// New builds a Client. An empty apiKey yields AI-off mode; an empty model
// selects DefaultModel. The client's own scope lock allows only
// api.anthropic.com, independent of the audit target's scope.
func New(apiKey, model string) *Client {
	return newClient(apiKey, model, anthropicURL)
}

func newClient(apiKey, model, endpoint string) *Client {
	if model == "" {
		model = DefaultModel
	}
	redact.Register(apiKey, "ANTHROPIC_KEY")
	host := anthropicHost
	if endpoint != anthropicURL {
		host = hostOf(endpoint)
	}
	lock := scope.MustNew(nil, []string{host})
	return &Client{key: apiKey, model: model, endpoint: endpoint, http: httpx.New(lock, httpx.WithTimeout(requestTimeout))}
}

func hostOf(endpoint string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(endpoint, "http://"), "https://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}

func (c *Client) enabled() bool { return c != nil && (c.key != "" || c.cli != "") }

// Mode returns "on (model)" when an API key or Claude Code is configured,
// else ModeOff.
func (c *Client) Mode() Mode {
	if !c.enabled() {
		return ModeOff
	}
	if c.cli != "" {
		return Mode("on (" + c.model + " via Claude Code)")
	}
	return Mode("on (" + c.model + ")")
}

func prompt(name string) string {
	b, err := promptFS.ReadFile("prompts/" + name + ".md")
	if err != nil {
		panic("ai: missing embedded prompt " + name) // build-time invariant
	}
	return string(b)
}

// guard refuses any text that still holds a key or secret, including every
// value registered with redact at runtime.
func guard(texts ...string) error {
	for _, t := range texts {
		if redact.ContainsSecret(t) {
			return ErrSecretInPrompt
		}
	}
	return nil
}

type messageRequest struct {
	Model       string    `json:"model"`
	MaxTokens   int       `json:"max_tokens"`
	Temperature float64   `json:"temperature"`
	System      string    `json:"system"`
	Messages    []message `json:"messages"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type messageResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
}

// send posts one prompt (no tools, temperature 0) and returns the text reply.
func (c *Client) send(ctx context.Context, system, user string) (string, error) {
	if err := guard(system, user); err != nil {
		return "", err
	}
	if c.cli != "" {
		return c.sendCLI(ctx, system, user)
	}
	body := messageRequest{Model: c.model, MaxTokens: maxOutputTokens, System: system, Messages: []message{{Role: "user", Content: user}}}
	var resp messageResponse
	_, err := c.http.JSON(ctx, httpx.Request{
		Method:     "POST",
		URL:        c.endpoint,
		Header:     map[string]string{"x-api-key": c.key, "anthropic-version": anthropicVersion},
		Body:       body,
		Idempotent: true,
	}, &resp)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, part := range resp.Content {
		if part.Type == "text" {
			sb.WriteString(part.Text)
		}
	}
	return sb.String(), nil
}

// ask sends the prompt and runs decode on the reply. When decode rejects the
// reply it retries once with a short correction, then gives up with errInvalid.
func (c *Client) ask(ctx context.Context, system, user string, decode func(raw string) error) error {
	next := user
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		text, err := c.send(ctx, system, next)
		if err != nil {
			return err
		}
		if last = decode(text); last == nil {
			return nil
		}
		next = user + "\n\nYour previous reply was rejected (" + last.Error() + "). Return ONLY JSON matching the schema. No prose."
	}
	return fmt.Errorf("%w: %v", errInvalid, last)
}

// stripFences removes Markdown code fences and any prose around the JSON.
func stripFences(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "```"); i >= 0 {
		s = s[i+3:]
		if nl := strings.IndexByte(s, '\n'); nl >= 0 && !strings.ContainsAny(s[:nl], "{[") {
			s = s[nl+1:]
		}
		if j := strings.Index(s, "```"); j >= 0 {
			s = s[:j]
		}
	}
	s = strings.TrimSpace(s)
	if open := strings.IndexAny(s, "{["); open > 0 {
		s = s[open:]
	}
	if end := strings.LastIndexAny(s, "}]"); end >= 0 && end < len(s)-1 {
		s = s[:end+1]
	}
	return s
}

// decodeJSON strips fences and decodes strictly into v.
func decodeJSON(raw string, v any) error {
	dec := json.NewDecoder(strings.NewReader(stripFences(raw)))
	if err := dec.Decode(v); err != nil {
		return errors.New("not valid JSON for the schema")
	}
	return nil
}

// marshal renders a prompt payload as compact JSON without HTML escaping.
func marshal(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic("ai: marshal prompt payload: " + err.Error()) // payloads are plain structs
	}
	return strings.TrimSpace(buf.String())
}
