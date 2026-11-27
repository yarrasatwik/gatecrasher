package watch

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/httpx"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
	"github.com/yarrasatwik/gatecrasher/internal/scope"
)

// slackHost is the only host alerts may be posted to.
const slackHost = "hooks.slack.com"

// SlackNotifier posts alerts to a Slack incoming webhook. Its HTTP client is
// scope-locked to hooks.slack.com, so it cannot be pointed anywhere else.
type SlackNotifier struct {
	client *httpx.Client
	url    string
}

// NewSlack validates webhookURL (https, hooks.slack.com) and builds a
// notifier. The URL embeds a secret token, so it is registered for redaction.
func NewSlack(webhookURL string) (*SlackNotifier, error) {
	u, err := url.Parse(webhookURL)
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Hostname(), slackHost) {
		return nil, fmt.Errorf("slack webhook must be an https://%s URL", slackHost)
	}
	lock, err := scope.New([]string{slackHost}, nil)
	if err != nil {
		return nil, err
	}
	redact.Register(webhookURL, "SLACK_WEBHOOK_URL")
	return newSlack(httpx.New(lock, httpx.WithTimeout(10*time.Second), httpx.WithRetries(1)), webhookURL), nil
}

func newSlack(c *httpx.Client, webhookURL string) *SlackNotifier {
	return &SlackNotifier{client: c, url: webhookURL}
}

// Notify posts a redacted summary of the alert.
func (s *SlackNotifier) Notify(ctx context.Context, a Alert) error {
	body := map[string]string{"text": SlackText(a)}
	if _, err := s.client.JSON(ctx, httpx.Request{Method: "POST", URL: s.url, Body: body}, nil); err != nil {
		return fmt.Errorf("post slack alert: %w", err)
	}
	return nil
}

// SlackText renders the redacted one-message summary of an alert.
func SlackText(a Alert) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Gatecrasher: %d new finding(s) after %s", len(a.Findings), a.Change.Kind)
	if o := a.Change.Object(); o != "" {
		fmt.Fprintf(&b, " on %s", o)
	}
	if a.Change.Environment != "" {
		fmt.Fprintf(&b, " (%s)", a.Change.Environment)
	}
	b.WriteString("\n")
	for i, f := range a.Findings {
		if i == 5 {
			fmt.Fprintf(&b, "- ...and %d more\n", len(a.Findings)-i)
			break
		}
		fmt.Fprintf(&b, "- [%s] %s\n", strings.ToUpper(f.Severity.String()), f.Title)
	}
	fmt.Fprintf(&b, "Detected in %d ms. Review the fix: %s", a.LatencyMS, a.ReviewURL)
	return redact.String(b.String())
}
