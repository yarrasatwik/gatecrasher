package secrets

import (
	"strings"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

const (
	slackHook   = "https://hooks." + "slack.com/services/T0123ABCD/B0456EFGH/Xk3j9QpLm2Zr8TvNb4Wc7YdA"
	discordHook = "https://discord.com/api/" + "webhooks/1098765432109876543/aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5bC7dE9fG1hJ3kL5mN7pQ9rS1tU3vW5x"
	twilioSID   = "AC" + hex32
	twilioTok   = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
)

// TestKnownTokenFormats: vendor token formats are SECRET wherever they appear.
func TestKnownTokenFormats(t *testing.T) {
	tests := []struct{ name, value, signal string }{
		{"slack_webhook", slackHook, "slack_webhook"},
		{"slack_webhook_json", `{"alerts":{"url":"` + slackHook + `"}}`, "slack_webhook@$.alerts.url"},
		{"discord_webhook", discordHook, "discord_webhook"},
		{"discordapp_webhook", strings.Replace(discordHook, "discord.com", "discordapp.com", 1), "discord_webhook"},
		{"discord_webhook_v10", strings.Replace(discordHook, "/api/", "/api/v10/", 1), "discord_webhook"},
		{"openai_legacy", "s" + "k-Xk3j9QpLm2Zr8TvNb4Wc7YdAeF5gH6iJ1kL2mN3oP4qR5sT", "openai_key"},
		{"openai_project", "s" + "k-proj-Xk3j9QpLm2Zr8TvNb4Wc7YdAeF5gH6iJ1kL2mN3oP4qR5sT_u-V6wX7yZ", "openai_key"},
		{"anthropic_full", "s" + "k-ant-api03-Xk3j9QpLm2Zr8TvNb4Wc7YdAeF5gH6iJ1kL2mN3oP4qR5sT6uV7wX8yZ-AA", "anthropic_key"},
		{"sendgrid", "S" + "G.Xk3j9QpLm2Zr8TvNb4Wc7Y.dAeF5gH6iJ1kL2mN3oP4qR5sT6uV7wX8yZ9aB0cD1eF", "sendgrid_key"},
		{"google_oauth_secret", "GOC" + "SPX-Xk3j9QpLm2Zr8TvNb4Wc7YdAeF5g", "google_oauth_client_secret"},
		{"npm", "np" + "m_Xk3j9QpLm2Zr8TvNb4Wc7YdAeF5gH6iJ1kL2", "npm_token"},
		{"twilio_auth_token", `{"accountSid":"` + twilioSID + `","authToken":"` + twilioTok + `"}`, "twilio_auth_token"},
		{"twilio_text", "TWILIO " + twilioSID + " " + twilioTok, "twilio_auth_token"},
		{"twilio_api_key", `{"sid":"SK` + hex32 + `","secret":"` + twilioTok + `"}`, "twilio_auth_token"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := classify(tc.name, tc.value)
			if c.Category != model.CatSecret || c.Confidence < 0.9 {
				t.Fatalf("category = %s conf %.2f via %v, want SECRET", c.Category, c.Confidence, c.Signals)
			}
			if !hasSignal(c, tc.signal) {
				t.Fatalf("signals %v missing %q", c.Signals, tc.signal)
			}
			kind := strings.SplitN(tc.signal, "@", 2)[0]
			for _, s := range Scan(tc.name, tc.value) {
				if s.Kind == kind && s.Secret == "" {
					t.Fatalf("signal %s carries no secret material for redaction", s)
				}
			}
		})
	}
}

func TestWebhookURLIsTheSecret(t *testing.T) {
	for _, v := range []string{slackHook, discordHook} {
		found := false
		for _, s := range Scan("hook", v) {
			if s.Category == model.CatSecret && s.Secret == v {
				found = true
			}
		}
		if !found {
			t.Fatalf("secret for %q must be the whole URL", v)
		}
	}
}

// TestTokenLookAlikesAreNotSecrets: things that resemble a token format.
func TestTokenLookAlikesAreNotSecrets(t *testing.T) {
	tests := []struct{ name, value string }{
		{"prose_sk", "Use sk- prefixed keys only in your server, never in the browser."},
		{"css_class", `{"className":"sk-circle-bounce-wrapper-container sk-fading-circle"}`},
		{"task_id", "task-1234"},
		{"task_long", "task-abcdefghijklmnopqrstuvwxyz0123456789"},
		{"skeleton", "skeleton"},
		{"skeleton_loader", "skeleton-loader-animation-pulse-variant"},
		{"slack_workspace", "https://acme-shop.slack.com/archives/C0123456789"},
		{"slack_help", "https://slack.com/help/articles/115005265063-Incoming-webhooks-for-Slack"},
		{"slack_hooks_host_only", "https://hooks." + "slack.com/"},
		{"discord_invite", "https://discord.gg/acmeshop"},
		{"discord_invite_com", "https://discord.com/invite/acmeshop"},
		{"discord_docs", "https://discord.com/developers/docs/resources/webhook"},
		{"sg_version", "SG.1.2"},
		{"npm_name", "npm_config_cache"},
		{"twilio_sid_alone", twilioSID},
		{"twilio_ac_prose", "ACME Corp invoice 0f1e2d3c4b5a69788796a5b4c3d2e1f0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if c := classify(tc.name, tc.value); c.Category == model.CatSecret {
				t.Fatalf("category = %s via %v, must not be SECRET", c.Category, c.Signals)
			}
		})
	}
}
