package secrets

import (
	"strings"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

func TestClassifyTable(t *testing.T) {
	const labSecret = `{"provider":"acmepay","api_secret":"acme_live_0123456789abcdef0123456789abcdef","webhook":"https://internal.acmeshop.dev/pay"}`
	tests := []struct {
		name  string
		value any
		want  model.Category
		path  string // expected substring in a signal, "" to skip
	}{
		{"payment_config", labSecret, model.CatSecret, "$.api_secret"},
		{"aws", "AKIAIOSFODNN7EXAMPLE", model.CatSecret, "aws_access_key@$"},
		{"gh", "ghp_abcdefghijklmnopqrstuvwxyz0123456789", model.CatSecret, "github_token"},
		{"slack", "xoxb-1234567890-abcdefghij", model.CatSecret, "slack_token"},
		{"jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.abcdefghijklmnop", model.CatSecret, "jwt"},
		{"pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----", model.CatSecret, "private_key"},
		{"stripe_style", "sk_live_abcdefghij1234567890", model.CatSecret, "live_api_key"},
		{"nested", `{"a":{"b":[{"password":"hunter2hunter2"}]}}`, model.CatSecret, "$.a.b[0].password"},
		{"entropy", "q8Zx3Lk9PwR2tYv7NmB4cJd1", model.CatPossibleSecret, "high_entropy"},
		{"internal_url", "http://10.0.3.7:8080/admin", model.CatInternalURL, "private_ip"},
		{"host", "https://api.corp.example.com/v1", model.CatInternalURL, "internal_host"},
		{"local", "http://localhost:3000", model.CatInternalURL, "localhost"},
		{"mdns", "printer.local", model.CatInternalURL, "internal_host"},
		{"email", "ceo@acmeshop.dev", model.CatPII, "email"},
		{"phone", "+1-555-0100", model.CatPII, "phone"},
		{"project_x_launch_2026_12_15", false, model.CatUnreleasedProduct, "codename_launch@name"},
		{"new_checkout_launch", false, model.CatUnreleasedProduct, "launch_name"},
		{"summer_2026_07_01", true, model.CatUnreleasedProduct, "dated_name"},
		{"discount_code", "SAVE20", model.CatPricing, "pricing_name"},
		{"tier_config", `{"enterprise_price":4999}`, model.CatPricing, "pricing_value"},
		{"admin_panel", false, model.CatSecurityControl, "admin_gate"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(model.FlagView{Name: tc.name, RawValue: tc.value})
			if got.Category != tc.want {
				t.Fatalf("category = %s (%v), want %s", got.Category, got.Signals, tc.want)
			}
			if got.Method != model.MethodDeterministic {
				t.Fatalf("method = %s", got.Method)
			}
			if tc.path != "" && !strings.Contains(strings.Join(got.Signals, ","), tc.path) {
				t.Fatalf("signals %v missing %q", got.Signals, tc.path)
			}
		})
	}
}

func TestNoFalsePositives(t *testing.T) {
	tests := []struct {
		name  string
		value any
	}{
		{"maintenance_mode", false},
		{"kill_switch_checkout", true},
		{"banner_text", "Free shipping over $50"},
		{"pricing_page", "price_high"},
		{"early_access_ai", false},
		{"premium_export", true},
		{"hero_image", "https://cdn.acmeshop.dev/assets/hero-banner-image-summer-collection.png"},
		{"request_id", "123e4567-e89b-12d3-a456-426614174000"},
		{"welcome", "Welcome back! Enjoy our summer collection of handmade ceramics and pottery."},
		{"slogan", "FreeShippingOverFiftyDollarsToday"},
		{"theme", `{"primary":"#3366ff","radius":8,"font":"Inter"}`},
		{"sentence_url", "See https://docs.acmeshop.dev/getting-started-with-feature-flags-guide for more"},
		{"number", float64(42)},
		{"nil_value", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(model.FlagView{Name: tc.name, RawValue: tc.value})
			if got.Category != model.CatHarmless {
				t.Fatalf("category = %s via %v, want HARMLESS", got.Category, got.Signals)
			}
		})
	}
}

func TestScanReportsPathAndHidesSecretInString(t *testing.T) {
	sigs := Scan("payment_config", `{"outer":{"api_key":"abcd1234efgh5678"}}`)
	if len(sigs) == 0 || sigs[0].Path != "$.outer.api_key" {
		t.Fatalf("unexpected signals: %+v", sigs)
	}
	if sigs[0].Secret != "abcd1234efgh5678" {
		t.Fatalf("secret not captured for redact registration")
	}
	if strings.Contains(sigs[0].String(), "abcd") {
		t.Fatal("Signal.String must not contain secret material")
	}
}

func TestEntropy(t *testing.T) {
	if Entropy("aaaaaaaa") != 0 {
		t.Fatal("constant string must have zero entropy")
	}
	if Entropy("abcdefgh") < 2.9 {
		t.Fatal("8 distinct chars must have entropy 3")
	}
}
