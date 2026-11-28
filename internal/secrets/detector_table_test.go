package secrets

import (
	"strings"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

const (
	hex32 = "9e107d9d372bb6826bd81d3542a419d6"
	hex40 = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
	hex64 = "9f86d081884c7a659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

	labPaymentConfig = `{"provider":"acmepay","api_secret":"acme_live_` + hex32 + `","webhook":"https://internal.acmeshop.dev/pay"}`
	firebaseKey      = "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"
	mapboxPublic     = "pk.eyJ1IjoiYWNtZXNob3AiLCJhIjoiY2xleGFtcGxlMDAwMDAifQ.Zm9vYmFyYmF6cXV4MTIzNDU2"
	recaptchaSite    = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"
	pngDataURI       = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
)

func classify(name string, value any) model.Classification {
	return Classify(model.FlagView{Name: name, RawValue: value})
}

func hasSignal(c model.Classification, want string) bool {
	return strings.Contains(strings.Join(c.Signals, ","), want)
}

// TestSpecRows pins the four rows of the fix spec (A3).
func TestSpecRows(t *testing.T) {
	t.Run("40-hex git SHA is harmless", func(t *testing.T) {
		if c := classify("build_commit", hex40); c.Category != model.CatHarmless {
			t.Fatalf("category = %s via %v", c.Category, c.Signals)
		}
	})
	t.Run("Stripe publishable key is harmless", func(t *testing.T) {
		c := classify("stripe_key", "pk_live_51H8xYzAbCdEfGhIjKlMnOpQr")
		if c.Category != model.CatHarmless {
			t.Fatalf("category = %s via %v", c.Category, c.Signals)
		}
	})
	t.Run("Sentry DSN is harmless", func(t *testing.T) {
		c := classify("sentry_dsn", "https://abc123def456@o12345.ingest.sentry.io/678")
		if c.Category != model.CatHarmless {
			t.Fatalf("category = %s via %v", c.Category, c.Signals)
		}
		if hasSignal(c, "email") {
			t.Fatalf("DSN must not read as an e-mail address: %v", c.Signals)
		}
	})
	t.Run("postgres URL with password is a secret on an internal host", func(t *testing.T) {
		const v = "postgres://app:Hunter2pass@db.internal:5432/prod"
		c := classify("database_url", v)
		if c.Category != model.CatSecret {
			t.Fatalf("category = %s via %v", c.Category, c.Signals)
		}
		for _, want := range []string{"url_credential", "internal_host"} {
			if !hasSignal(c, want) {
				t.Fatalf("signals %v missing %q", c.Signals, want)
			}
		}
		if hasSignal(c, "email") {
			t.Fatalf("user:pass@host must not read as an e-mail address: %v", c.Signals)
		}
		var secret string
		for _, s := range Scan("database_url", v) {
			if s.Kind == "url_credential" {
				secret = s.Secret
			}
		}
		if secret != "Hunter2pass" {
			t.Fatalf("password not captured for redaction, got %q", secret)
		}
	})
}

// TestHarmlessValues: realistic flag values that must never raise a secret
// (no SECRET, no POSSIBLE_SECRET, no PII) and stay HARMLESS.
func TestHarmlessValues(t *testing.T) {
	tests := []struct {
		name  string
		value any
		info  string // expected informational signal, "" for none
	}{
		{"checkout_config", `{"enabled":true,"max_items":25,"layout":"grid","variants":["a","b"],"timeout_ms":2500}`, ""},
		{"brand_colour", "#3366ff", ""},
		{"overlay_colour", "rgba(51, 102, 255, 0.85)", ""},
		{"theme", `{"primary":"#3366ff","accent":"#ff9900","radius":8,"font":"Inter, system-ui, sans-serif"}`, ""},
		{"campaign_link", "https://www.acmeshop.dev/collections/summer?utm_source=newsletter&utm_campaign=july_sale_2026", ""},
		{"hero_image", "https://cdn.acmeshop.dev/img/" + hex64 + ".webp", ""},
		{"signed_asset", "https://cdn.acmeshop.dev/a/Zm9vYmFyQmF6UXV4MTIzNDU2Nzg5MEFiQ2RFZg/logo.png", ""},
		{"app_version", "2.14.3-beta.1+build.20261128", ""},
		{"min_supported_version", ">=1.4.0 <2.0.0", ""},
		{"git_describe", "v2.3.1-14-g9a651a3", ""},
		{"build_commit", hex40, ""},
		{"asset_md5", hex32, ""},
		{"bundle_sha256", hex64, ""},
		{"integrity", `{"commit":"` + hex40 + `","checksum":"` + hex64 + `"}`, ""},
		{"tenant_id", "123e4567-e89b-12d3-a456-426614174000", ""},
		{"hcaptcha", `{"sitekey":"10000000-ffff-ffff-ffff-000000000001"}`, ""},
		{"max_cart_items", float64(5000), ""},
		{"rate_limits", `{"rate_limit_per_minute":600,"burst":50,"window":"100/min"}`, ""},
		{"welcome_copy", `{"en":"Welcome back!","de":"Willkommen zurück!","fr":"Bon retour parmi nous !","ja":"おかえりなさい"}`, ""},
		{"i18n_key", "checkout.shipping.freeOverThreshold", ""},
		{"long_copy", "Order before 14:00 for same-day dispatch. Returns are free within 30 days of delivery.", ""},
		{"banner_text", "Free shipping over $50", ""},
		{"pricing_page", "price_high", ""},
		{"maintenance_mode", false, ""},
		{"premium_export", true, ""},
		{"sale_ends", "2026-11-28T09:30:00Z", ""},
		{"grid_css", "max-width: 1200px; grid-template-columns: repeat(3, 1fr)", ""},
		{"analytics_id", "G-2X9K4LM7QP", ""},
		{"placeholder_pixel", pngDataURI, ""},
		{"avatar", `{"fallback":"` + pngDataURI + `","size":64}`, ""},
		{"auth_policy", `{"password_min_length":12,"password_policy":"min12-upper-digit","token_ttl_seconds":3600,"csrf_token_header":"X-CSRF-Token"}`, ""},
		{"login_fields", `{"password":"required","token":"optional"}`, ""},
		{"vault_ref", `{"api_secret":"${PAYMENT_API_SECRET}","password":"{{db_password}}"}`, ""},
		{"stripe_publishable", "pk_live_51H8xYzAbCdEfGhIjKlMnOpQr", "public_stripe_publishable_key"},
		{"stripe_checkout", `{"publishableKey":"pk_test_TYooMQauvdEDq54NiTphI7jx","apiVersion":"2026-01-01"}`, "public_stripe_publishable_key"},
		{"firebase", `{"apiKey":"` + firebaseKey + `","authDomain":"acme-shop.firebaseapp.com","projectId":"acme-shop"}`, "public_firebase_api_key@$.apiKey"},
		{"maps", mapboxPublic, "public_mapbox_token"},
		{"captcha", `{"recaptcha_site_key":"` + recaptchaSite + `"}`, "public_recaptcha_site_key"},
		{"error_reporting", "https://abc123def456@o12345.ingest.sentry.io/678", "public_sentry_dsn"},
		{"error_reporting_json", `{"dsn":"https://0123456789abcdef0123456789abcdef@sentry.acmeshop.dev/42","sampleRate":0.25}`, "public_sentry_dsn"},
		{"site_search", `{"appId":"B1G2GM9NG0","searchApiKey":"` + hex32 + `","indexName":"products"}`, "public_algolia_search_key"},
		{"site_search_v2", `{"algolia":{"searchOnlyKey":"` + hex32 + `"}}`, "public_algolia_search_key"},
	}
	if len(tests) < 15 {
		t.Fatalf("need at least 15 harmless values, have %d", len(tests))
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := classify(tc.name, tc.value)
			if c.Category != model.CatHarmless {
				t.Fatalf("category = %s via %v, want HARMLESS", c.Category, c.Signals)
			}
			for _, s := range Scan(tc.name, tc.value) {
				if s.Category != model.CatHarmless {
					t.Fatalf("unexpected %s signal %s", s.Category, s)
				}
				if s.Secret != "" {
					t.Fatalf("harmless signal %s carries secret material", s)
				}
			}
			if tc.info != "" && !hasSignal(c, tc.info) {
				t.Fatalf("signals %v missing informational %q", c.Signals, tc.info)
			}
		})
	}
}

func TestFirebaseKeyNoteSaysRestrictByReferrer(t *testing.T) {
	c := classify("firebase", `{"apiKey":"`+firebaseKey+`"}`)
	if c.Category != model.CatHarmless || !strings.Contains(c.Rationale, "referrer") {
		t.Fatalf("category=%s rationale=%q", c.Category, c.Rationale)
	}
}

// TestRealSecrets: every one must classify as SECRET (which the severity
// rules rate CRITICAL) with the expected signal.
func TestRealSecrets(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		signal string
		also   string // extra signal that must fire, "" for none
	}{
		{"payment_config", labPaymentConfig, "secret_key_name@$.api_secret", "acme_live_key"},
		{"aws", "AKIAIOSFODNN7EXAMPLE", "aws_access_key", ""},
		{"github", "ghp_abcdefghijklmnopqrstuvwxyz0123456789", "github_token", ""},
		{"slack", "xoxb-1234567890-abcdefghij", "slack_token", ""},
		{"jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.abcdefghijklmnop", "jwt", ""},
		{"pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----", "private_key", ""},
		{"stripe_secret", "sk_live_abcdefghij1234567890", "live_api_key", ""},
		{"anthropic", "sk-ant-api03-abcdefghijklmnop", "anthropic_key", ""},
		{"flagsmith_server", "ser.AbCdEfGhIjKlMnOpQrStUv", "flagsmith_server_key", ""},
		{"mapbox_secret", "sk.eyJ1IjoiYWNtZXNob3AiLCJhIjoiY2xleGFtcGxlMDAwMDAifQ.Zm9vYmFyYmF6cXV4MTIzNDU2", "mapbox_secret_token", ""},
		{"nested_password", `{"a":{"b":[{"password":"hunter2hunter2"}]}}`, "secret_key_name@$.a.b[0].password", ""},
		{"passphrase", `{"db":{"password":"correcthorsebattery"}}`, "secret_key_name@$.db.password", ""},
		{"client_secret", `{"oauth":{"clientSecret":"` + hex32 + `"}}`, "secret_key_name@$.oauth.clientSecret", ""},
		{"private_key_field", `{"private_key":"MIIEvQIBADANBgkqhkiG9w0BAQEFAASC"}`, "secret_key_name@$.private_key", ""},
		{"token_field", `{"auth_token":"` + hex40 + `"}`, "secret_key_name@$.auth_token", ""},
		{"recaptcha_secret", `{"recaptcha_secret":"6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"}`, "secret_key_name@$.recaptcha_secret", ""},
		{"algolia_admin", `{"adminApiKey":"` + hex32 + `"}`, "secret_key_name@$.adminApiKey", ""},
		{"postgres", "postgres://app:Hunter2pass@db.internal:5432/prod", "url_credential", "internal_host"},
		{"mysql", "mysql://root:s3cr3tPW@10.0.3.9:3306/shop", "url_credential", "private_ip"},
		{"mongodb", "mongodb://svc:Pa55word@mongo.example.com:27017/app?authSource=admin", "url_credential", ""},
		{"mongodb_srv", "mongodb+srv://svc:Pa55word@cluster0.ab1cd.mongodb.net/app", "url_credential", ""},
		{"redis", "redis://:s3cretpass@localhost:6379/0", "url_credential", "localhost"},
		{"amqp", "amqp://guest:Gu3stPass@rabbit.corp.example.com:5672/vhost", "url_credential", "internal_host"},
		{"https_basic", "https://deploy:t0psecret@artifacts.example.com/releases", "url_credential", ""},
		{"http_basic_json", `{"webhook":"http://hook:Wh00kPass@hooks.example.com/in"}`, "url_credential@$.webhook", ""},
		{"ftp", "ftp://backup:B4ckupPass@files.example.com/dumps", "url_credential", ""},
	}
	if len(tests) < 10 {
		t.Fatalf("need at least 10 secret patterns, have %d", len(tests))
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := classify(tc.name, tc.value)
			if c.Category != model.CatSecret {
				t.Fatalf("category = %s via %v, want SECRET", c.Category, c.Signals)
			}
			for _, want := range []string{tc.signal, tc.also} {
				if want != "" && !hasSignal(c, want) {
					t.Fatalf("signals %v missing %q", c.Signals, want)
				}
			}
			if hasSignal(c, "email") {
				t.Fatalf("credential read as an e-mail address: %v", c.Signals)
			}
		})
	}
}

// TestEntropyAloneIsOnlyPossibleSecret: randomness without a known pattern,
// a secret-named key or a URL credential is "needs review", never SECRET.
func TestEntropyAloneIsOnlyPossibleSecret(t *testing.T) {
	for name, v := range map[string]string{
		"mixed_token":   "q8Zx3Lk9PwR2tYv7NmB4cJd1",
		"upper_hex":     strings.ToUpper(hex40),
		"odd_hex":       hex32 + "0a1b2c3d4e5f6a7b",
		"neutral_field": `{"correlation":"q8Zx3Lk9PwR2tYv7NmB4cJd1"}`,
		"url_userinfo":  "https://q8Zx3Lk9PwR2tYv7NmB4cJd1@api.example.com/v1",
	} {
		t.Run(name, func(t *testing.T) {
			c := classify(name, v)
			if c.Category != model.CatPossibleSecret {
				t.Fatalf("category = %s via %v, want POSSIBLE_SECRET", c.Category, c.Signals)
			}
			if !strings.Contains(c.Rationale, "needs review") {
				t.Fatalf("rationale %q must say needs review", c.Rationale)
			}
			for _, s := range Scan(name, v) {
				if s.Category == model.CatSecret {
					t.Fatalf("entropy alone produced SECRET signal %s", s)
				}
			}
		})
	}
}

func TestEmailOnlyStandalone(t *testing.T) {
	for v, want := range map[string]bool{
		"ceo@acmeshop.dev": true,
		"Questions? Write to support@acmeshop.dev today.":  true,
		"mailto:support@acmeshop.dev":                      true,
		`{"owner":"jane.doe@example.com"}`:                 true,
		"https://abc123def456@o12345.ingest.sentry.io/678": false,
		"postgres://app:Hunter2pass@db.example.com/prod":   false,
		"app:Hunter2pass@db.example.com":                   false,
		"https://example.com/@acme/pkg@2.1.0/index.js":     false,
		"https://example.com/u?contact=jane@example.com":   false,
		"ssh://git@github.com/acme/shop.git":               false,
	} {
		got := false
		for _, s := range Scan("f", v) {
			if s.Kind == "email" {
				got = true
			}
		}
		if got != want {
			t.Errorf("email signal for %q = %v, want %v", v, got, want)
		}
	}
}

// TestLabControlFlags mirrors the lab seed: payment_config is the only
// secret; the control flags never become one.
func TestLabControlFlags(t *testing.T) {
	if c := classify("payment_config", labPaymentConfig); c.Category != model.CatSecret {
		t.Fatalf("payment_config = %s via %v", c.Category, c.Signals)
	}
	for name, tc := range map[string]struct {
		value any
		want  model.Category
	}{
		"banner_text":      {"Free shipping over $50", model.CatHarmless},
		"internal_api":     {"http://10.0.3.7:8080/admin", model.CatInternalURL},
		"maintenance_mode": {false, model.CatHarmless},
		"premium_export":   {true, model.CatHarmless},
		"pricing_page":     {"price_high", model.CatHarmless},
	} {
		c := classify(name, tc.value)
		if c.Category != tc.want {
			t.Errorf("%s = %s via %v, want %s", name, c.Category, c.Signals, tc.want)
		}
		for _, s := range Scan(name, tc.value) {
			if s.Category == model.CatSecret || s.Category == model.CatPossibleSecret {
				t.Errorf("%s raised %s", name, s)
			}
		}
	}
}
