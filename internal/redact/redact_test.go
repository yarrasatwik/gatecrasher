package redact

import (
	"strings"
	"testing"
)

func TestPatterns(t *testing.T) {
	Reset()
	secrets := []string{
		"ser.AbCdEfGhIjKlMnOpQrStUv",
		"Authorization: Api-Key 8VpiXQiR.abcdefghijklmnopqrstuvwxyz012345",
		"8VpiXQiR.abcdefghijklmnopqrstuvwxyz012345",
		"Token 10decf3cab975eaaf4715ca2493f2d486b359142",
		"acme_live_0123456789abcdef0123456789abcdef",
		"AKIAABCDEFGHIJKLMNOP",
		"ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		"xoxb-1234567890-abcdefghij",
		"sk-ant-api03-abcdefghijklmnop",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		`{"api_secret":"hunter2hunter2"}`,
		"X-Environment-Key: CQJFFFBP5Hk65U5vDHU3MS",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----",
	}
	for _, s := range secrets {
		out := String(s)
		if out == s {
			t.Errorf("not redacted: %q", s)
		}
		if !strings.Contains(out, "len=") {
			t.Errorf("no fingerprint in %q", out)
		}
	}
}

// Publishable Stripe keys are public by design and the classifier does not
// call them secrets, but output still never prints them in full.
func TestPublishableKeysStillRedacted(t *testing.T) {
	Reset()
	for _, s := range []string{"pk_live_51H8xYzAbCdEfGhIjKlMnOpQr", `{"publishableKey":"pk_test_TYooMQauvdEDq54NiTphI7jx"}`} {
		if out := String(s); strings.Contains(out, "MnOpQr") || strings.Contains(out, "NiTphI7jx") || !strings.Contains(out, "len=") {
			t.Errorf("publishable key not redacted: %q", out)
		}
	}
}

func TestURLPasswordRedacted(t *testing.T) {
	Reset()
	for in, password := range map[string]string{
		"postgres://app:Hunter2pass@db.internal:5432/prod":           "Hunter2pass",
		"mongodb+srv://svc:Pa55word@cluster0.ab1cd.mongodb.net/app":  "Pa55word",
		"redis://:s3cretpass@localhost:6379/0":                       "s3cretpass",
		`{"webhook":"https://hook:Wh00kPass@hooks.example.com/in"}`:  "Wh00kPass",
		"dial amqp://guest:Gu3stPass@rabbit.example.com:5672 failed": "Gu3stPass",
	} {
		out := String(in)
		if strings.Contains(out, password) {
			t.Errorf("password left in %q", out)
		}
		if !strings.Contains(out, "URL_PASSWORD len=") || !strings.Contains(out, "@") {
			t.Errorf("unexpected redaction %q", out)
		}
		if again := String(out); again != out {
			t.Errorf("not idempotent: %q -> %q", out, again)
		}
	}
	for _, s := range []string{
		"http://localhost:8000/api/v1/flags/",
		"https://example.com:8443/a@b",
		"https://abc123def456@o12345.ingest.sentry.io/678",
		"ratio 3:1 @ noon",
	} {
		if out := String(s); out != s {
			t.Errorf("%q must be left alone, got %q", s, out)
		}
	}
}

func TestRegistryAndIdempotence(t *testing.T) {
	Reset()
	Register("CQJFFFBP5Hk65U5vDHU3MS", "CLIENT_KEY")
	Register("abc", "TOO_SHORT")
	in := "key=CQJFFFBP5Hk65U5vDHU3MS and abc stays"
	out := String(in)
	if strings.Contains(out, "CQJFFFBP5Hk65U5vDHU3MS") {
		t.Fatalf("registered key leaked: %s", out)
	}
	if !strings.Contains(out, "abc stays") {
		t.Fatalf("short value must not be registered: %s", out)
	}
	if String(out) != out {
		t.Fatalf("redaction is not idempotent: %q -> %q", out, String(out))
	}
	if !ContainsSecret(in) || ContainsSecret("plain text, plan=gold") {
		t.Fatal("ContainsSecret wrong")
	}
}

func TestHarmlessUntouched(t *testing.T) {
	Reset()
	for _, s := range []string{"Free shipping over $50", "http://10.0.3.7:8080/admin", "plan=gold", "gc-probe-1b4e28ba-2fa1-11d2-883f-0016d3cca427"} {
		if String(s) != s {
			t.Errorf("harmless text changed: %q -> %q", s, String(s))
		}
	}
}

func TestFingerprint(t *testing.T) {
	if got := Fingerprint("acme_live_xyz", "SECRET"); got != "[SECRET len=13 prefix=acme…]" {
		t.Fatalf("got %s", got)
	}
}
