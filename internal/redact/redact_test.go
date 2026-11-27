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
