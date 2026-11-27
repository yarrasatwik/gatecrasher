package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValidAndDotEnv(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "gatecrasher.yaml", `
target_url: http://localhost:3030
allowed_domains: [localhost]
flagsmith:
  api_url: http://localhost:8000/api/v1
  allowed_api_hosts: ["localhost:8000"]
  production_environments: [Live]
test_identities: [ceo@acmeshop.dev]
`)
	write(t, dir, ".env", "GATECRASHER_SERVER_KEYS=Production=ser.abcdefghijkl, Development=ser.mnopqrstuv\n")
	t.Setenv("GATECRASHER_SERVER_KEYS", "")
	if err := os.Unsetenv("GATECRASHER_SERVER_KEYS"); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Flagsmith.APIURL != "http://localhost:8000/api/v1/" {
		t.Fatalf("api url not normalised: %s", c.Flagsmith.APIURL)
	}
	if c.ServerKeys["Production"] != "ser.abcdefghijkl" || c.ServerKeys["Development"] != "ser.mnopqrstuv" {
		t.Fatalf("server keys: %v", c.ServerKeys)
	}
	if !c.IsProduction("Live") || !c.IsProduction("production") || c.IsProduction("Development") {
		t.Fatal("IsProduction wrong")
	}
	if !c.IsTestIdentity("ceo@acmeshop.dev") || c.IsTestIdentity("someone@else.com") {
		t.Fatal("IsTestIdentity wrong")
	}
	if c.Lock().CheckURL("http://example.com") == nil {
		t.Fatal("scope lock must refuse example.com")
	}
	if c.Probes.RerollSamples != 200 || c.ApprovalTTLMinutes != 30 || !*c.ClientSetsIdentifier {
		t.Fatal("defaults not applied")
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]string{
		"target out of scope": "target_url: http://evil.test\nallowed_domains: [localhost]\nflagsmith: {allowed_api_hosts: [\"localhost:8000\"]}\n",
		"api out of scope":    "flagsmith: {api_url: \"http://other:8000/api/v1/\", allowed_api_hosts: [\"localhost:8000\"]}\n",
		"no api hosts":        "allowed_domains: [localhost]\n",
		"unknown field":       "alowed_domains: [localhost]\nflagsmith: {allowed_api_hosts: [\"localhost:8000\"]}\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			p := write(t, t.TempDir(), "g.yaml", body)
			_, err := Load(p)
			if err == nil {
				t.Fatal("expected error")
			}
			if strings.Contains(err.Error(), "ser.") {
				t.Fatal("error leaks key material")
			}
		})
	}
}
