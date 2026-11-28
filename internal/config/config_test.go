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
	if c.RerollSamples() != 200 || c.ApprovalTTLMinutes != 30 || !*c.ClientSetsIdentifier {
		t.Fatal("defaults not applied")
	}
}

func TestReconMaxScripts(t *testing.T) {
	base := "target_url: http://localhost:3030\nallowed_domains: [localhost]\nflagsmith:\n  allowed_api_hosts: [\"localhost:8000\"]\n"
	c, err := Load(write(t, t.TempDir(), "g.yaml", base))
	if err != nil {
		t.Fatal(err)
	}
	if c.Recon.MaxScripts != 60 {
		t.Fatalf("default recon.max_scripts = %d, want 60", c.Recon.MaxScripts)
	}
	c, err = Load(write(t, t.TempDir(), "g.yaml", base+"recon:\n  max_scripts: 12\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Recon.MaxScripts != 12 {
		t.Fatalf("recon.max_scripts = %d, want 12", c.Recon.MaxScripts)
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

func TestProtectedEnvironments(t *testing.T) {
	const base = "allowed_domains: [localhost]\nflagsmith:\n  allowed_api_hosts: [\"localhost:8000\"]\n"
	cases := []struct {
		name, yaml string
		protected  []string
		open       []string
		list       []string
	}{
		{"default", base, []string{"Production", "production", "PROD"}, []string{"Development", "Staging"}, []string{"Production"}},
		{"protected_environments", "protected_environments: [Live, Staging]\n" + base,
			[]string{"Live", "staging", "Production"}, []string{"Development"}, []string{"Live", "Staging", "Production"}},
		{"production_environments alias", base + "  production_environments: [Live]\n",
			[]string{"Live", "Production"}, []string{"Development"}, []string{"Live", "Production"}},
		{"both keys merge", "protected_environments: [Staging]\n" + base + "  production_environments: [Live, staging]\n",
			[]string{"Live", "Staging", "Production"}, []string{"Development"}, []string{"Staging", "Live", "Production"}},
		{"an empty list cannot unprotect Production", "protected_environments: []\n" + base,
			[]string{"Production"}, []string{"Development"}, []string{"Production"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Load(write(t, t.TempDir(), "g.yaml", tc.yaml))
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range tc.protected {
				if !c.IsProtected(e) || !c.IsProduction(e) {
					t.Errorf("%q must be protected", e)
				}
			}
			for _, e := range tc.open {
				if c.IsProtected(e) {
					t.Errorf("%q must not be protected", e)
				}
			}
			if got := strings.Join(c.Protected(), ","); got != strings.Join(tc.list, ",") {
				t.Errorf("Protected() = %s, want %s", got, strings.Join(tc.list, ","))
			}
		})
	}
}
