package main

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/yarrasatwik/gatecrasher/internal/config"
)

func TestBuildCIConfigRoundTripsHostileInputs(t *testing.T) {
	in := ciInputs{
		APIURL:      "https://flags.example.com:8443/api/v1/",
		Project:     `Acme "Shop": #1`,
		Environment: "Prod\n# evil: [x]\nallowed_domains: [evil.com]",
		AppPath:     "src/app #1: \"x\"\nstate_dir: /etc",
	}
	data, err := buildCIConfig(in, "/tmp/state")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := yaml.Unmarshal(data, &m); err != nil {
		t.Fatalf("invalid yaml: %v\n%s", err, data)
	}
	// No injected top-level keys.
	if len(m) != 4 {
		t.Fatalf("unexpected top-level keys: %v", m)
	}
	var c envConfig
	if err := yaml.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	if c.Flagsmith.Project != in.Project {
		t.Errorf("project = %q", c.Flagsmith.Project)
	}
	if got := c.Flagsmith.Environments; len(got) != 1 || got[0] != in.Environment {
		t.Errorf("environments = %q", got)
	}
	if c.AppRepo != in.AppPath || c.StateDir != "/tmp/state" {
		t.Errorf("app_repo/state_dir = %q / %q", c.AppRepo, c.StateDir)
	}
	if len(c.AllowedDomains) != 0 {
		t.Errorf("allowed_domains = %v", c.AllowedDomains)
	}
	if h := c.Flagsmith.AllowedAPIHosts; len(h) != 1 || h[0] != "flags.example.com:8443" {
		t.Errorf("hosts = %v", h)
	}
}

func TestWriteCIConfigFromEnvLoads(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RUNNER_TEMP", dir)
	t.Setenv("GC_API_URL", "http://localhost:8000/api/v1/")
	t.Setenv("GC_PROJECT", `Acme "Shop": #1`)
	t.Setenv("GC_ENV", "Staging # x: y")
	t.Setenv("GC_APP", "lab/shop")
	t.Setenv("GC_FAIL_ON", "")
	t.Setenv("GC_SERVER_KEY", "ser.abc")
	t.Setenv("GATECRASHER_ORG_API_KEY", "")
	path, in, err := writeCIConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(dir, "gatecrasher.yaml") || in.FailOn != "high" {
		t.Fatalf("path=%s failOn=%s", path, in.FailOn)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Flagsmith.Project != `Acme "Shop": #1` {
		t.Errorf("project = %q", cfg.Flagsmith.Project)
	}
	if cfg.Flagsmith.Environments[0] != "Staging # x: y" || cfg.ServerKeys["Staging # x: y"] != "ser.abc" {
		t.Errorf("env/server keys = %v %v", cfg.Flagsmith.Environments, cfg.ServerKeys)
	}
	if cfg.AppRepo != "lab/shop" || cfg.Flagsmith.UseCLI {
		t.Errorf("app_repo=%q use_cli=%v", cfg.AppRepo, cfg.Flagsmith.UseCLI)
	}
	if b, _ := os.ReadFile(path); len(b) == 0 {
		t.Error("empty config")
	}
}

func TestBuildCIConfigRequiresInputs(t *testing.T) {
	if _, err := buildCIConfig(ciInputs{Project: "p"}, "s"); err == nil {
		t.Error("want error for missing api url")
	}
	if _, err := buildCIConfig(ciInputs{APIURL: "http://x/"}, "s"); err == nil {
		t.Error("want error for missing project")
	}
}
