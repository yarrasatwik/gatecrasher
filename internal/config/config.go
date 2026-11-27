// Package config loads gatecrasher.yaml plus environment variables and
// builds the immutable scope lock. Secrets only ever come from the
// environment (or a git-ignored .env file), never from the YAML.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/yarrasatwik/gatecrasher/internal/redact"
	"github.com/yarrasatwik/gatecrasher/internal/scope"
)

// Flagsmith holds the Flagsmith connection settings.
type Flagsmith struct {
	// APIURL is the Flagsmith API base, e.g. http://localhost:8000/api/v1/
	APIURL string `yaml:"api_url"`
	// AllowedAPIHosts are host[:port] entries the agent may call.
	AllowedAPIHosts []string `yaml:"allowed_api_hosts"`
	// Project is the project name (inside view).
	Project string `yaml:"project"`
	// Environments to audit by name.
	Environments []string `yaml:"environments"`
	// ProductionEnvironments require typed confirmation to change.
	ProductionEnvironments []string `yaml:"production_environments"`
	// UseCLI makes the applier prefer the Flagsmith CLI when installed.
	UseCLI bool `yaml:"use_cli"`
}

// Probes tunes the attack stage.
type Probes struct {
	RerollSamples  int     `yaml:"reroll_samples"`
	RatePerSec     float64 `yaml:"rate_per_sec"`
	MaxHypotheses  int     `yaml:"max_hypotheses"`
	MaxCombos      int     `yaml:"max_combos"`
	MaxRerollTries int     `yaml:"max_reroll_tries"`
}

// Watch configures the webhook receiver.
type Watch struct {
	Listen    string `yaml:"listen"`
	PublicURL string `yaml:"public_url"`
}

// Config is the full runtime configuration.
type Config struct {
	TargetURL            string    `yaml:"target_url"`
	AllowedDomains       []string  `yaml:"allowed_domains"`
	Flagsmith            Flagsmith `yaml:"flagsmith"`
	TestIdentities       []string  `yaml:"test_identities"`
	ServerOnlyTraits     []string  `yaml:"server_only_traits"`
	ClientSetsIdentifier *bool     `yaml:"client_sets_identifier"`
	AppRepo              string    `yaml:"app_repo"`
	Probes               Probes    `yaml:"probes"`
	PropagationTimeoutS  int       `yaml:"propagation_timeout_s"`
	ApprovalTTLMinutes   int       `yaml:"approval_ttl_minutes"`
	StateDir             string    `yaml:"state_dir"`
	ReportDir            string    `yaml:"report_dir"`
	Watch                Watch     `yaml:"watch"`

	// From the environment (never YAML).
	OrgAPIKey     string            `yaml:"-"`
	ServerKeys    map[string]string `yaml:"-"` // env name -> ser. key
	ClientKeys    map[string]string `yaml:"-"` // env name -> client key (optional)
	AnthropicKey  string            `yaml:"-"`
	Model         string            `yaml:"-"`
	WebhookSecret string            `yaml:"-"`
	SlackWebhook  string            `yaml:"-"`

	Path string `yaml:"-"`
	lock *scope.Lock
}

// Defaults fills zero values with safe defaults.
func (c *Config) Defaults() {
	if c.Flagsmith.APIURL == "" {
		c.Flagsmith.APIURL = "http://localhost:8000/api/v1/"
	}
	if !strings.HasSuffix(c.Flagsmith.APIURL, "/") {
		c.Flagsmith.APIURL += "/"
	}
	if len(c.Flagsmith.Environments) == 0 {
		c.Flagsmith.Environments = []string{"Production"}
	}
	if c.Probes.RerollSamples == 0 {
		c.Probes.RerollSamples = 200
	}
	if c.Probes.RatePerSec == 0 {
		c.Probes.RatePerSec = 60
	}
	if c.Probes.MaxHypotheses == 0 {
		c.Probes.MaxHypotheses = 40
	}
	if c.Probes.MaxCombos == 0 {
		c.Probes.MaxCombos = 24
	}
	if c.Probes.MaxRerollTries == 0 {
		c.Probes.MaxRerollTries = 500
	}
	if c.PropagationTimeoutS == 0 {
		c.PropagationTimeoutS = 150
	}
	if c.ApprovalTTLMinutes == 0 {
		c.ApprovalTTLMinutes = 30
	}
	if c.StateDir == "" {
		c.StateDir = ".gatecrasher"
	}
	if c.ReportDir == "" {
		c.ReportDir = "reports"
	}
	if c.Watch.Listen == "" {
		c.Watch.Listen = "127.0.0.1:8788"
	}
	if c.ClientSetsIdentifier == nil {
		t := true // assume the worst: client picks its own identifier
		c.ClientSetsIdentifier = &t
	}
	if c.Model == "" {
		c.Model = "claude-sonnet-5-5"
	}
}

// Load reads the YAML file at path (optional if empty and not present),
// loads .env (if present) and the process environment, validates, and
// builds the scope lock.
func Load(path string) (*Config, error) {
	c := &Config{}
	if path == "" {
		for _, p := range []string{"gatecrasher.yaml", "gatecrasher.yml"} {
			if _, err := os.Stat(p); err == nil {
				path = p
				break
			}
		}
	}
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		dec := yaml.NewDecoder(strings.NewReader(string(b)))
		dec.KnownFields(true)
		if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		c.Path = path
	}
	dir := "."
	if path != "" {
		dir = filepath.Dir(path)
	}
	loadDotEnv(filepath.Join(dir, ".env"))
	c.fromEnv()
	c.Defaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) fromEnv() {
	get := os.Getenv
	if v := get("GATECRASHER_TARGET_URL"); v != "" && c.TargetURL == "" {
		c.TargetURL = v
	}
	if v := get("GATECRASHER_API_URL"); v != "" {
		c.Flagsmith.APIURL = v
	}
	c.OrgAPIKey = get("GATECRASHER_ORG_API_KEY")
	c.AnthropicKey = get("ANTHROPIC_API_KEY")
	c.Model = get("GATECRASHER_MODEL")
	c.WebhookSecret = get("GATECRASHER_WEBHOOK_SECRET")
	c.SlackWebhook = get("GATECRASHER_SLACK_WEBHOOK_URL")
	c.ServerKeys = parsePairs(get("GATECRASHER_SERVER_KEYS"))
	c.ClientKeys = parsePairs(get("GATECRASHER_CLIENT_KEYS"))
	for _, k := range []string{c.OrgAPIKey, c.AnthropicKey, c.WebhookSecret, c.SlackWebhook} {
		redact.Register(k, "KEY")
	}
	for _, m := range []map[string]string{c.ServerKeys, c.ClientKeys} {
		for _, v := range m {
			redact.Register(v, "KEY")
		}
	}
}

// parsePairs parses "Production=ser.x,Development=ser.y".
func parsePairs(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.TrimSpace(k) != "" && strings.TrimSpace(v) != "" {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

// Validate checks the config and builds the scope lock.
func (c *Config) Validate() error {
	u, err := url.Parse(c.Flagsmith.APIURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("flagsmith.api_url %q is not a valid http(s) URL", c.Flagsmith.APIURL)
	}
	apiHosts := c.Flagsmith.AllowedAPIHosts
	if len(apiHosts) == 0 {
		return errors.New("flagsmith.allowed_api_hosts is empty: list the Flagsmith API host(s) the agent may call")
	}
	lock, err := scope.New(c.AllowedDomains, apiHosts)
	if err != nil {
		return err
	}
	if err := lock.Check(u); err != nil {
		return fmt.Errorf("flagsmith.api_url: %w", err)
	}
	if c.TargetURL != "" {
		if err := lock.CheckURL(c.TargetURL); err != nil {
			return fmt.Errorf("target_url: %w", err)
		}
	}
	c.lock = lock
	return nil
}

// Lock returns the immutable scope lock.
func (c *Config) Lock() *scope.Lock { return c.lock }

// IsProduction reports whether env requires typed confirmation.
func (c *Config) IsProduction(env string) bool {
	for _, p := range c.Flagsmith.ProductionEnvironments {
		if strings.EqualFold(p, env) {
			return true
		}
	}
	return strings.EqualFold(env, "production") || strings.EqualFold(env, "prod")
}

// IsServerOnlyTrait reports whether the trait is set only by the server.
func (c *Config) IsServerOnlyTrait(key string) bool {
	for _, t := range c.ServerOnlyTraits {
		if strings.EqualFold(t, key) {
			return true
		}
	}
	return false
}

// IsTestIdentity reports whether id is an allowed identity-lookup target.
func (c *Config) IsTestIdentity(id string) bool {
	for _, t := range c.TestIdentities {
		if t == id {
			return true
		}
	}
	return false
}

// PropagationTimeout returns the max wait for a write to take effect.
func (c *Config) PropagationTimeout() time.Duration {
	return time.Duration(c.PropagationTimeoutS) * time.Second
}

// loadDotEnv sets variables from a KEY=VALUE file without overriding
// variables already present in the process environment.
func loadDotEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(strings.TrimPrefix(k, "export "))
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if _, exists := os.LookupEnv(k); !exists {
			_ = os.Setenv(k, v)
		}
	}
}
