// Package config loads gatecrasher.yaml plus environment variables and
// builds the immutable scope lock. Secrets only ever come from the
// environment (or a git-ignored .env file), never from the YAML.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
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
	// ProductionEnvironments is the older name for the top-level
	// protected_environments list; both are read and merged.
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
	// ParitySamples overrides the profile's parity sample count (0 = profile).
	ParitySamples int `yaml:"parity_samples"`
	// MaxRequests caps the requests one audit sends (0 = no cap); unfinished
	// stages are reported "incomplete (budget)". --budget overrides it.
	MaxRequests int `yaml:"max_requests"`
}

// DefaultAIConcurrency and MaxAIConcurrency bound the parallel AI calls.
const (
	DefaultAIConcurrency = 4
	MaxAIConcurrency     = 32
)

// AISettings selects the AI provider and how many calls run in parallel.
// In YAML it is a scalar (the provider) or a mapping with provider and
// concurrency.
type AISettings struct {
	Provider    string `yaml:"provider"`
	Concurrency int    `yaml:"concurrency"`
}

// UnmarshalYAML accepts "ai: off" as well as "ai: {provider: off, concurrency: 8}".
func (a *AISettings) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		return n.Decode(&a.Provider)
	}
	type plain AISettings
	var p plain
	for i := 0; i+1 < len(n.Content); i += 2 {
		switch k := n.Content[i].Value; k {
		case "provider", "concurrency":
		default:
			return fmt.Errorf("line %d: field %s not found in ai (want provider, concurrency)", n.Content[i].Line, k)
		}
	}
	if err := n.Decode(&p); err != nil {
		return err
	}
	*a = AISettings(p)
	return nil
}

// Recon tunes Stage 1 (reading the target page and its scripts).
type Recon struct {
	// MaxScripts bounds how many script resources one recon run fetches
	// (page scripts plus the chunks they preload or import). Default 60.
	MaxScripts int `yaml:"max_scripts"`
}

// Watch configures the webhook receiver.
type Watch struct {
	Listen    string `yaml:"listen"`
	PublicURL string `yaml:"public_url"`
	// MaxRequestsPerHour caps the requests webhook re-checks may send in any
	// rolling hour (default 500).
	MaxRequestsPerHour int `yaml:"max_requests_per_hour"`
}

// Config is the full runtime configuration.
type Config struct {
	TargetURL      string    `yaml:"target_url"`
	AllowedDomains []string  `yaml:"allowed_domains"`
	Flagsmith      Flagsmith `yaml:"flagsmith"`
	// ProtectedEnvironments can only be changed by a person: approvals need
	// a real terminal or the web UI and are refused inside agent and CI
	// sessions. An environment named Production is always protected.
	ProtectedEnvironments []string `yaml:"protected_environments"`
	TestIdentities        []string `yaml:"test_identities"`
	ServerOnlyTraits      []string `yaml:"server_only_traits"`
	ClientSetsIdentifier  *bool    `yaml:"client_sets_identifier"`
	// Profile is "lab" or "cloud"; empty or "auto" picks one from the API
	// host (a non-local, non-private host is "cloud").
	Profile             string `yaml:"profile"`
	AppRepo             string `yaml:"app_repo"`
	Probes              Probes `yaml:"probes"`
	Recon               Recon  `yaml:"recon"`
	PropagationTimeoutS int    `yaml:"propagation_timeout_s"`
	ApprovalTTLMinutes  int    `yaml:"approval_ttl_minutes"`
	StateDir            string `yaml:"state_dir"`
	// AI selects the AI provider: "api" (ANTHROPIC_API_KEY), "claude-code"
	// (a signed-in Claude Code CLI) or "off". Empty means "api" when a key
	// is set, else off.
	// It is either a bare provider name (ai: off) or a mapping
	// (ai: {provider: api, concurrency: 4}).
	AI        AISettings `yaml:"ai"`
	ReportDir string     `yaml:"report_dir"`
	Watch     Watch      `yaml:"watch"`

	// From the environment (never YAML).
	OrgAPIKey string `yaml:"-"`
	// WriteAPIKey is GATECRASHER_WRITE_API_KEY, used only to apply and roll
	// back. It is empty unless the config was loaded with LoadForWrites.
	WriteAPIKey   string            `yaml:"-"`
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
	if c.Recon.MaxScripts <= 0 {
		c.Recon.MaxScripts = 60
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
	if c.AI.Concurrency <= 0 {
		c.AI.Concurrency = DefaultAIConcurrency
	}
	if c.AI.Concurrency > MaxAIConcurrency {
		c.AI.Concurrency = MaxAIConcurrency
	}
	if c.Watch.MaxRequestsPerHour == 0 {
		c.Watch.MaxRequestsPerHour = 500
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

// WriteKeyEnv names the environment variable that holds the write key.
const WriteKeyEnv = "GATECRASHER_WRITE_API_KEY"

// Load reads the YAML file at path (optional if empty and not present),
// loads .env (if present) and the process environment, validates, and
// builds the scope lock.
func Load(path string) (*Config, error) { return load(path, false) }

// LoadForWrites is Load plus GATECRASHER_WRITE_API_KEY. Only `serve` and the
// interactive terminal write paths call it; audits, CI, watch, plan, report,
// parity and the MCP server use Load and never see the write key.
func LoadForWrites(path string) (*Config, error) { return load(path, true) }

func load(path string, withWriteKey bool) (*Config, error) {
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
	loadDotEnv(filepath.Join(dir, ".env"), withWriteKey)
	c.fromEnv(withWriteKey)
	c.Defaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) fromEnv(withWriteKey bool) {
	get := os.Getenv
	if v := get("GATECRASHER_TARGET_URL"); v != "" && c.TargetURL == "" {
		c.TargetURL = v
	}
	if v := get("GATECRASHER_API_URL"); v != "" {
		c.Flagsmith.APIURL = v
	}
	c.OrgAPIKey = get("GATECRASHER_ORG_API_KEY")
	if withWriteKey {
		c.WriteAPIKey = get(WriteKeyEnv)
		redact.Register(c.WriteAPIKey, "KEY")
	}
	c.AnthropicKey = get("ANTHROPIC_API_KEY")
	if v := get("GATECRASHER_AI"); v != "" {
		c.AI.Provider = v
	}
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
	if err := checkProfile(c.Profile); err != nil {
		return err
	}
	if c.Probes.MaxRequests < 0 || c.Watch.MaxRequestsPerHour < 0 || c.Probes.ParitySamples < 0 {
		return errors.New("probes.max_requests, probes.parity_samples and watch.max_requests_per_hour must not be negative")
	}
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

// Protected lists the protected environments: protected_environments plus
// the older flagsmith.production_environments, and always "Production".
// Configuration can add to the list but never take Production off it.
func (c *Config) Protected() []string {
	var out []string
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		for _, have := range out {
			if strings.EqualFold(have, name) {
				return
			}
		}
		out = append(out, name)
	}
	for _, p := range c.ProtectedEnvironments {
		add(p)
	}
	for _, p := range c.Flagsmith.ProductionEnvironments {
		add(p)
	}
	add("Production")
	return out
}

// IsProtected reports whether changes to env need a person at a real
// terminal or in the web UI. Names match case-insensitively; "prod" is
// treated like "Production".
func (c *Config) IsProtected(env string) bool {
	env = strings.TrimSpace(env)
	for _, p := range c.Protected() {
		if strings.EqualFold(p, env) {
			return true
		}
	}
	return strings.EqualFold(env, "prod")
}

// IsProduction is the older name for IsProtected.
func (c *Config) IsProduction(env string) bool { return c.IsProtected(env) }

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
func loadDotEnv(path string, withWriteKey bool) {
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
		if k == WriteKeyEnv && !withWriteKey {
			continue // keep the write key out of processes that never write
		}
		if _, exists := os.LookupEnv(k); !exists {
			_ = os.Setenv(k, v)
		}
	}
}

// Profiles tune how many probes an audit sends. "lab" is a local or private
// Flagsmith you own (probe freely); "cloud" is anything else (be polite).
const (
	ProfileLab   = "lab"
	ProfileCloud = "cloud"
)

func checkProfile(p string) error {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "", "auto", ProfileLab, ProfileCloud:
		return nil
	}
	return fmt.Errorf("profile %q is not valid (want lab, cloud or auto)", p)
}

// ProfileForURL picks the profile for an API URL: localhost, loopback,
// private and link-local addresses are "lab"; everything else is "cloud".
func ProfileForURL(apiURL string) string {
	u, err := url.Parse(apiURL)
	if err != nil || u.Hostname() == "" {
		return ProfileCloud
	}
	h := strings.ToLower(u.Hostname())
	if h == "localhost" || strings.HasSuffix(h, ".localhost") || h == "host.docker.internal" {
		return ProfileLab
	}
	if ip := net.ParseIP(h); ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
		return ProfileLab
	}
	return ProfileCloud
}

// ProfileName is the active profile: the configured (or --profile) value, or
// the one detected from the API host.
func (c *Config) ProfileName() string {
	switch p := strings.ToLower(strings.TrimSpace(c.Profile)); p {
	case ProfileLab, ProfileCloud:
		return p
	}
	return ProfileForURL(c.Flagsmith.APIURL)
}

// SetProfile overrides the profile ("auto" or "" restores detection).
func (c *Config) SetProfile(p string) error {
	if err := checkProfile(p); err != nil {
		return err
	}
	c.Profile = strings.ToLower(strings.TrimSpace(p))
	return nil
}

// ParitySamples is the engine-vs-live parity sample count: probes.parity_samples
// when set, else 1000 for lab and 200 for cloud.
func (c *Config) ParitySamples() int {
	if c.Probes.ParitySamples > 0 {
		return c.Probes.ParitySamples
	}
	if c.ProfileName() == ProfileCloud {
		return 200
	}
	return 1000
}

// RerollSamples is the identifier re-roll sample count: probes.reroll_samples
// when set, else 200 for lab and 100 for cloud.
func (c *Config) RerollSamples() int {
	if c.Probes.RerollSamples != 0 {
		return c.Probes.RerollSamples
	}
	if c.ProfileName() == ProfileCloud {
		return 100
	}
	return 200
}
