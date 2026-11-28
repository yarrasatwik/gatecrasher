package config

import (
	"strings"
	"testing"
)

func TestProfileForURL(t *testing.T) {
	cases := map[string]string{
		"http://localhost:8000/api/v1/":      ProfileLab,
		"http://app.localhost:8000/api/v1/":  ProfileLab,
		"http://127.0.0.1:8000/api/v1/":      ProfileLab,
		"http://[::1]:8000/api/v1/":          ProfileLab,
		"http://10.1.2.3/api/v1/":            ProfileLab,
		"http://192.168.0.20:8000/api/v1/":   ProfileLab,
		"http://172.20.0.5:8000/api/v1/":     ProfileLab,
		"http://169.254.10.1/api/v1/":        ProfileLab,
		"https://edge.api.flagsmith.com/api": ProfileCloud,
		"https://flags.example.com/api/v1/":  ProfileCloud,
		"https://8.8.8.8/api/v1/":            ProfileCloud,
		"http://172.32.0.1/api/v1/":          ProfileCloud, // just outside 172.16/12
		"not a url":                          ProfileCloud,
	}
	for u, want := range cases {
		if got := ProfileForURL(u); got != want {
			t.Errorf("ProfileForURL(%q) = %s, want %s", u, got, want)
		}
	}
}

func loadProfileCfg(t *testing.T, yaml string) *Config {
	t.Helper()
	t.Setenv("GATECRASHER_API_URL", "")
	c, err := Load(write(t, t.TempDir(), "g.yaml", yaml))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestProfileDefaultsFollowTheAPIHost(t *testing.T) {
	lab := loadProfileCfg(t, "allowed_domains: [localhost]\nflagsmith: {allowed_api_hosts: [\"localhost:8000\"]}\n")
	if lab.ProfileName() != ProfileLab || lab.ParitySamples() != 1000 || lab.RerollSamples() != 200 {
		t.Fatalf("lab: %s parity=%d reroll=%d", lab.ProfileName(), lab.ParitySamples(), lab.RerollSamples())
	}
	cloud := loadProfileCfg(t, "flagsmith: {api_url: \"https://flags.example.com/api/v1/\", allowed_api_hosts: [flags.example.com]}\n")
	if cloud.ProfileName() != ProfileCloud || cloud.ParitySamples() != 200 || cloud.RerollSamples() != 100 {
		t.Fatalf("cloud: %s parity=%d reroll=%d", cloud.ProfileName(), cloud.ParitySamples(), cloud.RerollSamples())
	}
}

func TestProfileOverrideAndExplicitSamplesWin(t *testing.T) {
	c := loadProfileCfg(t, "profile: lab\nflagsmith: {api_url: \"https://flags.example.com/api/v1/\", allowed_api_hosts: [flags.example.com]}\n")
	if c.ProfileName() != ProfileLab || c.ParitySamples() != 1000 {
		t.Fatalf("config profile must override detection: %s %d", c.ProfileName(), c.ParitySamples())
	}
	if err := c.SetProfile("cloud"); err != nil || c.ProfileName() != ProfileCloud || c.RerollSamples() != 100 {
		t.Fatalf("--profile override failed: %v %s", err, c.ProfileName())
	}
	if err := c.SetProfile("auto"); err != nil || c.ProfileName() != ProfileCloud {
		t.Fatalf("auto must fall back to detection: %v %s", err, c.ProfileName())
	}
	if err := c.SetProfile("staging"); err == nil {
		t.Fatal("unknown profile accepted")
	}
	e := loadProfileCfg(t, "probes: {reroll_samples: 30, parity_samples: 50}\nallowed_domains: [localhost]\nflagsmith: {allowed_api_hosts: [\"localhost:8000\"]}\n")
	if e.RerollSamples() != 30 || e.ParitySamples() != 50 {
		t.Fatalf("explicit samples must win: %d %d", e.RerollSamples(), e.ParitySamples())
	}
}

func TestInvalidProfileInConfigRejected(t *testing.T) {
	_, err := Load(write(t, t.TempDir(), "g.yaml", "profile: prod\nallowed_domains: [localhost]\nflagsmith: {allowed_api_hosts: [\"localhost:8000\"]}\n"))
	if err == nil || !strings.Contains(err.Error(), "profile") {
		t.Fatalf("err = %v", err)
	}
}

func TestBudgetAndWatchLimitsDefaults(t *testing.T) {
	c := loadProfileCfg(t, "allowed_domains: [localhost]\nflagsmith: {allowed_api_hosts: [\"localhost:8000\"]}\n")
	if c.Probes.MaxRequests != 0 || c.Watch.MaxRequestsPerHour != 500 {
		t.Fatalf("max_requests=%d watch/h=%d, want 0 and 500", c.Probes.MaxRequests, c.Watch.MaxRequestsPerHour)
	}
	e := loadProfileCfg(t, "probes: {max_requests: 120}\nwatch: {max_requests_per_hour: 80}\nallowed_domains: [localhost]\nflagsmith: {allowed_api_hosts: [\"localhost:8000\"]}\n")
	if e.Probes.MaxRequests != 120 || e.Watch.MaxRequestsPerHour != 80 {
		t.Fatalf("max_requests=%d watch/h=%d", e.Probes.MaxRequests, e.Watch.MaxRequestsPerHour)
	}
	if _, err := Load(write(t, t.TempDir(), "g.yaml", "probes: {max_requests: -1}\nallowed_domains: [localhost]\nflagsmith: {allowed_api_hosts: [\"localhost:8000\"]}\n")); err == nil {
		t.Fatal("negative max_requests accepted")
	}
}
