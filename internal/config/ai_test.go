package config

import (
	"strings"
	"testing"
)

const aiBase = "allowed_domains: [localhost]\nflagsmith: {allowed_api_hosts: [\"localhost:8000\"]}\n"

func TestAIScalarKeepsWorkingAndDefaultsConcurrency(t *testing.T) {
	t.Setenv("GATECRASHER_AI", "")
	c, err := Load(write(t, t.TempDir(), "g.yaml", "ai: claude-code\n"+aiBase))
	if err != nil {
		t.Fatal(err)
	}
	if c.AI.Provider != "claude-code" || c.AI.Concurrency != 4 {
		t.Fatalf("ai = %+v, want provider claude-code, concurrency 4", c.AI)
	}
}

func TestAIMappingSetsConcurrency(t *testing.T) {
	t.Setenv("GATECRASHER_AI", "")
	c, err := Load(write(t, t.TempDir(), "g.yaml", "ai:\n  provider: off\n  concurrency: 7\n"+aiBase))
	if err != nil {
		t.Fatal(err)
	}
	if c.AI.Provider != "off" || c.AI.Concurrency != 7 {
		t.Fatalf("ai = %+v", c.AI)
	}
}

func TestAIConcurrencyIsClampedAndUnknownKeysRejected(t *testing.T) {
	t.Setenv("GATECRASHER_AI", "")
	c, err := Load(write(t, t.TempDir(), "g.yaml", "ai: {concurrency: 9999}\n"+aiBase))
	if err != nil {
		t.Fatal(err)
	}
	if c.AI.Concurrency != MaxAIConcurrency {
		t.Fatalf("concurrency = %d, want clamp to %d", c.AI.Concurrency, MaxAIConcurrency)
	}
	_, err = Load(write(t, t.TempDir(), "g.yaml", "ai: {concurency: 2}\n"+aiBase))
	if err == nil || !strings.Contains(err.Error(), "concurency") {
		t.Fatalf("unknown ai key must be rejected, got %v", err)
	}
}
