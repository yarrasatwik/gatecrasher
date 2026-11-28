package config

import (
	"os"
	"testing"
)

const writeKeyEnv = "GATECRASHER_WRITE_API_KEY"

const minimalYAML = "allowed_domains: [localhost]\nflagsmith: {allowed_api_hosts: [\"localhost:8000\"]}\n"

// Audits, MCP, CI, watch, plan, report and parity load the configuration
// with Load, which must never read the write key, from the process
// environment or from .env.
func TestLoadNeverReadsTheWriteKey(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "gatecrasher.yaml", minimalYAML)

	t.Setenv(writeKeyEnv, "writekey1.abcdefghijklmnopqrstuvwxyz012345")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.WriteAPIKey != "" {
		t.Fatal("Load read GATECRASHER_WRITE_API_KEY from the environment")
	}

	// .env must not leak it into the process environment either.
	t.Setenv(writeKeyEnv, "")
	if err := os.Unsetenv(writeKeyEnv); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GATECRASHER_ORG_API_KEY", "")
	if err := os.Unsetenv("GATECRASHER_ORG_API_KEY"); err != nil {
		t.Fatal(err)
	}
	write(t, dir, ".env", "GATECRASHER_ORG_API_KEY=orgkey01.abcdefghijklmnopqrstuvwxyz012345\n"+writeKeyEnv+"=writekey1.abcdefghijklmnopqrstuvwxyz012345\n")
	t.Cleanup(func() { os.Unsetenv(writeKeyEnv); os.Unsetenv("GATECRASHER_ORG_API_KEY") })
	c, err = Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.WriteAPIKey != "" {
		t.Fatal("Load read the write key from .env")
	}
	if _, set := os.LookupEnv(writeKeyEnv); set {
		t.Fatal("Load put the write key from .env into the process environment")
	}
	if c.OrgAPIKey == "" {
		t.Fatal("the org key must still load")
	}
}

func TestLoadForWritesReadsTheWriteKey(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "gatecrasher.yaml", minimalYAML)
	t.Setenv(writeKeyEnv, "writekey1.abcdefghijklmnopqrstuvwxyz012345")
	c, err := LoadForWrites(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.WriteAPIKey != "writekey1.abcdefghijklmnopqrstuvwxyz012345" {
		t.Fatalf("write key = %q", c.WriteAPIKey)
	}

	t.Setenv(writeKeyEnv, "")
	if err := os.Unsetenv(writeKeyEnv); err != nil {
		t.Fatal(err)
	}
	write(t, dir, ".env", writeKeyEnv+"=fromdotenv.abcdefghijklmnopqrstuvwxyz012345\n")
	t.Cleanup(func() { os.Unsetenv(writeKeyEnv) })
	c, err = LoadForWrites(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.WriteAPIKey != "fromdotenv.abcdefghijklmnopqrstuvwxyz012345" {
		t.Fatalf("write key from .env = %q", c.WriteAPIKey)
	}
}
