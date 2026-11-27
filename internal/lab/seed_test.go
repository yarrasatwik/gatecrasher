package lab

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// seedFixture runs Seed against a stub Flagsmith with temp state/env files.
type seedFixture struct {
	t    *testing.T
	stub *stubFlagsmith
	opts Options
}

func newSeedFixture(t *testing.T) *seedFixture {
	t.Helper()
	stub := newStub()
	srv := stub.start(t)
	dir := t.TempDir()
	return &seedFixture{t: t, stub: stub, opts: Options{
		APIURL:    srv.URL + "/api/v1/",
		RepoRoot:  dir,
		DataPath:  filepath.Join("..", "..", "lab", "seed_data.yaml"),
		StatePath: filepath.Join(dir, ".state.json"),
		EnvPath:   filepath.Join(dir, ".env"),
	}}
}

func (s *seedFixture) seed() *State {
	s.t.Helper()
	st, err := Seed(context.Background(), s.opts)
	if err != nil {
		s.t.Fatalf("Seed: %v", err)
	}
	return st
}

func TestSeedCreatesDeclaredState(t *testing.T) {
	fx := newSeedFixture(t)
	st := fx.seed()
	f := fx.stub
	if len(f.projects) != 1 || len(f.envs) != 2 || len(f.features) != 11 || len(f.segments) != 4 {
		t.Fatalf("projects=%d envs=%d features=%d segments=%d", len(f.projects), len(f.envs), len(f.features), len(f.segments))
	}
	if len(f.exps) != 2 {
		t.Errorf("want one experiment per environment, got %d", len(f.exps))
	}
	for _, e := range f.envs {
		if e["allow_client_traits"] != true || e["hide_sensitive_data"] != false {
			t.Errorf("environment %v is not in the vulnerable state", e["name"])
		}
	}
	if len(f.links) != 8 {
		t.Errorf("want 4 segment overrides in each of 2 environments, got %d", len(f.links))
	}
	if len(st.Changes) == 0 {
		t.Error("first run must report changes")
	}
	for _, name := range []string{"Development", "Production"} {
		e := st.Environments[name]
		if e.ClientKey == "" || !strings.HasPrefix(e.ServerKey, "ser.") {
			t.Errorf("%s keys not captured: %+v", name, e)
		}
	}
}

func TestSeedIsIdempotent(t *testing.T) {
	fx := newSeedFixture(t)
	first := fx.seed()
	fx.stub.mutations = nil
	second := fx.seed()
	if len(second.Changes) != 0 {
		t.Fatalf("second run changed things: %v", second.Changes)
	}
	if len(fx.stub.mutations) != 0 {
		t.Fatalf("second run sent mutating requests: %v", fx.stub.mutations)
	}
	if first.PaymentSecret != second.PaymentSecret || first.OrgAPIKey != second.OrgAPIKey || first.AdminPassword != second.AdminPassword {
		t.Fatal("generated credentials must be stable across runs")
	}
}

func TestSeedWritesEnvWithoutLeakingSecrets(t *testing.T) {
	fx := newSeedFixture(t)
	st := fx.seed()
	raw, err := os.ReadFile(fx.opts.EnvPath)
	if err != nil {
		t.Fatal(err)
	}
	env := string(raw)
	for _, want := range []string{"GATECRASHER_ORG_API_KEY=" + st.OrgAPIKey, "GATECRASHER_API_URL=", "GATECRASHER_SERVER_KEYS=Development=ser.", ",Production=ser.", "GATECRASHER_CLIENT_KEYS=Development="} {
		if !strings.Contains(env, want) {
			t.Errorf(".env lacks %q:\n%s", want, redactEnv(env))
		}
	}
	if strings.Contains(env, st.PaymentSecret) || strings.Contains(env, st.AdminPassword) {
		t.Error(".env must not contain the payment secret or lab password")
	}
	state, _ := os.ReadFile(fx.opts.StatePath)
	if !regexp.MustCompile(`acme_live_[0-9a-f]{32}`).Match(state) {
		t.Error("state file should hold the generated secret")
	}
}

func redactEnv(s string) string {
	return regexp.MustCompile(`=\S{6,}`).ReplaceAllString(s, "=<redacted>")
}

func TestSeedStoresGeneratedSecretInFeatureValue(t *testing.T) {
	fx := newSeedFixture(t)
	st := fx.seed()
	for _, ft := range fx.stub.features {
		if ft["name"] == "payment_config" {
			if v, _ := ft["initial_value"].(string); !strings.Contains(v, st.PaymentSecret) || strings.Contains(v, SecretPlaceholder) {
				t.Fatalf("payment_config value not rendered: %q", v)
			}
			return
		}
	}
	t.Fatal("payment_config missing")
}

func TestResetRestoresEveryVulnerability(t *testing.T) {
	fx := newSeedFixture(t)
	fx.seed()
	f := fx.stub
	// Simulate a "fix": harden an environment, hide a flag, edit a segment, drop an override.
	f.envs[1]["allow_client_traits"] = false
	f.envs[1]["hide_sensitive_data"] = true
	for _, ft := range f.features {
		if ft["name"] == "payment_config" {
			ft["is_server_key_only"] = true
		}
	}
	f.segments[0]["rules"] = segmentRules([]ConditionData{{Property: "plan", Operator: "EQUAL", Value: "nobody"}})
	f.links[0]["segment"] = -1
	f.mutations = nil

	st, err := Reset(context.Background(), fx.opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Changes) < 4 {
		t.Fatalf("reset changes = %v", st.Changes)
	}
	if f.envs[1]["allow_client_traits"] != true || f.envs[1]["hide_sensitive_data"] != false {
		t.Error("environment settings not restored")
	}
	for _, ft := range f.features {
		if ft["is_server_key_only"] == true {
			t.Errorf("%v still server-side only", ft["name"])
		}
	}
	if ruleSig(segmentRulesFromStub(f.segments[0])) != ruleSig(segmentRules([]ConditionData{{Property: "plan", Operator: "EQUAL", Value: "gold"}})) {
		t.Error("segment rules not restored")
	}
	again, err := Reset(context.Background(), fx.opts)
	if err != nil || len(again.Changes) != 0 {
		t.Fatalf("second reset not a no-op: %v %v", again.Changes, err)
	}
}

func segmentRulesFromStub(seg map[string]any) []apiRule {
	raw, err := json.Marshal(seg["rules"])
	if err != nil {
		panic(err)
	}
	var rules []apiRule
	if err := json.Unmarshal(raw, &rules); err != nil {
		panic(err)
	}
	return rules
}

func TestResetRequiresExistingLab(t *testing.T) {
	fx := newSeedFixture(t)
	if _, err := Reset(context.Background(), fx.opts); err == nil || !strings.Contains(err.Error(), "seed") {
		t.Fatalf("want a 'run the seed first' error, got %v", err)
	}
}

func TestSeedRefusesForeignAdmin(t *testing.T) {
	fx := newSeedFixture(t)
	fx.stub.users["lab-admin@acmeshop.dev"] = "someone-elses-password"
	_, err := Seed(context.Background(), fx.opts)
	if err == nil || !strings.Contains(err.Error(), "cannot log in or sign up") {
		t.Fatalf("want a clear admin conflict error, got %v", err)
	}
	if len(fx.stub.projects) != 0 {
		t.Fatal("nothing may be created after the admin step fails")
	}
}
