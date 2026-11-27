package attacks

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/ai"
	"github.com/yarrasatwik/gatecrasher/internal/config"
	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
	"github.com/yarrasatwik/gatecrasher/internal/httpx"
	labstate "github.com/yarrasatwik/gatecrasher/internal/lab"
	"github.com/yarrasatwik/gatecrasher/internal/model"
)

// Opt-in smoke test for the seeded local lab. Never seeds or resets its settings.
func TestLocalLab(t *testing.T) {
	if os.Getenv("GATECRASHER_ATTACKS_LAB") != "1" {
		t.Skip("set GATECRASHER_ATTACKS_LAB=1 to probe the configured local lab")
	}
	cfg, err := config.Load("../../gatecrasher.yaml")
	if err != nil {
		t.Fatal(err)
	}
	state, err := labstate.LoadState("../../lab/.state.json")
	if err != nil || state == nil {
		t.Fatal("seeded local lab state is required")
	}
	sdk := flagsmith.NewSDK(httpx.New(cfg.Lock(), httpx.WithRate(60), httpx.WithRetries(0)), cfg.Flagsmith.APIURL, state.Environments["Production"].ClientKey)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	baseline, err := sdk.Identify(ctx, freshID(), nil)
	if err != nil {
		t.Fatal(err)
	}
	runner := New(sdk, Options{Environment: "Production", TestIdentities: cfg.TestIdentities, MaxCombos: 4, RerollSamples: 50, ClientSetsIdentifier: true})
	fs, err := runner.Run(ctx, baseline.Flags, []ai.Hypothesis{{TraitKey: "plan", TraitValue: "gold"}, {TraitKey: "role", TraitValue: "admin"}, {TraitKey: "email", TraitValue: "probe@acmeshop.dev"}})
	if err != nil {
		t.Fatal(err)
	}
	counts := map[model.FindingType]int{}
	for _, f := range fs {
		counts[f.Type]++
		st, _, err := runner.Recheck(ctx, f)
		if err != nil || st != model.StatusExploitable {
			t.Fatalf("%s recheck: %s %v", f.Type, st, err)
		}
	}
	t.Logf("local lab: %d confirmed findings; types=%v", len(fs), counts)
}
