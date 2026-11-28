package verify

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

// fakeTarget is a scripted Flagsmith environment: a 10% rollout decided by
// the identifier, a trait-gated flag, and the two environment settings.
type fakeTarget struct {
	clientVisible map[string]bool   // flags the client key receives
	rollout       map[string]bool   // identifier -> inside the rollout
	rolloutFlag   string            // flag the rollout turns on ("" = rollout removed)
	traitFlag     map[string]string // "key=value" -> flag it unlocks
	settings      Settings
	clientSetsID  bool
	serverErr     error
}

func (t *fakeTarget) eval(id string, traits map[string]string) map[string]string {
	out := map[string]string{"early_access_ai": "off", "premium_export": "off", "banner": "on: hello"}
	if t.rolloutFlag != "" && t.rollout[id] {
		out[t.rolloutFlag] = "on"
	}
	for k, v := range traits {
		if flag, ok := t.traitFlag[k+"="+v]; ok {
			out[flag] = "on"
		}
	}
	return out
}

func (t *fakeTarget) visible(all map[string]string) map[string]string {
	out := map[string]string{}
	for name, st := range all {
		if t.clientVisible[name] {
			out[name] = st
		}
	}
	return out
}

func (t *fakeTarget) Settings(context.Context) (Settings, error) { return t.settings, nil }

func (t *fakeTarget) ClientFlags(context.Context) (map[string]string, string, error) {
	return t.visible(t.eval("", nil)), "GET /flags/", nil
}

func (t *fakeTarget) ClientIdentify(_ context.Context, id string, traits map[string]string) (map[string]string, string, error) {
	if !t.settings.AllowClientTraits {
		traits = nil
	}
	return t.visible(t.eval(id, traits)), "POST /identities/ " + id, nil
}

func (t *fakeTarget) ServerEvaluate(_ context.Context, id string, traits map[string]string) (map[string]string, error) {
	if t.serverErr != nil {
		return nil, t.serverErr
	}
	return t.eval(id, traits), nil
}

func (t *fakeTarget) ReplayLookup(context.Context, model.Finding) (model.Status, string, bool, error) {
	return "", "", false, nil
}

func (t *fakeTarget) ClientSetsIdentifier() bool { return t.clientSetsID }

func labTarget() *fakeTarget {
	return &fakeTarget{
		clientVisible: map[string]bool{"early_access_ai": true, "premium_export": true, "banner": true},
		rollout:       map[string]bool{"gc-probe-map-9": true, RerollIdentifier(7): true},
		rolloutFlag:   "early_access_ai",
		traitFlag:     map[string]string{"plan=gold": "premium_export"},
		settings:      Settings{AllowClientTraits: true},
		clientSetsID:  true,
	}
}

func rerollFinding(t model.FindingType) model.Finding {
	return model.Finding{ID: "GC-ROLL", Type: t, Subject: "early_access_ai", Status: model.StatusExploitable,
		ProofID: "gc-probe-map-9", Unlocked: []model.FlagChange{{Flag: "early_access_ai", Before: "off", After: "on"}}}
}

// The A1 regression: Server-side only hides the flag from client SDKs but the
// percentage split is still there, so the finding is HIDDEN, never BLOCKED.
func TestRerollFixedOnlyByServerSideOnlyIsHiddenNotBlocked(t *testing.T) {
	for _, ft := range []model.FindingType{model.FPercentageReroll, model.FVariantReroll, model.FExperimentRigging} {
		tg := labTarget()
		if st, _, err := Check(context.Background(), tg, rerollFinding(ft)); err != nil || st != model.StatusExploitable {
			t.Fatalf("%s before any fix: %s %v, want EXPLOITABLE", ft, st, err)
		}
		tg.clientVisible["early_access_ai"] = false // the only change: Server-side only
		st, proof, err := Check(context.Background(), tg, rerollFinding(ft))
		if err != nil {
			t.Fatalf("%s: %v", ft, err)
		}
		if st != model.StatusHidden {
			t.Fatalf("%s fixed only by Server-side only = %s, want HIDDEN (%s)", ft, st, proof)
		}
		if !strings.Contains(proof, "no longer served to client SDKs") || !strings.Contains(proof, "gc-probe-map-9") {
			t.Fatalf("%s proof does not explain the hidden mechanism: %q", ft, proof)
		}
	}
}

func TestRerollBlockedOnlyWhenTheMechanismIsGone(t *testing.T) {
	// Rollout removed: no identifier reaches the state any more.
	tg := labTarget()
	tg.rolloutFlag = ""
	if st, proof, err := Check(context.Background(), tg, rerollFinding(model.FPercentageReroll)); err != nil || st != model.StatusBlocked {
		t.Fatalf("rollout removed = %s %v (%s), want BLOCKED", st, err, proof)
	}
	// Rollout removed and the flag is server-only as well.
	tg.clientVisible["early_access_ai"] = false
	if st, _, err := Check(context.Background(), tg, rerollFinding(model.FPercentageReroll)); err != nil || st != model.StatusBlocked {
		t.Fatalf("rollout removed + server-only = %s %v, want BLOCKED", st, err)
	}
	// Identifiers assigned on the server (declared in config).
	tg = labTarget()
	tg.clientSetsID = false
	if st, proof, err := Check(context.Background(), tg, rerollFinding(model.FPercentageReroll)); err != nil || st != model.StatusBlocked || !strings.Contains(proof, "server") {
		t.Fatalf("server-assigned identifiers = %s %v (%s), want BLOCKED", st, err, proof)
	}
}

// The re-run repeats the attack (keep choosing identifiers), so a re-salted
// rollout that no longer includes the old proof identifier is still found.
func TestRerollReRunsTheAttackNotJustTheOldIdentifier(t *testing.T) {
	tg := labTarget()
	delete(tg.rollout, "gc-probe-map-9")
	st, proof, err := Check(context.Background(), tg, rerollFinding(model.FPercentageReroll))
	if err != nil || st != model.StatusExploitable {
		t.Fatalf("re-salted rollout = %s %v (%s), want EXPLOITABLE", st, err, proof)
	}
	if !strings.Contains(proof, RerollIdentifier(7)) {
		t.Fatalf("proof should name the identifier that hit: %q", proof)
	}
	tg.clientVisible["early_access_ai"] = false
	if st, _, _ := Check(context.Background(), tg, rerollFinding(model.FPercentageReroll)); st != model.StatusHidden {
		t.Fatalf("re-salted + server-only = %s, want HIDDEN", st)
	}
}

func TestHiddenNeedsTheServerPathNeverGuessed(t *testing.T) {
	tg := labTarget()
	tg.clientVisible["early_access_ai"] = false
	tg.serverErr = errors.New("environment document unavailable")
	st, _, err := Check(context.Background(), tg, rerollFinding(model.FPercentageReroll))
	if err == nil || st != model.StatusUnknown {
		t.Fatalf("server path unreadable = %s %v, want UNKNOWN with an error (never BLOCKED)", st, err)
	}
}

func forgeryFinding() model.Finding {
	return model.Finding{ID: "GC-FORGE", Type: model.FTraitForgery, Subject: "gold_plan", Status: model.StatusExploitable,
		Traits: map[string]string{"plan": "gold"}, Unlocked: []model.FlagChange{{Flag: "premium_export", Before: "off", After: "on"}}}
}

func TestForgeryReRunsTheForgedIdentity(t *testing.T) {
	tg := labTarget()
	if st, _, err := Check(context.Background(), tg, forgeryFinding()); err != nil || st != model.StatusExploitable {
		t.Fatalf("forgery = %s %v, want EXPLOITABLE", st, err)
	}
	tg.settings.AllowClientTraits = false
	if st, _, err := Check(context.Background(), tg, forgeryFinding()); err != nil || st != model.StatusBlocked {
		t.Fatalf("client traits off = %s %v, want BLOCKED", st, err)
	}
	// Server-side only alone: clients can still write the trait a server will read.
	tg = labTarget()
	tg.clientVisible["premium_export"] = false
	if st, _, err := Check(context.Background(), tg, forgeryFinding()); err != nil || st != model.StatusHidden {
		t.Fatalf("forgery hidden by Server-side only = %s %v, want HIDDEN", st, err)
	}
	tg.settings.AllowClientTraits = false
	if st, _, err := Check(context.Background(), tg, forgeryFinding()); err != nil || st != model.StatusBlocked {
		t.Fatalf("server-only + client traits off = %s %v, want BLOCKED", st, err)
	}
}

func TestSettingAndLeakChecks(t *testing.T) {
	tg := labTarget()
	ctx := context.Background()
	on := model.Finding{Type: model.FSettingClientTraitsOn}
	if st, _, _ := Check(ctx, tg, on); st != model.StatusExploitable {
		t.Fatalf("client traits on = %s", st)
	}
	sens := model.Finding{Type: model.FSettingSensitiveData}
	if st, _, _ := Check(ctx, tg, sens); st != model.StatusExploitable {
		t.Fatalf("sensitive data visible = %s", st)
	}
	tg.settings = Settings{AllowClientTraits: false, HideSensitiveData: true}
	if st, _, _ := Check(ctx, tg, on); st != model.StatusBlocked {
		t.Fatalf("client traits off = %s", st)
	}
	if st, _, _ := Check(ctx, tg, sens); st != model.StatusBlocked {
		t.Fatalf("sensitive data hidden = %s", st)
	}
	if st, _, _ := Check(ctx, tg, model.Finding{Type: model.FIdentityTraitLeak}); st != model.StatusBlocked {
		t.Fatalf("trait leak with hide_sensitive_data on = %s", st)
	}
	leak := model.Finding{Type: model.FSecretExposed, Subject: "banner"}
	if st, _, _ := Check(ctx, tg, leak); st != model.StatusExploitable {
		t.Fatalf("visible leak = %s", st)
	}
	tg.clientVisible["banner"] = false
	if st, _, _ := Check(ctx, tg, leak); st != model.StatusBlocked {
		t.Fatalf("server-only leak = %s", st)
	}
	if st, _, err := Check(ctx, tg, model.Finding{Type: "SOMETHING_NEW"}); err == nil || st != model.StatusUnknown {
		t.Fatalf("unknown type = %s %v", st, err)
	}
	if st, _, err := Check(ctx, tg, model.Finding{Type: model.FPercentageReroll}); err == nil || st != model.StatusUnknown {
		t.Fatalf("reroll without a flag change = %s %v", st, err)
	}
}

func TestRerunListsPartiallyMitigatedAndNeverCountsThemAsClosed(t *testing.T) {
	rec := &model.PlanRecord{Plan: model.Plan{FindingsAddressed: []string{"GC-LEAK"}, PartiallyMitigated: []string{"GC-ROLL"}}}
	findings := []model.Finding{{ID: "GC-LEAK", Status: model.StatusExploitable}, {ID: "GC-ROLL", Status: model.StatusExploitable}}
	rows := Rerun(context.Background(), rec, findings, func(_ context.Context, f model.Finding) (model.Status, string, error) {
		if f.ID == "GC-ROLL" {
			return model.StatusHidden, "hidden", nil
		}
		return model.StatusBlocked, "gone", nil
	})
	if len(rows) != 2 || rows[1].FindingID != "GC-ROLL" || !rows[1].PartiallyMitigated || rows[1].After != model.StatusHidden {
		t.Fatalf("rows = %+v", rows)
	}
	if !AllBlocked(rows) {
		t.Fatal("the plan closed everything it claimed to close")
	}
	if StillOpen(rows) != 1 {
		t.Fatalf("StillOpen = %d, want 1 (HIDDEN is still open)", StillOpen(rows))
	}
	if AllBlocked(rows[1:]) {
		t.Fatal("a plan with only partially mitigated rows closed nothing")
	}
}
