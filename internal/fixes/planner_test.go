package fixes

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

func opKinds(p model.Plan) []string {
	var out []string
	for _, o := range p.Operations {
		out = append(out, o.Kind)
	}
	return out
}

func TestPlannerClientTraitsPlan(t *testing.T) {
	h := newHarness(t)
	repo := shopApp(t)
	plans, err := h.planner(repo).Plan(t.Context(), []model.Finding{traitFinding(), leakFinding(),
		{ID: "GC-OK", Type: model.FControlOK, Environment: "Production"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 1 {
		t.Fatalf("want one environment plan, got %d", len(plans))
	}
	p := plans[0]
	if !regexp.MustCompile(`^plan-[0-9a-f]{8}$`).MatchString(p.ID) {
		t.Fatalf("plan id %q", p.ID)
	}
	if p.Environment != "Production" || !p.Production || p.TargetObject != "environment:Production" {
		t.Fatalf("identity wrong: %+v", p)
	}
	if got := strings.Join(opKinds(p), ","); got != "env.patch,env.patch,pr.draft" {
		t.Fatalf("operations = %s", got)
	}
	a, b := p.Operations[0], p.Operations[1]
	if a.Method != "PATCH" || a.Path != "environments/"+testEnvKey+"/" || a.Body["allow_client_traits"] != false || a.Before["allow_client_traits"] != true || !a.Automatic {
		t.Fatalf("op0 = %+v", a)
	}
	if b.Body["hide_sensitive_data"] != true || b.Before["hide_sensitive_data"] != false {
		t.Fatalf("op1 = %+v", b)
	}
	if len(p.BeforeSnapshot) != 2 || p.BeforeSnapshot["allow_client_traits"] != true || p.BeforeSnapshot["hide_sensitive_data"] != false {
		t.Fatalf("snapshot must hold exactly the changed fields: %v", p.BeforeSnapshot)
	}
	if len(p.FindingsAddressed) != 2 || p.Hash == "" || p.Hash != p.ComputeHash() {
		t.Fatalf("findings/hash wrong: %+v", p)
	}
	var plan, locale *model.ImpactItem
	for i := range p.Impact {
		switch {
		case strings.Contains(p.Impact[i].Message, "`plan`"):
			plan = &p.Impact[i]
		case strings.Contains(p.Impact[i].Message, "`locale`"):
			locale = &p.Impact[i]
		}
	}
	want := "This will break: lab/shop/static/app.js:42 sets `plan` client-side. Move it to your server (PR draft attached)."
	if plan == nil || plan.Message != want || !plan.Breaks || plan.Line != 42 {
		t.Fatalf("plan impact = %+v", plan)
	}
	if locale == nil || locale.Breaks {
		t.Fatalf("locale is used by no segment and must not be flagged as breaking: %+v", locale)
	}
	if len(p.Operations[2].Draft) == 0 || p.Operations[2].Automatic {
		t.Fatalf("pr draft missing or automatic: %+v", p.Operations[2])
	}
}

func TestPlannerHashSurvivesStoreRoundTrip(t *testing.T) {
	h := newHarness(t)
	recs := h.planFor(t, shopApp(t), traitFinding(), secretFinding())
	for _, r := range recs {
		got, err := h.store.Get(r.Plan.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Plan.ComputeHash() != got.Plan.Hash {
			t.Fatalf("hash changed through the store for %s", r.Plan.ID)
		}
	}
}

func TestPlannerServerOnlyPlanAndExperiment(t *testing.T) {
	h := newHarness(t)
	h.stub.experiments = []map[string]any{{"id": float64(1), "name": "checkout test", "status": "RUNNING", "feature": float64(5)}}
	plans, err := h.planner(shopApp(t)).Plan(t.Context(), []model.Finding{secretFinding()})
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 1 {
		t.Fatalf("plans = %d", len(plans))
	}
	p := plans[0]
	if got := strings.Join(opKinds(p), ","); got != "feature.patch,pr.draft,manual" {
		t.Fatalf("operations = %s", got)
	}
	fp := p.Operations[0]
	if fp.Path != "projects/1/features/5/" || fp.Body["is_server_key_only"] != true || fp.Before["is_server_key_only"] != false {
		t.Fatalf("feature op = %+v", fp)
	}
	if !strings.Contains(p.Operations[2].Description, "Rotate the secret") {
		t.Fatalf("rotate instruction missing: %+v", p.Operations[2])
	}
	if len(p.Impact) != 1 || !p.Impact[0].Breaks || !strings.Contains(p.Impact[0].Message, "app.js:44 reads `payment_config` in client code") {
		t.Fatalf("impact = %+v", p.Impact)
	}
	if !strings.Contains(p.ExperimentWarning, "contaminates experiment") {
		t.Fatalf("experiment warning = %q", p.ExperimentWarning)
	}
}

func TestPlannerRerollIsGuidanceOnly(t *testing.T) {
	h := newHarness(t)
	f := model.Finding{ID: "GC-RIG", Type: model.FExperimentRigging, Environment: "Production", Subject: "checkout_ab", Status: model.StatusExploitable}
	h.stub.experiments = []map[string]any{{"id": float64(1), "name": "ab", "status": "RUNNING", "feature": float64(6)}}
	plans, err := h.planner("").Plan(t.Context(), []model.Finding{f})
	if err != nil || len(plans) != 1 {
		t.Fatalf("plans=%d err=%v", len(plans), err)
	}
	p := plans[0]
	for _, o := range p.Operations {
		if o.Automatic {
			t.Fatalf("reroll plans must have no automatic operation: %+v", o)
		}
	}
	joined, _ := json.Marshal(p.Operations)
	if !strings.Contains(string(joined), "never stops or restarts experiments") || strings.Contains(string(joined), "stop the experiment now") {
		t.Fatalf("experiment guidance wrong: %s", joined)
	}
	if p.ExperimentWarning != "" {
		t.Fatalf("no write happens, so there is nothing to contaminate: %q", p.ExperimentWarning)
	}
	rec := &model.PlanRecord{Plan: p, State: model.PlanPending}
	if err := Approve(rec, "me", "cli", "Production", "", 0); err != nil {
		t.Fatal(err)
	}
	if err := h.applier().Apply(t.Context(), rec); err == nil || !strings.Contains(err.Error(), "no automatic operations") {
		t.Fatalf("applying guidance-only plan: %v", err)
	}
}

func TestPlannerSkipsFixedAndReportsUnknown(t *testing.T) {
	h := newHarness(t)
	h.stub.set("allow_client_traits", false)
	bad := traitFinding()
	bad.ID, bad.Environment = "GC-X", "Nowhere"
	plans, err := h.planner("").Plan(t.Context(), []model.Finding{traitFinding(), secretFinding(), bad})
	if err == nil || !strings.Contains(err.Error(), `unknown environment "Nowhere"`) {
		t.Fatalf("err = %v", err)
	}
	if len(plans) != 1 || plans[0].TargetObject != "feature:payment_config" {
		t.Fatalf("plans = %+v", plans)
	}
}

func TestPlannerOnePlanPerEnvironmentAndTarget(t *testing.T) {
	h := newHarness(t)
	other := secretFinding()
	other.ID, other.Subject = "GC-SECRET02", "checkout_ab"
	stage := traitFinding()
	stage.ID, stage.Environment = "GC-STAGE", "Staging"
	plans, _ := h.planner("").Plan(t.Context(), []model.Finding{secretFinding(), other, traitFinding(), stage})
	targets := map[string]bool{}
	for _, p := range plans {
		targets[p.Environment+"/"+p.TargetObject] = true
	}
	for _, want := range []string{"Production/feature:payment_config", "Production/feature:checkout_ab", "Production/environment:Production", "Staging/environment:Staging"} {
		if !targets[want] {
			t.Fatalf("missing plan %s in %v", want, targets)
		}
	}
	if len(plans) != 4 {
		t.Fatalf("plans = %d", len(plans))
	}
}

func TestCustomDraftFuncIsUsedAndRedacted(t *testing.T) {
	h := newHarness(t)
	key := "ser." + strings.Repeat("cd", 12)
	pl := h.planner(shopApp(t))
	pl.draft = func(f model.Finding, impact []model.ImpactItem) string { return "ai draft for " + f.ID + " " + key }
	plans, err := pl.Plan(t.Context(), []model.Finding{traitFinding()})
	if err != nil {
		t.Fatal(err)
	}
	d := plans[0].Operations[len(plans[0].Operations)-1].Draft
	if !strings.HasPrefix(d, "ai draft for GC-TRAIT01") || strings.Contains(d, key) {
		t.Fatalf("draft = %q", d)
	}
}

func TestDefaultDraftIsARealApplicableDiff(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	h := newHarness(t)
	repo := shopApp(t)
	plans, err := h.planner(repo).Plan(t.Context(), []model.Finding{traitFinding()})
	if err != nil {
		t.Fatal(err)
	}
	var draft string
	for _, o := range plans[0].Operations {
		if o.Kind == OpPRDraft {
			draft = o.Draft
		}
	}
	for _, want := range []string{"--- a/lab/shop/static/app.js", "+++ b/lab/shop/static/app.js", "@@ -39,7 +39,8 @@", "-    flagsmith.setTrait(\"plan\", \"premium\");",
		"+    fetch(\"/api/flagsmith/traits/plan\"", "+++ b/server/flagsmith-traits.js"} {
		if !strings.Contains(draft, want) {
			t.Fatalf("draft missing %q:\n%s", want, draft)
		}
	}
	patch := draft[strings.Index(draft, "--- a/"):]
	patch = strings.Replace(patch, "\nServer side (new file):\n", "\n", 1)
	pf := filepath.Join(t.TempDir(), "d.patch")
	if err := os.WriteFile(pf, []byte(patch), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "apply", "--check", "--unsafe-paths", "-p1", pf)
	cmd.Dir = repo
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git apply --check failed: %v\n%s\n%s", err, out, patch)
	}
}

func identifierFinding() model.Finding {
	return model.Finding{ID: "GC-IDF", Type: model.FIdentifierForgery, Environment: "Production", Subject: "internal_tools",
		Title: "Choosing identifier a@acmeshop.dev unlocks internal_tools — this survives turning off client traits.", Status: model.StatusExploitable,
		ProofID: "gc-probe-a@acmeshop.dev", Unlocked: []model.FlagChange{{Flag: "internal_tools", Before: "off", After: "on"}}}
}

func TestPlannerIdentifierForgeryIsGuidanceOnly(t *testing.T) {
	h := newHarness(t)
	plans, err := h.planner("").Plan(t.Context(), []model.Finding{identifierFinding()})
	if err != nil || len(plans) != 1 {
		t.Fatalf("plans=%d err=%v", len(plans), err)
	}
	p := plans[0]
	if got := strings.Join(opKinds(p), ","); got != "pr.draft,manual" {
		t.Fatalf("operations = %s", got)
	}
	for _, o := range p.Operations {
		if o.Automatic || o.Method != "" || o.Path != "" || len(o.Body) != 0 {
			t.Fatalf("identifier plans must never change a Flagsmith setting: %+v", o)
		}
	}
	const fix = "assign identifiers on the server and stop targeting on identifier patterns"
	if !strings.Contains(p.Title, fix) || !strings.Contains(p.Operations[0].Description, fix) || !strings.Contains(strings.ToLower(p.Operations[0].Draft), fix) {
		t.Fatalf("plan does not carry the fix %q: title=%q op=%+v", fix, p.Title, p.Operations[0])
	}
	if !strings.Contains(p.Operations[1].Description, "does not close this") {
		t.Fatalf("manual step must say the client-traits setting does not help: %q", p.Operations[1].Description)
	}
	if len(p.FindingsAddressed) != 1 || p.FindingsAddressed[0] != "GC-IDF" || len(p.BeforeSnapshot) != 0 || p.Hash != p.ComputeHash() {
		t.Fatalf("plan = %+v", p)
	}
	if len(h.stub.writes) != 0 {
		t.Fatalf("planning wrote to Flagsmith: %v", h.stub.writes)
	}
	rec := &model.PlanRecord{Plan: p, State: model.PlanPending}
	if err := Approve(rec, "me", "cli", "Production", "", 0); err != nil {
		t.Fatal(err)
	}
	if err := h.applier().Apply(t.Context(), rec); err == nil || !strings.Contains(err.Error(), "no automatic operations") {
		t.Fatalf("applying guidance-only plan: %v", err)
	}
}

// The client-traits plan must neither absorb nor claim to fix an identifier
// forgery: it stays in its own guidance plan.
func TestPlannerKeepsIdentifierForgeryOutOfClientTraitsPlan(t *testing.T) {
	h := newHarness(t)
	plans, err := h.planner("").Plan(t.Context(), []model.Finding{traitFinding(), identifierFinding()})
	if err != nil || len(plans) != 2 {
		t.Fatalf("plans=%d err=%v", len(plans), err)
	}
	for _, p := range plans {
		auto := false
		for _, o := range p.Operations {
			auto = auto || o.Automatic
		}
		addressesIt := contains(p.FindingsAddressed, "GC-IDF")
		if auto && addressesIt {
			t.Fatalf("plan %q changes Flagsmith and claims the identifier forgery: %+v", p.Title, p)
		}
		if !auto && !addressesIt {
			t.Fatalf("unexpected guidance plan %q", p.Title)
		}
	}
}
