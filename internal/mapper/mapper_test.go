package mapper_test

import (
	"regexp"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
	"github.com/yarrasatwik/gatecrasher/internal/mapper"
	"github.com/yarrasatwik/gatecrasher/internal/mapper/testdoc"
	"github.com/yarrasatwik/gatecrasher/internal/model"
)

func tru() *bool { b := true; return &b }

func engineFor(t *testing.T, d testdoc.Doc) *flagsmith.Engine {
	t.Helper()
	eng, err := flagsmith.NewEngine(d.JSON())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return eng
}

// single builds a document with flag "f" (off by default) switched on by one
// segment whose only rule is r.
func single(r testdoc.Rule) testdoc.Doc {
	return testdoc.Doc{
		APIKey:   "envkey",
		Features: []testdoc.Feature{{Name: "f", Enabled: false, Value: "base"}},
		Segments: []testdoc.Segment{{ID: 7, Name: "seg", Rules: []testdoc.Rule{r},
			Overrides: []testdoc.Override{{Feature: "f", Enabled: true, Value: "on"}}}},
	}
}

func allOf(cs ...testdoc.Cond) testdoc.Rule {
	return testdoc.Rule{Type: "ALL", Rules: []testdoc.Rule{{Type: "ALL", Conds: cs}}}
}

func settingsOn() []model.EnvSettings {
	return []model.EnvSettings{{Environment: "prod", AllowClientTraits: tru()}}
}

func mapDoc(t *testing.T, d testdoc.Doc, opts mapper.Options) []model.Reachable {
	t.Helper()
	opts.Environment = "prod"
	return mapper.Map(engineFor(t, d), nil, nil, settingsOn(), opts)
}

func TestOperators(t *testing.T) {
	cond := func(prop, op, val string) testdoc.Rule {
		return allOf(testdoc.Cond{Property: prop, Operator: op, Value: val})
	}
	tests := []struct {
		name  string
		rule  testdoc.Rule
		check func(t *testing.T, r model.Reachable)
	}{
		{"EQUAL", cond("plan", "EQUAL", "pro"), func(t *testing.T, r model.Reachable) { eq(t, r.ForgedTraits["plan"], "pro") }},
		{"NOT_EQUAL", cond("plan", "NOT_EQUAL", "free"), nil},
		{"GREATER_THAN", cond("age", "GREATER_THAN", "18"), func(t *testing.T, r model.Reachable) { eq(t, r.ForgedTraits["age"], "19") }},
		{"GREATER_THAN_INCLUSIVE", cond("age", "GREATER_THAN_INCLUSIVE", "18"), func(t *testing.T, r model.Reachable) { eq(t, r.ForgedTraits["age"], "18") }},
		{"LESS_THAN", cond("age", "LESS_THAN", "18"), func(t *testing.T, r model.Reachable) { eq(t, r.ForgedTraits["age"], "17") }},
		{"LESS_THAN_INCLUSIVE", cond("age", "LESS_THAN_INCLUSIVE", "18"), nil},
		{"CONTAINS", cond("email", "CONTAINS", "acme"), nil},
		{"NOT_CONTAINS", cond("email", "NOT_CONTAINS", "evil"), nil},
		{"IN", cond("country", "IN", "us,de,fr"), func(t *testing.T, r model.Reachable) { eq(t, r.ForgedTraits["country"], "us") }},
		{"IS_SET", cond("beta", "IS_SET", ""), nil},
		{"IS_NOT_SET", cond("beta", "IS_NOT_SET", ""), func(t *testing.T, r model.Reachable) {
			if len(r.ForgedTraits) != 0 {
				t.Errorf("IS_NOT_SET needs no traits, got %v", r.ForgedTraits)
			}
		}},
		{"REGEX", cond("email", "REGEX", `.*@acmeshop\.dev$`), func(t *testing.T, r model.Reachable) {
			if !regexp.MustCompile(`.*@acmeshop\.dev$`).MatchString(r.ForgedTraits["email"]) {
				t.Errorf("email %q does not match", r.ForgedTraits["email"])
			}
		}},
		{"REGEX alternation", cond("role", "REGEX", `^(admin|staff)-[0-9]{2}$`), nil},
		{"MODULO", cond("n", "MODULO", "10|3"), func(t *testing.T, r model.Reachable) { eq(t, r.ForgedTraits["n"], "3") }},
		{"SEMVER GT", cond("version", "GREATER_THAN", "1.2.3:semver"), func(t *testing.T, r model.Reachable) { eq(t, r.ForgedTraits["version"], "1.2.4") }},
		{"SEMVER EQUAL", cond("version", "EQUAL", "2.0.0:semver"), nil},
		{"PERCENTAGE_SPLIT", cond("", "PERCENTAGE_SPLIT", "10"), func(t *testing.T, r model.Reachable) {
			if r.Identifier == "" {
				t.Error("percentage split needs a searched identifier")
			}
		}},
		{"PERCENTAGE_SPLIT on trait", cond("cohort", "PERCENTAGE_SPLIT", "10"), nil},
		{"identity identifier EQUAL", cond("$.identity.identifier", "EQUAL", "gc-probe-vip"), func(t *testing.T, r model.Reachable) { eq(t, r.Identifier, "gc-probe-vip") }},
		{"identity key EQUAL", cond("$.identity.key", "EQUAL", "envkey_gc-probe-vip"), func(t *testing.T, r model.Reachable) { eq(t, r.Identifier, "gc-probe-vip") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mapDoc(t, single(tc.rule), mapper.Options{ClientSetsIdentifier: true})
			if len(got) != 1 {
				t.Fatalf("want 1 reachable flag, got %d: %+v", len(got), got)
			}
			r := got[0]
			if !r.EngineVerified || r.Flag != "f" || !r.Enabled || r.Value != "on" || r.DefaultEnabled || r.DefaultValue != "base" || r.Segment != "seg" {
				t.Errorf("unexpected reachable %+v", r)
			}
			if r.Forgeable != "yes" {
				t.Errorf("forgeable = %q, want yes", r.Forgeable)
			}
			if tc.check != nil {
				tc.check(t, r)
			}
		})
	}
}

func eq(t *testing.T, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestNesting(t *testing.T) {
	c := func(p, op, v string) testdoc.Cond { return testdoc.Cond{Property: p, Operator: op, Value: v} }
	tests := []struct {
		name        string
		rule        testdoc.Rule
		wantTraits  map[string]string // nil: only require reachable
		unreachable bool
	}{
		{"ANY picks cheapest branch", testdoc.Rule{Type: "ALL", Rules: []testdoc.Rule{{Type: "ANY", Conds: []testdoc.Cond{c("a", "EQUAL", "1"), c("b", "EQUAL", "2")}}}}, nil, false},
		{"ALL needs both", allOf(c("a", "EQUAL", "1"), c("b", "EQUAL", "2")), map[string]string{"a": "1", "b": "2"}, false},
		{"NONE omits the trait", testdoc.Rule{Type: "ALL", Rules: []testdoc.Rule{
			{Type: "ALL", Conds: []testdoc.Cond{c("plan", "EQUAL", "pro")}},
			{Type: "NONE", Conds: []testdoc.Cond{c("banned", "EQUAL", "true")}},
		}}, map[string]string{"plan": "pro"}, false},
		{"NONE with IS_NOT_SET forces the trait", testdoc.Rule{Type: "ALL", Rules: []testdoc.Rule{
			{Type: "NONE", Conds: []testdoc.Cond{c("flag", "IS_NOT_SET", "")}},
		}}, nil, false},
		{"nested NONE inside ALL", testdoc.Rule{Type: "ALL", Rules: []testdoc.Rule{
			{Type: "ALL", Conds: []testdoc.Cond{c("plan", "EQUAL", "pro")}, Rules: []testdoc.Rule{
				{Type: "NONE", Conds: []testdoc.Cond{c("region", "IN", "cn,ru")}},
			}},
		}}, map[string]string{"plan": "pro"}, false},
		{"contradiction is unreachable", allOf(c("a", "EQUAL", "1"), c("a", "EQUAL", "2")), nil, true},
		{"NONE of two equal conditions", testdoc.Rule{Type: "NONE", Conds: []testdoc.Cond{c("a", "EQUAL", "1"), c("b", "EQUAL", "2")}}, nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mapDoc(t, single(tc.rule), mapper.Options{})
			if tc.unreachable {
				if len(got) != 0 {
					t.Fatalf("expected unreachable, got %+v", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("want 1 reachable, got %+v", got)
			}
			for k, v := range tc.wantTraits {
				eq(t, got[0].ForgedTraits[k], v)
			}
			if tc.wantTraits != nil && len(got[0].ForgedTraits) != len(tc.wantTraits) {
				t.Errorf("traits = %v, want exactly %v", got[0].ForgedTraits, tc.wantTraits)
			}
		})
	}
}

func TestPriorityConflicts(t *testing.T) {
	seg := func(id int, name, prop, val, flagVal string, prio int) testdoc.Segment {
		return testdoc.Segment{ID: id, Name: name, Priority: prio,
			Rules:     []testdoc.Rule{allOf(testdoc.Cond{Property: prop, Operator: "EQUAL", Value: val})},
			Overrides: []testdoc.Override{{Feature: "f", Enabled: true, Value: flagVal}}}
	}
	base := []testdoc.Feature{{Name: "f", Enabled: false, Value: "base"}}

	t.Run("independent segments are both reachable", func(t *testing.T) {
		got := mapDoc(t, testdoc.Doc{APIKey: "k", Features: base, Segments: []testdoc.Segment{
			seg(1, "gold", "plan", "gold", "G", 1), seg(2, "eu", "region", "eu", "E", 2)}}, mapper.Options{})
		if len(got) != 2 || got[0].Value != "G" || got[1].Value != "E" {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("shadowed override is not reachable", func(t *testing.T) {
		got := mapDoc(t, testdoc.Doc{APIKey: "k", Features: base, Segments: []testdoc.Segment{
			seg(1, "high", "plan", "gold", "HIGH", 1), seg(2, "low", "plan", "gold", "LOW", 2)}}, mapper.Options{})
		if len(got) != 1 || got[0].Segment != "high" || got[0].Value != "HIGH" {
			t.Fatalf("only the higher priority override should be reachable, got %+v", got)
		}
	})
	t.Run("priority number decides, not document order", func(t *testing.T) {
		got := mapDoc(t, testdoc.Doc{APIKey: "k", Features: base, Segments: []testdoc.Segment{
			seg(1, "listed-first", "plan", "gold", "FIRST", 5), seg(2, "listed-second", "plan", "gold", "SECOND", 1)}}, mapper.Options{})
		if len(got) != 1 || got[0].Segment != "listed-second" {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("an override equal to the default is skipped", func(t *testing.T) {
		d := testdoc.Doc{APIKey: "k", Features: base, Segments: []testdoc.Segment{
			{ID: 1, Name: "same", Rules: []testdoc.Rule{allOf(testdoc.Cond{Property: "a", Operator: "EQUAL", Value: "1"})},
				Overrides: []testdoc.Override{{Feature: "f", Enabled: false, Value: "base"}}}}}
		if got := mapDoc(t, d, mapper.Options{}); len(got) != 0 {
			t.Fatalf("got %+v", got)
		}
	})
}

func TestMultivariateVariants(t *testing.T) {
	mv := []testdoc.MV{{ID: 1, Value: "red", Percent: 50}, {ID: 2, Value: "blue", Percent: 50}}
	d := testdoc.Doc{APIKey: "k",
		Features: []testdoc.Feature{{Name: "color", Enabled: true, Value: "none", MV: mv}},
		Segments: []testdoc.Segment{{ID: 3, Name: "beta", Rules: []testdoc.Rule{allOf(testdoc.Cond{Property: "beta", Operator: "EQUAL", Value: "1"})},
			Overrides: []testdoc.Override{{Feature: "color", Enabled: true, Value: "none", MV: []testdoc.MV{{ID: 11, Value: "gold", Percent: 50}, {ID: 12, Value: "silver", Percent: 50}}}}}}}
	got := mapDoc(t, d, mapper.Options{ClientSetsIdentifier: true})
	values := map[string]model.Reachable{}
	for _, r := range got {
		values[r.Segment+"/"+r.Value] = r
	}
	for _, want := range []string{"/red", "/blue", "beta/gold", "beta/silver"} {
		r, ok := values[want]
		if !ok {
			t.Fatalf("variant %s not reached; got %+v", want, got)
		}
		if r.Identifier == "" || r.Forgeable != "yes" || !r.EngineVerified {
			t.Errorf("%s: %+v", want, r)
		}
	}
	// Re-evaluating the proof inputs must reproduce each value.
	eng := engineFor(t, d)
	for _, r := range got {
		f := eng.Evaluate(r.Identifier, r.ForgedTraits)["color"]
		eq(t, flagsmith.ValueString(f.Value), r.Value)
	}
	// With a server-assigned identifier the same variants are not forgeable.
	for _, r := range mapDoc(t, d, mapper.Options{}) {
		if r.Forgeable != "no" {
			t.Errorf("server-chosen identifier: %+v", r)
		}
	}
}

func TestMapUsesAdminRules(t *testing.T) {
	d := single(allOf(testdoc.Cond{Property: "plan", Operator: "EQUAL", Value: "pro"}))
	got := mapper.Map(engineFor(t, d), d.AdminSegments(), []flagsmith.Feature{{Name: "f"}}, settingsOn(), mapper.Options{Environment: "prod"})
	if len(got) != 1 || got[0].ForgedTraits["plan"] != "pro" {
		t.Fatalf("got %+v", got)
	}
	archived := mapper.Map(engineFor(t, d), nil, []flagsmith.Feature{{Name: "f", IsArchived: true}}, settingsOn(), mapper.Options{})
	if len(archived) != 0 {
		t.Fatalf("archived feature mapped: %+v", archived)
	}
}

func TestForgeabilityInReachability(t *testing.T) {
	d := single(allOf(testdoc.Cond{Property: "plan", Operator: "EQUAL", Value: "pro"}))
	eng := engineFor(t, d)
	off := false
	tests := []struct {
		name     string
		settings []model.EnvSettings
		opts     mapper.Options
		want     string
	}{
		{"client traits on", settingsOn(), mapper.Options{}, "yes"},
		{"client traits off", []model.EnvSettings{{Environment: "prod", AllowClientTraits: &off}}, mapper.Options{}, "no"},
		{"server-only trait", settingsOn(), mapper.Options{ServerOnlyTraits: []string{"plan"}}, "no"},
		{"settings missing", nil, mapper.Options{}, "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.Environment = "prod"
			got := mapper.Map(eng, nil, nil, tc.settings, tc.opts)
			if len(got) != 1 || got[0].Forgeable != tc.want {
				t.Fatalf("want forgeable %q, got %+v", tc.want, got)
			}
		})
	}
}

func TestForgeableFindings(t *testing.T) {
	reach := []model.Reachable{
		{Environment: "prod", Flag: "premium", Enabled: true, Value: "on", DefaultValue: "off", Segment: "gold", ForgedTraits: map[string]string{"plan": "gold"}, Forgeable: "yes", EngineVerified: true},
		{Environment: "prod", Flag: "a", Segment: "s", Forgeable: "unknown", EngineVerified: true},
		{Environment: "prod", Flag: "b", Segment: "s", Forgeable: "no", EngineVerified: true},
		{Environment: "prod", Flag: "c", Forgeable: "yes", EngineVerified: true},
	}
	got := mapper.ForgeableFindings(reach, mapper.Options{Classifications: map[string]model.Category{"premium": model.CatPricing}})
	if len(got) != 2 {
		t.Fatalf("want 2 findings (yes, unknown), got %d", len(got))
	}
	if got[0].Type != model.FSegmentForgeable || got[0].Status != model.StatusExploitable || !got[0].Confirmed || got[0].Severity != model.SevHigh || got[0].Traits["plan"] != "gold" {
		t.Errorf("first finding: %+v", got[0])
	}
	if got[1].Status != model.StatusUnknown || got[1].Confirmed {
		t.Errorf("unknown forgeability must not be confirmed: %+v", got[1])
	}
	if got[0].ID == got[1].ID {
		t.Error("finding IDs must differ")
	}
}
