package mapper

import (
	"regexp"
	"strings"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
	"github.com/yarrasatwik/gatecrasher/internal/model"
)

func TestForgeabilityMatrix(t *testing.T) {
	serverOnly := []string{"plan"}
	tests := []struct {
		name     string
		cond     Condition
		traitsOn bool
		clientID bool
		want     string
	}{
		{"trait, traits on", Condition{Property: "role", Operator: OpEqual}, true, false, "yes"},
		{"trait, traits off", Condition{Property: "role", Operator: OpEqual}, false, false, "no"},
		{"server-only trait", Condition{Property: "plan", Operator: OpEqual}, true, false, "no"},
		{"IS_NOT_SET by omission, traits off", Condition{Property: "role", Operator: OpIsNotSet}, false, false, "yes"},
		{"IS_NOT_SET on server-only trait", Condition{Property: "plan", Operator: OpIsNotSet}, true, false, "unknown"},
		{"identifier, client chooses", Condition{Property: "$.identity.identifier", Operator: OpEqual}, false, true, "yes"},
		{"identifier, server chooses", Condition{Property: "$.identity.identifier", Operator: OpEqual}, true, false, "no"},
		{"identity key", Condition{Property: "$.identity.key", Operator: OpContains}, false, true, "yes"},
		{"identity split, client chooses", Condition{Operator: OpPercentSplit}, false, true, "yes"},
		{"identity split, server chooses", Condition{Operator: OpPercentSplit}, true, false, "no"},
		{"trait split, traits on", Condition{Property: "cohort", Operator: OpPercentSplit}, true, false, "yes"},
		{"environment property", Condition{Property: "$.environment.name", Operator: OpEqual}, true, true, "no"},
		{"unrecognised JSONPath", Condition{Property: "$.flags.other.enabled", Operator: OpEqual}, true, true, "unknown"},
		{"identity trait path", Condition{Property: "$.identity.traits.role", Operator: OpEqual}, true, false, "yes"},
		{"no property, non-split", Condition{Operator: OpEqual}, true, true, "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Forgeability(tc.cond, tc.traitsOn, serverOnly, tc.clientID); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCombineForgeability(t *testing.T) {
	tests := []struct {
		in   []string
		want string
	}{
		{nil, "yes"}, {[]string{"yes", "yes"}, "yes"}, {[]string{"yes", "unknown"}, "unknown"},
		{[]string{"unknown", "no"}, "no"}, {[]string{"no", "yes"}, "no"},
	}
	for _, tc := range tests {
		if got := combineForgeability(tc.in); got != tc.want {
			t.Errorf("%v: got %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSettingsAudit(t *testing.T) {
	envs := []flagsmith.Environment{
		{Name: "Production", AllowClientTraits: true, HideSensitiveData: false},
		{Name: "Staging", AllowClientTraits: false, HideSensitiveData: true, UseV2FeatureVersioning: true},
	}
	features := []flagsmith.Feature{
		{Name: "payment_config"}, {Name: "internal_api", IsServerKeyOnly: true},
		{Name: "banner_text"}, {Name: "old", IsArchived: true}, {Name: "new_logo"}, {Name: "unclassified"},
	}
	cls := map[string]model.Category{
		"payment_config": model.CatSecret, "internal_api": model.CatInternalURL,
		"banner_text": model.CatHarmless, "old": model.CatSecret, "new_logo": model.CatUnreleasedProduct,
	}
	settings, findings := SettingsAudit(envs, features, cls)

	if len(settings) != 2 || *settings[0].AllowClientTraits != true || *settings[0].HideSensitiveData != false {
		t.Fatalf("settings: %+v", settings)
	}
	if !settings[1].UseV2Versioning || *settings[1].AllowClientTraits {
		t.Errorf("staging settings: %+v", settings[1])
	}
	if got := strings.Join(settings[0].ServerOnlyFlags, ","); got != "internal_api" {
		t.Errorf("server only flags = %q", got)
	}
	if got := strings.Join(settings[0].ClientVisible, ","); got != "banner_text,new_logo,payment_config,unclassified" {
		t.Errorf("client visible flags = %q (archived must be skipped)", got)
	}

	byType := map[model.FindingType][]model.Finding{}
	for _, f := range findings {
		byType[f.Type] = append(byType[f.Type], f)
		if len(f.DetectedBy) != 1 || f.DetectedBy[0] != model.MethodSettings || !f.Confirmed {
			t.Errorf("%s: detection metadata %+v", f.Type, f)
		}
	}
	traits := byType[model.FSettingClientTraitsOn]
	if len(traits) != 1 || traits[0].Environment != "Production" || !strings.Contains(traits[0].Evidence[0].Note, "Allow client SDKs to set user traits") {
		t.Errorf("client traits findings: %+v", traits)
	}
	hide := byType[model.FSettingSensitiveData]
	if len(hide) != 1 || hide[0].Environment != "Production" || !strings.Contains(hide[0].Evidence[0].Note, "Hide sensitive data") {
		t.Errorf("hide sensitive findings: %+v", hide)
	}
	notServer := byType[model.FFlagNotServerOnly]
	if len(notServer) != 2 {
		t.Fatalf("want payment_config and new_logo flagged, got %+v", notServer)
	}
	names := notServer[0].Subject + "," + notServer[1].Subject
	if names != "payment_config,new_logo" {
		t.Errorf("flagged flags = %s (harmless, server-only, archived and unclassified must not be flagged)", names)
	}
	if notServer[0].Severity != model.SevHigh || notServer[1].Severity != model.SevMedium {
		t.Errorf("severities: %v %v", notServer[0].Severity, notServer[1].Severity)
	}
	if !strings.Contains(notServer[0].Evidence[0].Note, "Server-side only") {
		t.Errorf("note: %q", notServer[0].Evidence[0].Note)
	}
	_, again := SettingsAudit(envs, features, cls)
	if again[0].ID != findings[0].ID {
		t.Error("finding IDs must be stable")
	}
}

func TestMatchingStrings(t *testing.T) {
	patterns := []string{
		`.*@acmeshop\.dev$`, `^(admin|staff)-[0-9]{2}$`, `^v\d+\.\d+$`, `colou?r`, `^[A-Z][a-z]+$`,
		`(foo|bar)+baz`, `^\w+@\w+\.com$`, `^$`, `^a{2,3}b*$`, `(?i)hello`,
	}
	for _, p := range patterns {
		got := matchingStrings(p, 4)
		if len(got) == 0 {
			t.Errorf("%s: no candidate generated", p)
		}
		re := regexp.MustCompile(p)
		for _, s := range got {
			if !re.MatchString(s) {
				t.Errorf("%s: %q does not match", p, s)
			}
		}
	}
	if got := matchingStrings(`[`, 4); got != nil {
		t.Errorf("invalid pattern: %v", got)
	}
	if got := matchingStrings(`^$`, 4); len(got) != 1 || got[0] != "" {
		t.Errorf("^$ should yield the empty string, got %q", got)
	}
}

func TestSolveCandidatesAreCheapestFirst(t *testing.T) {
	seg := Segment{ID: 1, Name: "s", Rules: []Rule{{Type: RuleAll, Rules: []Rule{{Type: RuleAny, Conditions: []Condition{
		{Property: "a", Operator: OpEqual, Value: "1"},
		{Property: "b", Operator: OpEqual, Value: "2"},
	}}}}}}
	cands := Solve(seg, "env", 0)
	if len(cands) != 2 || cands[0].Cost() != 1 || cands[1].Cost() != 1 {
		t.Fatalf("%+v", cands)
	}
	again := Solve(seg, "env", 0)
	if cands[0].key() != again[0].key() {
		t.Error("Solve must be deterministic")
	}
	if len(Solve(Segment{ID: 2}, "env", 0)) != 0 {
		t.Error("a segment without rules never matches")
	}
}

func TestShiftAndValues(t *testing.T) {
	tests := []struct {
		v    string
		d    int
		want string
	}{
		{"18", 1, "19"}, {"18", -1, "17"}, {"1.5", 1, "2.5"}, {"1.2.3:semver", 1, "1.2.4"},
		{"1.2.0:semver", -1, "1.1.0"}, {"true", 1, "false"}, {"abc", 1, "abca"}, {"abc", -1, "ab"},
	}
	for _, tc := range tests {
		if got := shift(tc.v, tc.d); got != tc.want {
			t.Errorf("shift(%q,%d) = %q, want %q", tc.v, tc.d, got, tc.want)
		}
	}
	if got := valueCandidates(OpModulo, "10|3", true); len(got) == 0 || got[0] != "3" {
		t.Errorf("modulo: %v", got)
	}
	if got := valueCandidates(OpModulo, "10|3", false); len(got) == 0 || got[0] == "3" {
		t.Errorf("modulo (false): %v", got)
	}
	if got := valueCandidates(OpIn, `["x","y"]`, true); len(got) != 2 || got[0] != "x" {
		t.Errorf("IN json list: %v", got)
	}
	if got := valueCandidates(OpContains, "acme", true); len(got) == 0 || !strings.Contains(got[0], "acme") || got[0] == "acme" {
		t.Errorf("CONTAINS should wrap the constant: %v", got)
	}
}
