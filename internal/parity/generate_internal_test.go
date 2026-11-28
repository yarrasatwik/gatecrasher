package parity

import (
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
	"github.com/yarrasatwik/gatecrasher/internal/mapper/testdoc"
)

// A forged identifier must not be reused: the live API answers concurrent
// requests for the same transient identifier inconsistently.
func TestGenerateUsesEachIdentifierOnce(t *testing.T) {
	d := testdoc.Doc{
		APIKey:   "envkey",
		Features: []testdoc.Feature{{Name: "tools", Enabled: false, Value: "off"}},
		Segments: []testdoc.Segment{{ID: 1, Name: "staff",
			Rules: []testdoc.Rule{{Type: "ALL", Rules: []testdoc.Rule{{Type: "ANY",
				Conds: []testdoc.Cond{{Property: "$.identity.identifier", Operator: "REGEX", Value: `.*@acmeshop\.dev$`}}}}}},
			Overrides: []testdoc.Override{{Feature: "tools", Enabled: true, Value: "on"}}}},
	}
	eng, err := flagsmith.NewEngine(d.JSON())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	forged := 0
	for _, tc := range generate(eng, d.AdminSegments(), 200) {
		if seen[tc.id] {
			t.Fatalf("identifier %q used twice", tc.id)
		}
		seen[tc.id] = true
		if tc.id != "" && len(tc.id) > 0 && tc.id[len(tc.id)-1] == 'v' {
			forged++
		}
	}
	if forged > 1 {
		t.Fatalf("forged identifier used %d times", forged)
	}
}
