package fixes

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// shopApp writes the lab-shop pattern: setTrait("plan", ...) on line 42 of
// lab/shop/static/app.js plus a client read of payment_config.
func shopApp(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	var b strings.Builder
	for i := 1; i <= 41; i++ {
		b.WriteString("// filler line\n")
	}
	b.WriteString("    flagsmith.setTrait(\"plan\", \"premium\");\n")
	b.WriteString("    flagsmith.setTrait(\"locale\", \"en\");\n")
	b.WriteString("    const cfg = flagsmith.getValue(\"payment_config\");\n")
	b.WriteString("    const on = flagsmith.hasFeature('checkout_ab');\n")
	writeFile(t, root, "lab/shop/static/app.js", b.String())
	return root
}

func TestScanFindsSetTraitAtTheRightLine(t *testing.T) {
	items, err := Scan(shopApp(t))
	if err != nil {
		t.Fatal(err)
	}
	var plan *int
	for _, it := range items {
		if it.File != "lab/shop/static/app.js" {
			t.Fatalf("file must be repo-relative with forward slashes, got %q", it.File)
		}
		if strings.Contains(it.Message, "`plan`") {
			l := it.Line
			plan = &l
			if it.Snippet != `flagsmith.setTrait("plan", "premium");` {
				t.Fatalf("snippet = %q", it.Snippet)
			}
		}
	}
	if plan == nil || *plan != 42 {
		t.Fatalf("setTrait(plan) line = %v, want 42 (items: %+v)", plan, items)
	}
	if len(items) != 4 {
		t.Fatalf("got %d items, want 4: %+v", len(items), items)
	}
}

func TestScanPatterns(t *testing.T) {
	tests := []struct {
		name, file, src string
		kind            UsageKind
		names           []string
	}{
		{"js setTraits object", "a.js", `client.setTraits({ plan: "pro", "beta-user": true });`, UsageTraitWrite, []string{"beta-user", "plan"}},
		{"identify traits", "a.ts", `await flagsmith.identify(uid, { traits: { tier: "gold" } });`, UsageTraitWrite, []string{"tier"}},
		{"init traits", "a.jsx", `flagsmith.init({ environmentID: k, identity: u, traits: {plan: p} })`, UsageTraitWrite, []string{"plan"}},
		{"swift", "A.swift", `Flagsmith.shared.setTrait(Trait(key: "plan", value: "pro"), forIdentity: id)`, UsageTraitWrite, []string{"plan"}},
		{"kotlin", "A.kt", `flagsmith.setTrait(Trait(key = "plan", value = "pro"), identity)`, UsageTraitWrite, []string{"plan"}},
		{"dart", "a.dart", `await client.updateTrait("plan", "pro");`, UsageTraitWrite, []string{"plan"}},
		{"html inline", "i.html", `<script>flagsmith.setTrait('plan','pro')</script>`, UsageTraitWrite, []string{"plan"}},
		{"opaque", "a.js", `flagsmith.setTraits(traitsFromForm);`, UsageTraitWrite, nil},
		{"getValue", "a.tsx", "const v = flagsmith.getValue(`secret_url`);", UsageFlagRead, []string{"secret_url"}},
		{"getFeatureValue swift label", "A.swift", `flagsmith.getFeatureValue(withID: "pricing")`, UsageFlagRead, []string{"pricing"}},
		{"useFlags", "c.tsx", `const f = useFlags(['a_flag', "b_flag"]);`, UsageFlagRead, []string{"a_flag", "b_flag"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, tc.file, "\n"+tc.src+"\n")
			us, err := ScanUsages(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(us) != 1 {
				t.Fatalf("usages = %+v", us)
			}
			u := us[0]
			if u.Kind != tc.kind || u.Line != 2 || strings.Join(u.Names, ",") != strings.Join(tc.names, ",") {
				t.Fatalf("got %+v, want kind=%s names=%v line 2", u, tc.kind, tc.names)
			}
		})
	}
}

func TestScanSkipsAndRedacts(t *testing.T) {
	root := t.TempDir()
	hit := `flagsmith.setTrait("plan", "x");`
	for _, rel := range []string{"node_modules/x/a.js", "vendor/b.js", ".git/c.js", "dist/d.js", "build/e.js", "readme.md", "server/f.js"} {
		src := hit
		if rel == "server/f.js" {
			src = `const flagsmith = require("flagsmith-nodejs"); flagsmith.getValue("secret")`
		}
		writeFile(t, root, rel, src)
	}
	writeFile(t, root, "huge.min.js", hit+strings.Repeat("/*"+strings.Repeat("x", 998)+"*/\n", 1100))
	key := "ser." + strings.Repeat("ab", 12)
	writeFile(t, root, "src/ok.js", `flagsmith.setTrait("token", "`+key+`");`)
	us, err := ScanUsages(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(us) != 1 || us[0].File != "src/ok.js" {
		t.Fatalf("usages = %+v", us)
	}
	if strings.Contains(us[0].Snippet, key) {
		t.Fatalf("snippet leaks a key: %q", us[0].Snippet)
	}
}
