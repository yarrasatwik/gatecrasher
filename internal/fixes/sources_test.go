package fixes

import (
	"strings"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/patch"
)

func labShop(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, root, "app.js", "const id = cookie(\"acme_visitor\");\nflagsmith.setTrait(\"plan\", v);\n")
	writeFile(t, root, "index.html", "<script src=\"app.js\"></script>\n")
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")
	writeFile(t, root, ".env", "FLAGSMITH_SERVER_KEY=ser.abcdefghijklmnop\n")
	writeFile(t, root, "node_modules/x/main.go", "package x\n")
	return root
}

func paths(fs []model.SourceFile) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Path)
	}
	return out
}

func TestCollectSourcesAffectedPlusServerFile(t *testing.T) {
	root := labShop(t)
	impact := []model.ImpactItem{{File: "app.js", Line: 2}, {File: "app.js", Line: 1}, {File: "index.html", Line: 1}}
	got := paths(CollectSources(root, impact))
	if strings.Join(got, ",") != "app.js,index.html,main.go" {
		t.Fatalf("files = %v", got)
	}
}

func TestCollectSourcesNeverLeavesTheRepoOrReadsEnv(t *testing.T) {
	root := labShop(t)
	impact := []model.ImpactItem{{File: ".env"}, {File: "../outside.js"}, {File: "/etc/passwd"}, {File: "missing.js"}, {File: "app.js"}}
	got := paths(CollectSources(root, impact))
	if strings.Join(got, ",") != "app.js,main.go" {
		t.Fatalf("files = %v", got)
	}
}

func TestCollectSourcesLimits(t *testing.T) {
	root := labShop(t)
	writeFile(t, root, "big.js", strings.Repeat("x\n", patch.MaxFileLines+1))
	writeFile(t, root, "wide.js", strings.Repeat("y", patch.MaxFileBytes+1)+"\n")
	var impact []model.ImpactItem
	for _, f := range []string{"big.js", "wide.js", "app.js", "index.html", "c.js", "d.js", "e.js"} {
		impact = append(impact, model.ImpactItem{File: f})
	}
	writeFile(t, root, "c.js", "1\n")
	writeFile(t, root, "d.js", "2\n")
	writeFile(t, root, "e.js", "3\n")
	got := paths(CollectSources(root, impact))
	if len(got) != patch.MaxFiles {
		t.Fatalf("files = %v, want %d", got, patch.MaxFiles)
	}
	for _, p := range got {
		if p == "big.js" || p == "wide.js" {
			t.Fatalf("oversized file sent: %v", got)
		}
	}
	if got[len(got)-1] != "main.go" {
		t.Fatalf("the server file must keep its slot: %v", got)
	}
}

func TestCollectSourcesWithoutImpactFindsIdentifierCode(t *testing.T) {
	root := labShop(t)
	got := paths(CollectSources(root, nil))
	if len(got) < 2 || got[0] != "app.js" || got[len(got)-1] != "main.go" {
		t.Fatalf("files = %v", got)
	}
	if got := CollectSources("", nil); len(got) != 0 {
		t.Fatalf("no repo, files = %v", got)
	}
}
