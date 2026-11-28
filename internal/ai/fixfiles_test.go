package ai

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

func fixReply(t *testing.T, diff string) string {
	t.Helper()
	b, err := json.Marshal(map[string]string{"title": "Send plan from the server", "body": "Moves the trait.", "diff": diff})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var shopFiles = []model.SourceFile{
	{Path: "app.js", Content: "const a = 1;\nawait flagsmith.setTrait(\"plan\", v);\nconst b = 2;\n"},
	{Path: "main.go", Content: "package main\n\nfunc main() {}\n"},
}

var shopImpact = []model.ImpactItem{{File: "app.js", Line: 2, Snippet: `flagsmith.setTrait("plan", v)`, Message: "sets plan"}}

func TestFixPRFilesKeepsDiffThatApplies(t *testing.T) {
	diff := "--- a/app.js\n+++ b/app.js\n@@ -1,3 +1,3 @@\n const a = 1;\n-await flagsmith.setTrait(\"plan\", v);\n+await fetch(\"/api/plan\", { method: \"POST\" });\n const b = 2;\n"
	fk := newStubAnthropic(t, fixReply(t, diff))
	d := fk.client().FixPRFiles(context.Background(), sampleFinding(), shopImpact, shopFiles)
	if d.Source != "ai" || d.Diff != diff || d.DiffNote != "" {
		t.Fatalf("%+v", d)
	}
	if !strings.Contains(fk.bodies[0], "const a = 1;") || !strings.Contains(fk.bodies[0], "package main") {
		t.Fatalf("file contents were not sent: %s", fk.bodies[0])
	}
}

func TestFixPRFilesRejectsUnlistedFile(t *testing.T) {
	diff := "--- a/secrets.js\n+++ b/secrets.js\n@@ -1 +1 @@\n-a\n+b\n"
	d := newStubAnthropic(t, fixReply(t, diff)).client().FixPRFiles(context.Background(), sampleFinding(), shopImpact, shopFiles)
	if d.Source != "ai" || d.Diff != "" || !strings.Contains(d.DiffNote, "not shown") || d.Body == "" {
		t.Fatalf("%+v", d)
	}
}

func TestFixPRFilesRejectsDiffThatDoesNotApply(t *testing.T) {
	diff := "--- a/app.js\n+++ b/app.js\n@@ -1,2 +1,2 @@\n-this line is not in the file\n+x\n const b = 2;\n"
	d := newStubAnthropic(t, fixReply(t, diff)).client().FixPRFiles(context.Background(), sampleFinding(), shopImpact, shopFiles)
	if d.Diff != "" || d.DiffNote != "diff did not apply; not shown" || d.Title == "" {
		t.Fatalf("%+v", d)
	}
}

func TestFixPRFilesNeverSendsSecretsOrExtraFiles(t *testing.T) {
	planted := "acme_live_aaaabbbbccccdddd1111222233334444"
	files := []model.SourceFile{{Path: "app.js", Content: "const k = \"" + planted + "\";\nsetTrait(\"plan\", 1);\n"}}
	fk := newStubAnthropic(t, fixReply(t, ""))
	d := fk.client().FixPRFiles(context.Background(), sampleFinding(), shopImpact, files)
	if fk.count() != 1 {
		t.Fatalf("requests = %d", fk.count())
	}
	if strings.Contains(fk.bodies[0], planted) || strings.Contains(fk.bodies[0], "aaaabbbbccccdddd") {
		t.Fatalf("planted key reached the provider: %s", fk.bodies[0])
	}
	if !strings.Contains(fk.bodies[0], "setTrait") {
		t.Fatalf("redacted file content missing: %s", fk.bodies[0])
	}
	if d.Diff != "" || d.DiffNote == "" {
		t.Fatalf("%+v", d)
	}
}

func TestFixPRFilesWithoutFilesHasNoDiff(t *testing.T) {
	d := newStubAnthropic(t, fixReply(t, "")).client().FixPRFiles(context.Background(), sampleFinding(), shopImpact, nil)
	if d.Diff != "" || !strings.Contains(d.DiffNote, "not available") {
		t.Fatalf("%+v", d)
	}
}
