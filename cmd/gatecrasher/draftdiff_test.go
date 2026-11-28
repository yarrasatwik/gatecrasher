package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

func TestWriteDraftsPrintsDiffAndNote(t *testing.T) {
	color = false
	p := model.Plan{Operations: []model.Operation{
		{Kind: "env.patch", Description: "Turn off traits", Automatic: true},
		{Kind: "pr.draft", Description: "Draft a PR", Draft: "Title\n\nBody",
			Diff: "--- a/app.js\n+++ b/app.js\n@@ -1,2 +1,2 @@\n a\n-b\n+c acme_live_0123456789abcdef0123\n"},
		{Kind: "pr.draft", Description: "Draft another", Draft: "T2", DiffNote: "diff did not apply; not shown"},
	}}
	var buf bytes.Buffer
	writeDrafts(&buf, p)
	out := buf.String()
	for _, want := range []string{"PR draft", "Title", "--- a/app.js", "-b", "+c ", "diff did not apply; not shown", "never applies"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "0123456789abcdef0123") {
		t.Fatalf("key material leaked:\n%s", out)
	}
	buf.Reset()
	writeDrafts(&buf, model.Plan{Operations: []model.Operation{{Kind: "env.patch"}}})
	if buf.Len() != 0 {
		t.Fatalf("no drafts, got %q", buf.String())
	}
}
