package patch

import (
	"errors"
	"strings"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

var app = model.SourceFile{Path: "app.js", Content: "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\n"}

func TestApplyNormalisesAndApplies(t *testing.T) {
	// Wrong counts and wrong start line: the context still locates the hunk.
	diff := "--- a/app.js\n+++ b/app.js\n@@ -1,9 +1,9 @@\n d\n e\n-f\n+F\n+F2\n g\n h\n"
	r, err := Apply([]model.SourceFile{app}, diff)
	if err != nil {
		t.Fatal(err)
	}
	want := "--- a/app.js\n+++ b/app.js\n@@ -4,5 +4,6 @@\n d\n e\n-f\n+F\n+F2\n g\n h\n"
	if r.Diff != want {
		t.Fatalf("diff:\n%s\nwant:\n%s", r.Diff, want)
	}
	if got := r.New["app.js"]; got != "a\nb\nc\nd\ne\nF\nF2\ng\nh\ni\nj\n" {
		t.Fatalf("new content %q", got)
	}
}

func TestApplyTwoHunksAndGitHeader(t *testing.T) {
	diff := "diff --git a/app.js b/app.js\nindex 1..2 100644\n--- a/app.js\n+++ b/app.js\n" +
		"@@ -1,3 +1,3 @@\n-a\n+A\n b\n c\n@@ -8,3 +8,2 @@\n h\n-i\n j\n"
	r, err := Apply([]model.SourceFile{app}, diff)
	if err != nil {
		t.Fatal(err)
	}
	if r.New["app.js"] != "A\nb\nc\nd\ne\nf\ng\nh\nj\n" {
		t.Fatalf("%q", r.New["app.js"])
	}
	if !strings.Contains(r.Diff, "@@ -8,3 +8,2 @@") {
		t.Fatalf("second hunk header: %s", r.Diff)
	}
}

func TestApplyRejectsUnlistedFile(t *testing.T) {
	for _, diff := range []string{
		"--- a/other.js\n+++ b/other.js\n@@ -1 +1 @@\n-a\n+b\n",
		"--- a/.env\n+++ b/.env\n@@ -1 +1 @@\n-a\n+b\n",
		"--- a/../app.js\n+++ b/../app.js\n@@ -1 +1 @@\n-a\n+b\n",
		"--- /dev/null\n+++ b/new.js\n@@ -0,0 +1 @@\n+x\n",
		"--- a/app.js\n+++ b/app.js\n@@ -1 +1 @@\n-a\n+b\n--- a/other.js\n+++ b/other.js\n@@ -1 +1 @@\n-a\n+b\n",
	} {
		if _, err := Apply([]model.SourceFile{app}, diff); !errors.Is(err, ErrOutsideFiles) {
			t.Errorf("%q: err = %v, want ErrOutsideFiles", diff, err)
		}
	}
}

func TestApplyRejectsContextMismatch(t *testing.T) {
	for _, diff := range []string{
		"--- a/app.js\n+++ b/app.js\n@@ -1,2 +1,2 @@\n-a\n+A\n x\n",
		"--- a/app.js\n+++ b/app.js\n@@ -1 +1 @@\n-nope\n+yes\n",
		"just prose",
		"",
	} {
		if _, err := Apply([]model.SourceFile{app}, diff); !errors.Is(err, ErrNotApplicable) {
			t.Errorf("%q: err = %v, want ErrNotApplicable", diff, err)
		}
	}
}

func TestApplyCRLFAndAnchoredEnd(t *testing.T) {
	crlf := model.SourceFile{Path: "main.go", Content: "x\r\ny\r\nz\r\n"}
	r, err := Apply([]model.SourceFile{crlf}, "--- a/main.go\n+++ b/main.go\n@@ -1,3 +1,3 @@\n x\n-y\n+Y\n z\n")
	if err != nil || r.New["main.go"] != "x\r\nY\r\nz\r\n" {
		t.Fatalf("%v %q", err, r.New["main.go"])
	}
	// A hunk with no trailing context must sit at the end of the file (git's rule).
	if _, err := Apply([]model.SourceFile{app}, "--- a/app.js\n+++ b/app.js\n@@ -1,2 +1,2 @@\n a\n-b\n+B\n"); !errors.Is(err, ErrNotApplicable) {
		t.Fatalf("err = %v", err)
	}
	if _, err := Apply([]model.SourceFile{app}, "--- a/app.js\n+++ b/app.js\n@@ -9,2 +9,3 @@\n i\n j\n+k\n"); err != nil {
		t.Fatal(err)
	}
}
