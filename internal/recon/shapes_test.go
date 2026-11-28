package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestPageShapes(t *testing.T) {
	cases := []struct {
		name  string
		pages map[string]string // path -> fixture file
		want  string            // expected first key source
	}{
		{"inline init", map[string]string{"": "inline.html"}, "inline-1:3 environmentID"},
		{"window.__CONFIG__", map[string]string{"": "config.html"}, "inline-1:4 FLAGSMITH_ENVIRONMENT_ID"},
		{"Next.js __NEXT_DATA__", map[string]string{"": "next.html"}, "__NEXT_DATA__:6 environmentID"},
		{"Nuxt __NUXT_DATA__", map[string]string{"": "nuxt.html"}, "__NUXT_DATA__:1 flagsmithEnvironmentId"},
		{"modulepreload link", map[string]string{"": "modulepreload.html", "assets/entry.js": "entry-plain.js", "assets/flags-abc.js": "flags-abc.js"}, "flags-abc.js:5 environmentID"},
		{"dynamic import", map[string]string{"": "module-entry.html", "assets/entry.js": "entry-dynamic.js", "assets/flags-abc.js": "flags-abc.js"}, "flags-abc.js:5 environmentID"},
		{"static import", map[string]string{"": "module-entry.html", "assets/entry.js": "entry-static.js", "assets/flags-abc.js": "flags-abc.js"}, "flags-abc.js:5 environmentID"},
		{"vite mapDeps", map[string]string{"": "module-entry.html", "assets/entry.js": "entry-mapdeps.js", "assets/flags-abc.js": "flags-abc.js"}, "flags-abc.js:5 environmentID"},
		{"minified identifier", map[string]string{"": "minified.html", "assets/min.js": "min.js"}, "min.js:1 environmentID via K"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pages := map[string]string{}
			for p, f := range tc.pages {
				pages[p] = fixture(t, f)
			}
			f := newStub(t, pages)
			res, err := Run(context.Background(), f.srv, ReconConfig{TargetURL: f.url + "/", APIURL: f.url + "/api/v1/"})
			if err != nil {
				t.Fatal(err)
			}
			inv := res.Inventory
			if inv.Key != goodKey {
				t.Fatalf("key = %q", inv.Key)
			}
			if len(inv.KeySources) == 0 || inv.KeySources[0] != tc.want {
				t.Fatalf("key sources = %v, want first %q", inv.KeySources, tc.want)
			}
			if inv.APIURL != f.url+"/api/v1/" {
				t.Fatalf("api url = %q", inv.APIURL)
			}
		})
	}
}

func TestOutOfScopeChunkNeverFetched(t *testing.T) {
	var evilHits atomic.Int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		evilHits.Add(1)
		_, _ = w.Write([]byte(`export const k = "` + badKey + `";`))
	}))
	t.Cleanup(evil.Close)

	entry := `import("` + evil.URL + `/chunk-a.js");` + "\n" + `import x from "` + evil.URL + `/chunk-b.js";`
	html := `<link rel="modulepreload" href="` + evil.URL + `/chunk-c.js">` +
		`<script type="module" src="/assets/entry.js"></script>` +
		`<script>flagsmith.init({environmentID:"` + goodKey + `",api:"{{API}}"})</script>`
	f := newStub(t, map[string]string{"": page(html), "assets/entry.js": entry})
	res, err := Run(context.Background(), f.srv, ReconConfig{TargetURL: f.url + "/"})
	if err != nil {
		t.Fatal(err)
	}
	if n := evilHits.Load(); n != 0 {
		t.Fatalf("out-of-scope chunk server received %d requests, want 0", n)
	}
	notes := strings.Join(res.Notes, "\n")
	for _, want := range []string{"chunk-a.js", "chunk-b.js", "chunk-c.js"} {
		if !strings.Contains(notes, "skipped") || !strings.Contains(notes, want) {
			t.Fatalf("no skip note for %s in:\n%s", want, notes)
		}
	}
}

func TestChunksFollowedOnlyOneLevel(t *testing.T) {
	f := newStub(t, map[string]string{
		"":     page(`<script type="module" src="/a.js"></script>`),
		"a.js": `import("./b.js");`,
		"b.js": `import("./c.js");`,
		"c.js": `flagsmith.init({environmentID:"` + goodKey + `",api:"{{API}}"})`,
	})
	_, err := Run(context.Background(), f.srv, ReconConfig{TargetURL: f.url + "/", APIURL: f.url + "/api/v1/"})
	if err == nil {
		t.Fatal("key two levels deep should not be found")
	}
	if f.hitCount("/b.js") != 1 || f.hitCount("/c.js") != 0 {
		t.Fatalf("b.js hits=%d c.js hits=%d", f.hitCount("/b.js"), f.hitCount("/c.js"))
	}
}

func TestMaxScriptsConfigurable(t *testing.T) {
	var tags []string
	pages := map[string]string{}
	for _, n := range []string{"s1", "s2", "s3", "s4", "s5"} {
		tags = append(tags, `<script src="/`+n+`.js"></script>`)
		pages[n+".js"] = "var a = 1;"
	}
	pages[""] = page(tags...)
	f := newStub(t, pages)
	res, err := Run(context.Background(), f.srv, ReconConfig{TargetURL: f.url + "/", APIURL: f.url + "/api/v1/", MaxScripts: 2})
	if err == nil {
		t.Fatal("no key expected")
	}
	if f.hitCount("/s2.js") != 1 || f.hitCount("/s3.js") != 0 {
		t.Fatalf("cap not applied: s2=%d s3=%d", f.hitCount("/s2.js"), f.hitCount("/s3.js"))
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "script limit reached (2): 3 further") {
		t.Fatalf("notes = %v", res.Notes)
	}
	if DefaultMaxScripts != 60 {
		t.Fatalf("default cap = %d, want 60", DefaultMaxScripts)
	}
}

func TestNoKeyMessageSaysWhatWasTriedAndHowToFix(t *testing.T) {
	f := newStub(t, map[string]string{"": page(`<script>var a = 1;</script>`, `<script id="__NEXT_DATA__" type="application/json">{"props":{}}</script>`, `<script src="/x.js"></script>`), "x.js": "var b=2;"})
	_, err := Recon(context.Background(), f.srv, ReconConfig{TargetURL: f.url + "/", APIURL: f.url + "/api/v1/"})
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	for _, want := range []string{
		"no valid Flagsmith client key found",
		"tried 1 inline script(s), 1 JSON data block(s), 1 linked script(s) and 0 imported or preloaded chunk(s)",
		"GATECRASHER_CLIENT_KEYS=Production=<key>",
		"mobile apps, server-rendered pages",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q:\n%s", want, msg)
		}
	}
}

func TestSuppliedClientKeyUsedWhenBundleHasNone(t *testing.T) {
	f := newStub(t, map[string]string{"": page(`<script>var a = 1;</script>`)})
	res, err := Run(context.Background(), f.srv, ReconConfig{TargetURL: f.url + "/", APIURL: f.url + "/api/v1/", SuppliedKeys: map[string]string{"Production": goodKey}})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Inventory.KeySources; len(got) != 1 || got[0] != "GATECRASHER_CLIENT_KEYS (Production)" {
		t.Fatalf("sources = %v", got)
	}
}

func TestChunkRefs(t *testing.T) {
	webpack := `__webpack_require__.p="/_next/";__webpack_require__.u=e=>"static/chunks/"+e+"."+{123:"abc123",456:"def456"}[e]+".js";`
	cases := []struct {
		name, js string
		want     []string
	}{
		{"static", `import a from"./a.js";import{b}from '../b.mjs';export*from"./c.js";import"./side.js";import x from"flagsmith"`, []string{"./a.js", "../b.mjs", "./c.js", "./side.js"}},
		{"dynamic", `const m=()=>import( "./d.js" );import("/abs/e.js")`, []string{"./d.js", "/abs/e.js"}},
		{"vite", `m.f||(m.f=["assets/f.js","assets/f.css"])`, []string{"assets/f.js"}},
		{"webpack", webpack, []string{"/_next/static/chunks/123.abc123.js", "/_next/static/chunks/456.def456.js"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, r := range chunkRefs(tc.js) {
				got = append(got, r.ref)
			}
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Fatalf("refs = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIdentifierAssignmentForms(t *testing.T) {
	for _, assign := range []string{`K="` + goodKey + `"`, `const K = "` + goodKey + `"`, `var o={K:"` + goodKey + `"}`} {
		src := source{label: "m.js", text: assign + ";\n" + strings.Repeat("x", 500) + "\nflagsmith.init({environmentID:K})"}
		ex := extract([]source{src})
		if len(ex.candidates) != 1 || ex.candidates[0].rank != 0 || !strings.HasPrefix(ex.candidates[0].sources[0], "m.js:1 environmentID via K") {
			t.Errorf("%s: candidates = %+v", assign, ex.candidates)
		}
	}
}
