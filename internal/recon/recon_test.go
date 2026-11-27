package recon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/httpx"
	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
	"github.com/yarrasatwik/gatecrasher/internal/scope"
)

const (
	goodKey   = "AbCd3fGhJk5mNpQr7StUvW"
	badKey    = "ZzYyXx9wWvVuUt8sSrRqQp"
	serverKey = "ser.AbCdEfGhIjKlMnOp12345"
	labSecret = "acme_live_0123456789abcdef0123456789abcdef"
)

// stub is a tiny stand-in for the target site plus the Flagsmith API.
type stub struct {
	srv   *httpx.Client
	url   string
	mu    sync.Mutex
	pages map[string]string
	hits  map[string]int
}

func newStub(t *testing.T, pages map[string]string) *stub {
	t.Helper()
	redact.Reset()
	f := &stub{pages: pages, hits: map[string]int{}}
	ts := httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(ts.Close)
	f.url = ts.URL
	host := strings.TrimPrefix(ts.URL, "http://")
	f.srv = httpx.New(scope.MustNew(nil, []string{host}), httpx.WithRetries(0))
	return f
}

func (f *stub) page(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.ReplaceAll(f.pages[name], "{{API}}", f.url+"/api/v1/")
}

func (f *stub) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.hits[r.URL.Path]++
	f.mu.Unlock()
	if r.URL.Path == "/api/v1/flags/" {
		if r.Header.Get("X-Environment-Key") != goodKey {
			http.Error(w, `{"detail":"Invalid"}`, http.StatusUnauthorized)
			return
		}
		flags := []map[string]any{
			{"feature": map[string]any{"id": 2, "name": "payment_config", "type": "STANDARD"}, "enabled": true,
				"feature_state_value": `{"provider":"acmepay","api_secret":"` + labSecret + `","webhook":"https://internal.acmeshop.dev/pay"}`},
			{"feature": map[string]any{"id": 1, "name": "banner_text", "type": "STANDARD"}, "enabled": true, "feature_state_value": "Free shipping over $50"},
			{"feature": map[string]any{"id": 3, "name": "maintenance_mode", "type": "STANDARD"}, "enabled": false, "feature_state_value": nil},
			{"feature": map[string]any{"id": 4, "name": "max_items", "type": "STANDARD"}, "enabled": true, "feature_state_value": 12},
		}
		_ = json.NewEncoder(w).Encode(flags)
		return
	}
	if body := f.page(strings.TrimPrefix(r.URL.Path, "/")); body != "" {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(body))
		return
	}
	http.NotFound(w, r)
}

func (f *stub) hitCount(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

func page(scripts ...string) string {
	return "<html><body>" + strings.Join(scripts, "\n") + "</body></html>"
}

func TestUnminifiedBundle(t *testing.T) {
	bundle := "// shop\nimport flagsmith from 'flagsmith';\n\nflagsmith.init({\n  environmentID: \"" + goodKey + "\",\n  api: \"{{API}}\",\n});\n" +
		"flagsmith.setTrait(\"plan\", sel.value);\nflagsmith.setTraits({ role: 'x', \"beta_user\": 1 });\nflagsmith.identify(uid, { country: 'US', ltv: 3 });\n"
	f := newStub(t, map[string]string{
		"":              page(`<script src="/static/app.js"></script>`),
		"static/app.js": bundle,
	})
	res, err := Run(context.Background(), f.srv, ReconConfig{TargetURL: f.url + "/"})
	if err != nil {
		t.Fatal(err)
	}
	inv := res.Inventory
	if inv.Key != goodKey || inv.KeyFingerprint != redact.Fingerprint(goodKey, "CLIENT_KEY") {
		t.Fatalf("key/fingerprint wrong: %q %q", inv.Key, inv.KeyFingerprint)
	}
	if got := inv.KeySources; len(got) != 1 || got[0] != "app.js:5 environmentID" {
		t.Fatalf("key sources = %v", got)
	}
	if inv.APIURL != f.url+"/api/v1/" {
		t.Fatalf("api url = %q", inv.APIURL)
	}
	want := []string{"beta_user", "country", "ltv", "plan", "role"}
	if strings.Join(inv.TraitKeys, ",") != strings.Join(want, ",") {
		t.Fatalf("trait keys = %v, want %v", inv.TraitKeys, want)
	}
	if redact.String("x "+goodKey) == "x "+goodKey {
		t.Fatal("discovered key was not registered with redact")
	}
}

func TestMinifiedBundleAndInlineScript(t *testing.T) {
	min := `!function(){var a=window.flagsmith;a.init({environmentID:"` + goodKey + `",api:"{{API}}",cacheFlags:!0}),a.setTrait("tier","x")}();`
	inline := "var x = 1;\nfetch(u,{headers:{'X-Environment-Key':'" + badKey + "'}});"
	f := newStub(t, map[string]string{
		"":           page(`<script src='app.min.js'></script>`, "<script>"+inline+"</script>"),
		"app.min.js": min,
	})
	res, err := Run(context.Background(), f.srv, ReconConfig{TargetURL: f.url})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Inventory.KeySources[0]; got != "app.min.js:1 environmentID" {
		t.Fatalf("source = %q", got)
	}
	if len(res.Candidates) != 2 {
		t.Fatalf("candidates = %+v", res.Candidates)
	}
	var sawInline bool
	for _, c := range res.Candidates {
		if !c.Valid {
			sawInline = len(c.Sources) == 1 && c.Sources[0] == "inline-1:2 X-Environment-Key"
		}
	}
	if !sawInline {
		t.Fatalf("invalid inline candidate not recorded with line: %+v", res.Candidates)
	}
	if got := res.Inventory.TraitKeys; len(got) != 1 || got[0] != "tier" {
		t.Fatalf("trait keys = %v", got)
	}
}

func TestMultipleKeysOnlyValidOneUsed(t *testing.T) {
	js := `flagsmith.init({environmentID:"` + badKey + `"});
flagsmith.init({environmentID:"` + goodKey + `",api:"{{API}}"});`
	f := newStub(t, map[string]string{"": page(`<script src="a.js"></script>`), "a.js": js})
	res, err := Run(context.Background(), f.srv, ReconConfig{TargetURL: f.url})
	if err != nil {
		t.Fatal(err)
	}
	if res.Inventory.Key != goodKey || len(res.Candidates) != 2 {
		t.Fatalf("key=%q candidates=%+v", res.Inventory.Key, res.Candidates)
	}
	if f.hitCount("/api/v1/flags/") != 2 {
		t.Fatalf("expected one GET flags/ per candidate, got %d", f.hitCount("/api/v1/flags/"))
	}
}

func TestKeyShapedStringNearFlagsmith(t *testing.T) {
	js := `const cfg = { word: "ThisIsJustSomeLongWord", other: "x" };
window.flagsmith.init({ env: "` + goodKey + `" });`
	f := newStub(t, map[string]string{"": page(`<script src="a.js"></script>`), "a.js": js})
	res, err := Run(context.Background(), f.srv, ReconConfig{TargetURL: f.url, APIURL: f.url + "/api/v1/"})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Inventory.KeySources[0]; got != "a.js:2 key-shaped string near flagsmith" {
		t.Fatalf("source = %q", got)
	}
}

func TestOutOfScopeScriptSkippedWithNote(t *testing.T) {
	js := `flagsmith.init({environmentID:"` + goodKey + `",api:"{{API}}"});`
	f := newStub(t, map[string]string{
		"":     page(`<script src="https://cdn.evil.example/lib.js"></script>`, `<script src="/a.js"></script>`),
		"a.js": js,
	})
	res, err := Run(context.Background(), f.srv, ReconConfig{TargetURL: f.url})
	if err != nil {
		t.Fatal(err)
	}
	var noted bool
	for _, n := range res.Notes {
		noted = noted || strings.Contains(n, "skipped out-of-scope script cdn.evil.example/lib.js")
	}
	if !noted {
		t.Fatalf("notes = %v", res.Notes)
	}
	if f.srv.Sent() != 3 { // page, a.js, flags
		t.Fatalf("requests sent = %d, want 3 (out-of-scope script must not be requested)", f.srv.Sent())
	}
}

func TestOutOfScopeAPIHostRefused(t *testing.T) {
	js := `flagsmith.init({environmentID:"` + goodKey + `",api:"https://flags.attacker.example/api/v1/"});`
	f := newStub(t, map[string]string{"": page(`<script src="/a.js"></script>`), "a.js": js})
	_, err := Recon(context.Background(), f.srv, ReconConfig{TargetURL: f.url, APIURL: f.url + "/api/v1/"})
	if err == nil {
		t.Fatal("expected refusal")
	}
	if !strings.Contains(err.Error(), "out of scope") || !strings.Contains(err.Error(), "flags.attacker.example") {
		t.Fatalf("unclear error: %v", err)
	}
	if f.hitCount("/api/v1/flags/") != 0 {
		t.Fatal("flags must not be requested after refusing the API host")
	}
}

func TestRelativeAPIResolvedAgainstPage(t *testing.T) {
	js := `flagsmith.init({environmentID:"` + goodKey + `",api:"/api/v1/"});`
	f := newStub(t, map[string]string{"": page(`<script src="/a.js"></script>`), "a.js": js})
	inv, err := Recon(context.Background(), f.srv, ReconConfig{TargetURL: f.url})
	if err != nil {
		t.Fatal(err)
	}
	if inv.APIURL != f.url+"/api/v1/" {
		t.Fatalf("api = %q", inv.APIURL)
	}
}

func TestServerKeyInBundleIsCriticalLeak(t *testing.T) {
	js := `var k="` + serverKey + `";flagsmith.init({environmentID:"` + goodKey + `",api:"{{API}}"});`
	f := newStub(t, map[string]string{"": page(`<script src="/a.js"></script>`), "a.js": js})
	res, err := Run(context.Background(), f.srv, ReconConfig{TargetURL: f.url})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Leaks) != 1 || res.Leaks[0].Severity != model.SevCritical || res.Leaks[0].Source != "a.js:1" {
		t.Fatalf("leaks = %+v", res.Leaks)
	}
	if strings.Contains(res.Leaks[0].Fingerprint, serverKey) || strings.Contains(strings.Join(res.Notes, "\n"), serverKey) {
		t.Fatal("server key printed in clear")
	}
}

func TestNoKeyFound(t *testing.T) {
	f := newStub(t, map[string]string{"": page(`<script>var a = 1;</script>`)})
	_, err := Recon(context.Background(), f.srv, ReconConfig{TargetURL: f.url, APIURL: f.url + "/api/v1/"})
	if err == nil || !strings.Contains(err.Error(), "no valid Flagsmith client key") {
		t.Fatalf("err = %v", err)
	}
}

func TestInventoryFlagViews(t *testing.T) {
	js := `flagsmith.init({environmentID:"` + goodKey + `",api:"{{API}}"});`
	f := newStub(t, map[string]string{"": page(`<script src="/a.js"></script>`), "a.js": js})
	inv, err := Recon(context.Background(), f.srv, ReconConfig{TargetURL: f.url})
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]model.FlagView{}
	for _, fv := range inv.Flags {
		byName[fv.Name] = fv
	}
	pc := byName["payment_config"]
	if pc.ValueType != "json" || pc.Size == 0 || len([]rune(pc.Preview)) > 80 {
		t.Fatalf("payment_config view = %+v", pc)
	}
	if strings.Contains(pc.Preview, "0123456789abcdef") {
		t.Fatalf("secret leaked in preview: %s", pc.Preview)
	}
	if !strings.Contains(pc.RawValue.(string), labSecret) {
		t.Fatal("RawValue must keep the unredacted value in memory")
	}
	if b, _ := json.Marshal(pc); strings.Contains(string(b), labSecret) {
		t.Fatal("RawValue must never serialise")
	}
	cases := map[string]string{"banner_text": "string", "maintenance_mode": "null", "max_items": "number"}
	for n, vt := range cases {
		if byName[n].ValueType != vt {
			t.Errorf("%s value type = %s, want %s", n, byName[n].ValueType, vt)
		}
	}
	if byName["banner_text"].Preview != "Free shipping over $50" {
		t.Errorf("banner preview = %q", byName["banner_text"].Preview)
	}
	for i := 1; i < len(inv.Flags); i++ {
		if inv.Flags[i-1].Name > inv.Flags[i].Name {
			t.Fatal("flags must be sorted by name")
		}
	}
}
