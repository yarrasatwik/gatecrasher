package flagsmith_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
	"github.com/yarrasatwik/gatecrasher/internal/httpx"
	"github.com/yarrasatwik/gatecrasher/internal/scope"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func bg() context.Context { return context.Background() }

// serve starts a server answering every request through h and returns a
// scoped client plus the API base URL.
func serve(t *testing.T, retries int, h http.HandlerFunc) (*httpx.Client, string) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	c := httpx.New(scope.MustNew(nil, []string{u.Host}), httpx.WithRetries(retries))
	return c, srv.URL + "/api/v1/"
}

// fixtureServer maps "METHOD path" (below /api/v1/) to a fixture name.
func fixtureServer(t *testing.T, routes map[string]string) (*httpx.Client, string) {
	return serve(t, 0, func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/api/v1/")
		name, ok := routes[r.Method+" "+p]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(fixture(t, name))
	})
}

func TestAdminListEndpointsFromFixtures(t *testing.T) {
	c, api := fixtureServer(t, map[string]string{
		"GET organisations/":                           "organisations",
		"GET projects/":                                "projects",
		"GET environments/":                            "environments",
		"GET environments/ENVKEY/":                     "environment_settings",
		"GET projects/1/features/":                     "features",
		"GET projects/1/segments/":                     "segments",
		"GET environments/ENVKEY/featurestates/":       "featurestates",
		"GET environments/ENVKEY/experiments/":         "experiments",
		"GET environments/ENVKEY/document/":            "environment_document",
		"GET environments/ENVKEY/api-keys/":            "environment_api_keys",
		"GET organisations/1/webhooks/":                "organisation_webhooks_list",
		"GET environments/ENVKEY/features/1/versions/": "feature_versions_v2",
	})
	ctx := bg()
	a := flagsmith.NewAdmin(c, api, "orgkey-for-tests")
	if a.APIURL() != api {
		t.Fatalf("APIURL = %q", a.APIURL())
	}

	orgs, err := a.Organisations(ctx)
	if err != nil || len(orgs) != 1 || orgs[0].Name != "Acme Labs" {
		t.Fatalf("orgs = %+v, %v", orgs, err)
	}
	ps, err := a.Projects(ctx)
	if err != nil || len(ps) != 1 {
		t.Fatalf("projects = %+v, %v", ps, err)
	}
	p, err := a.ProjectByName(ctx, "Acme Shop")
	if err != nil || p.ID != 1 {
		t.Fatalf("ProjectByName = %+v, %v", p, err)
	}
	if p, err = a.ProjectByName(ctx, ""); err != nil || p.Name != "Acme Shop" {
		t.Fatalf("sole project by empty name = %+v, %v", p, err)
	}
	if _, err = a.ProjectByName(ctx, "nope"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing project err = %v", err)
	}

	envs, err := a.Environments(ctx, 1)
	if err != nil || len(envs) != 2 {
		t.Fatalf("envs = %+v, %v", envs, err)
	}
	prod, err := a.EnvironmentByName(ctx, 1, "production")
	if err != nil || prod.Name != "Production" || prod.APIKey == "" {
		t.Fatalf("EnvironmentByName = %+v, %v", prod, err)
	}
	if _, err = a.EnvironmentByName(ctx, 1, "staging"); err == nil {
		t.Fatal("expected not-found error")
	}
	one, err := a.Environment(ctx, "ENVKEY")
	if err != nil || one.Name == "" {
		t.Fatalf("Environment = %+v, %v", one, err)
	}

	feats, err := a.Features(ctx, 1)
	if err != nil || len(feats) != 11 || feats[0].Name != "premium_export" {
		t.Fatalf("features = %d, %v", len(feats), err)
	}
	segs, err := a.Segments(ctx, 1)
	if err != nil || len(segs) == 0 {
		t.Fatalf("segments = %d, %v", len(segs), err)
	}
	states, err := a.FeatureStates(ctx, "ENVKEY")
	if err != nil || len(states) == 0 {
		t.Fatalf("states = %d, %v", len(states), err)
	}
	exps, err := a.Experiments(ctx, "ENVKEY")
	if err != nil || len(exps) != 1 {
		t.Fatalf("experiments = %+v, %v", exps, err)
	}
	if exps[0].FeatureID() != 5 {
		t.Fatalf("experiment feature id = %d", exps[0].FeatureID())
	}
	doc, err := a.EnvironmentDocument(ctx, "ENVKEY")
	if err != nil || !json.Valid(doc) {
		t.Fatalf("document: %v", err)
	}

	var versions struct {
		Results []struct {
			UUID      string `json:"uuid"`
			Published bool   `json:"published"`
		} `json:"results"`
	}
	if err := a.Get(ctx, "environments/ENVKEY/features/1/versions/", &versions); err != nil || len(versions.Results) != 2 || !versions.Results[0].Published {
		t.Fatalf("versions = %+v, %v", versions, err)
	}
	var keys any
	if err := a.Get(ctx, "environments/ENVKEY/api-keys/", &keys); err != nil {
		t.Fatal(err)
	}
	var hooks any
	if err := a.Get(ctx, api+"organisations/1/webhooks/", &hooks); err != nil { // absolute URL form
		t.Fatal(err)
	}
}

func TestAdminTags(t *testing.T) {
	c, api := serve(t, 0, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `[{"id":3,"label":"beta"}]`)
	})
	tags, err := flagsmith.NewAdmin(c, api, "k-tags-test").Tags(bg(), 1)
	if err != nil || len(tags) != 1 || tags[0].Label != "beta" {
		t.Fatalf("tags = %+v, %v", tags, err)
	}
}

func TestAdminSendsApiKeyHeaderAndNeedsKey(t *testing.T) {
	var got string
	c, api := serve(t, 0, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, `{"results":[],"next":null}`)
	})
	a := flagsmith.NewAdmin(c, api, "secret-org-key")
	if _, err := a.Organisations(bg()); err != nil {
		t.Fatal(err)
	}
	if got != "Api-Key secret-org-key" {
		t.Fatalf("Authorization = %q", got)
	}
	var nilAdmin *flagsmith.Admin
	if err := nilAdmin.Get(bg(), "x/", nil); !errors.Is(err, flagsmith.ErrNoAdminKey) {
		t.Fatalf("nil admin err = %v", err)
	}
	if err := flagsmith.NewAdmin(c, api, "").Get(bg(), "x/", nil); !errors.Is(err, flagsmith.ErrNoAdminKey) {
		t.Fatalf("empty key err = %v", err)
	}
}

func TestAdminPaginationFollowsNext(t *testing.T) {
	var base string
	c, api := serve(t, 0, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			_, _ = io.WriteString(w, `{"results":[{"id":2,"name":"B"}],"next":null}`)
			return
		}
		_, _ = io.WriteString(w, `{"results":[{"id":1,"name":"A"}],"next":"`+base+`organisations/?page=2"}`)
	})
	base = api
	orgs, err := flagsmith.NewAdmin(c, api, "k-pagination").Organisations(bg())
	if err != nil || len(orgs) != 2 || orgs[1].Name != "B" {
		t.Fatalf("orgs = %+v, %v", orgs, err)
	}
}

func TestAdminMalformedBodies(t *testing.T) {
	for name, body := range map[string]string{"array": `[1,2,"x"]`, "paged": `{"results":"nope"}`, "garbage": `not json`} {
		t.Run(name, func(t *testing.T) {
			c, api := serve(t, 0, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) })
			if _, err := flagsmith.NewAdmin(c, api, "k-malformed").Organisations(bg()); err == nil {
				t.Fatal("expected a decode error")
			}
		})
	}
}

func TestEnvironmentDocumentServerKey(t *testing.T) {
	var key string
	c, api := serve(t, 0, func(w http.ResponseWriter, r *http.Request) {
		key = r.Header.Get("X-Environment-Key")
		if r.URL.Path != "/api/v1/environment-document/" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(fixture(t, "environment_document"))
	})
	raw, err := flagsmith.EnvironmentDocumentServerKey(bg(), c, api, "ser.testkey")
	if err != nil || !json.Valid(raw) || key != "ser.testkey" {
		t.Fatalf("raw ok=%v key=%q err=%v", json.Valid(raw), key, err)
	}
}

func TestAdminErrorPaths(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusBadRequest} {
		c, api := serve(t, 2, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write(fixture(t, "audit_generic_error"))
		})
		_, err := flagsmith.NewAdmin(c, api, "k-errs").Organisations(bg())
		var se *httpx.StatusError
		if !errors.As(err, &se) || se.Status != status {
			t.Fatalf("status %d: err = %v", status, err)
		}
	}
}

func TestAdminRetries429And5xx(t *testing.T) {
	for _, bad := range []int{http.StatusTooManyRequests, http.StatusBadGateway} {
		var calls atomic.Int32
		c, api := serve(t, 2, func(w http.ResponseWriter, r *http.Request) {
			if calls.Add(1) < 3 {
				w.WriteHeader(bad)
				return
			}
			_, _ = w.Write(fixture(t, "organisations"))
		})
		orgs, err := flagsmith.NewAdmin(c, api, "k-retry").Organisations(bg())
		if err != nil || len(orgs) != 1 || calls.Load() != 3 {
			t.Fatalf("status %d: orgs=%d calls=%d err=%v", bad, len(orgs), calls.Load(), err)
		}
	}
}

func TestAdminGivesUpAfterRetries(t *testing.T) {
	var calls atomic.Int32
	c, api := serve(t, 1, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})
	_, err := flagsmith.NewAdmin(c, api, "k-giveup").Organisations(bg())
	var se *httpx.StatusError
	if !errors.As(err, &se) || se.Status != 500 || calls.Load() != 2 {
		t.Fatalf("calls=%d err=%v", calls.Load(), err)
	}
}

func TestAdminOversizedBody(t *testing.T) {
	c, api := serve(t, 0, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"results":["` + strings.Repeat("a", httpx.MaxBody+10) + `"]}`))
	})
	_, err := flagsmith.NewAdmin(c, api, "k-big").Organisations(bg())
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v", err)
	}
}

func TestAdminOutOfScopeRefused(t *testing.T) {
	c := httpx.New(scope.MustNew(nil, []string{"127.0.0.1:1"}), httpx.WithRetries(0))
	a := flagsmith.NewAdmin(c, "http://127.0.0.1:2/api/v1/", "k-scope")
	if _, err := a.Organisations(bg()); !errors.Is(err, scope.ErrOutOfScope) {
		t.Fatalf("err = %v", err)
	}
}

// TestAdminVersioningWrites exercises the writes Gatecrasher's fixes make on
// v1 (PUT featurestates) and v2 (create version, edit its state, publish).
func TestAdminVersioningWrites(t *testing.T) {
	type call struct{ method, path, body string }
	var calls []call
	c, api := serve(t, 0, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		calls = append(calls, call{r.Method, strings.TrimPrefix(r.URL.Path, "/api/v1/"), string(b)})
		switch {
		case strings.HasSuffix(r.URL.Path, "/publish/"):
			_, _ = w.Write(fixture(t, "feature_version_publish"))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/versions/"):
			_, _ = io.WriteString(w, `{"uuid":"new-version","published":false}`)
		default:
			_, _ = io.WriteString(w, `{"id":9,"enabled":false}`)
		}
	})
	a := flagsmith.NewAdmin(c, api, "k-writes")
	ctx := bg()

	var st flagsmith.FeatureState
	if err := a.Do(ctx, "PUT", "environments/E/featurestates/9/", map[string]any{"enabled": false}, &st); err != nil || st.ID != 9 {
		t.Fatalf("v1 put: %+v %v", st, err)
	}
	var ver struct {
		UUID string `json:"uuid"`
	}
	if err := a.Do(ctx, "POST", "environments/E/features/1/versions/", map[string]any{}, &ver); err != nil || ver.UUID != "new-version" {
		t.Fatalf("v2 create: %+v %v", ver, err)
	}
	if err := a.Do(ctx, "PUT", "environments/E/features/1/versions/new-version/featurestates/9/", map[string]any{"enabled": false}, nil); err != nil {
		t.Fatal(err)
	}
	var pub struct {
		LiveFrom string `json:"live_from"`
	}
	if err := a.Do(ctx, "POST", "environments/E/features/1/versions/new-version/publish/", map[string]any{}, &pub); err != nil || pub.LiveFrom == "" {
		t.Fatalf("v2 publish: %+v %v", pub, err)
	}
	if len(calls) != 4 || calls[0].method != "PUT" || calls[3].method != "POST" || !strings.Contains(calls[1].path, "versions") ||
		calls[0].body != `{"enabled":false}` {
		t.Fatalf("calls = %+v", calls)
	}

	// A failing non-GET write is not retried and surfaces the status.
	var n atomic.Int32
	c2, api2 := serve(t, 2, func(w http.ResponseWriter, r *http.Request) { n.Add(1); w.WriteHeader(502) })
	err := flagsmith.NewAdmin(c2, api2, "k-writes2").Do(ctx, "POST", "environments/E/features/1/versions/", map[string]any{}, nil)
	var se *httpx.StatusError
	if !errors.As(err, &se) || n.Load() != 1 {
		t.Fatalf("write retried or wrong err: %v (calls %d)", err, n.Load())
	}
}

func TestExperimentHelpers(t *testing.T) {
	cases := []struct {
		e       flagsmith.Experiment
		id      int
		running bool
	}{
		{flagsmith.Experiment{Feature: float64(7), Status: "running"}, 7, true},
		{flagsmith.Experiment{Feature: map[string]any{"id": float64(8)}, Status: "IN_PROGRESS"}, 8, true},
		{flagsmith.Experiment{Feature: map[string]any{"id": "x"}, Status: "STARTED"}, 0, true},
		{flagsmith.Experiment{Feature: "weird", Status: "ACTIVE"}, 0, true},
		{flagsmith.Experiment{Status: "DRAFT"}, 0, false},
	}
	for i, c := range cases {
		if c.e.FeatureID() != c.id || c.e.Running() != c.running {
			t.Errorf("case %d: id=%d running=%v", i, c.e.FeatureID(), c.e.Running())
		}
	}
}
