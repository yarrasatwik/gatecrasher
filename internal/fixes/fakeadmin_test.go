package fixes

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/audit"
	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
	"github.com/yarrasatwik/gatecrasher/internal/httpx"
	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/scope"
)

const (
	testEnvKey = "clientkey0123456789"
	testOrgKey = "ABCDEFGH.0123456789abcdef0123456789abcdef" // gatecrasher:allow-secret (fake test key)
)

// fakeAdmin is a stateful in-memory Flagsmith Admin API. The environment
// document lags behind writes by docLag document reads, modelling
// propagation delay.
type fakeAdmin struct {
	mu                 sync.Mutex
	env                map[string]any
	docEnv             map[string]any
	features           map[int]map[string]any
	docFeatures        map[int]map[string]any
	featureStates      map[int]map[string]any // v1 environment feature states by id
	segments           []map[string]any
	experiments        []map[string]any
	docLag             int
	lagLeft            int
	writes             []string
	versions           map[string]map[int]map[string]any // uuid -> version feature states
	published          []string
	failPatch          bool
	docOmitsServerOnly bool
}

func newFakeAdmin() *fakeAdmin {
	f := &fakeAdmin{
		env: map[string]any{
			"id": float64(1), "name": "Production", "api_key": testEnvKey, "project": float64(1),
			"allow_client_traits": true, "hide_sensitive_data": false, "use_v2_feature_versioning": false,
		},
		features: map[int]map[string]any{
			5: {"id": float64(5), "name": "payment_config", "type": "STANDARD", "is_server_key_only": false},
			6: {"id": float64(6), "name": "checkout_ab", "type": "STANDARD", "is_server_key_only": false},
		},
		featureStates: map[int]map[string]any{
			9: {"id": float64(9), "feature": float64(6), "enabled": false, "feature_state_value": "off"},
		},
		segments: []map[string]any{{
			"id": float64(1), "name": "premium", "project": float64(1),
			"rules": []any{map[string]any{"type": "ALL", "rules": []any{
				map[string]any{"type": "ANY", "conditions": []any{
					map[string]any{"property": "plan", "operator": "EQUAL", "value": "premium"}}}}}},
		}},
		versions: map[string]map[int]map[string]any{},
	}
	f.docEnv, f.docFeatures = clone(f.env), cloneFeatures(f.features)
	return f
}

func clone(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cloneFeatures(m map[int]map[string]any) map[int]map[string]any {
	out := make(map[int]map[string]any, len(m))
	for k, v := range m {
		out[k] = clone(v)
	}
	return out
}

// set changes live state out of band (a human editing in the dashboard).
func (f *fakeAdmin) set(field string, v any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.env[field] = v
	f.docEnv[field] = v
}

func (f *fakeAdmin) get(field string) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.env[field]
}

func (f *fakeAdmin) featureField(id int, field string) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.features[id][field]
}

func (f *fakeAdmin) writeLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.writes...)
}

func (f *fakeAdmin) syncDoc() {
	if f.lagLeft > 0 {
		f.lagLeft--
		return
	}
	f.docEnv, f.docFeatures = clone(f.env), cloneFeatures(f.features)
}

var (
	reEnvRoot   = regexp.MustCompile(`^environments/([^/]+)/$`)
	reEnvDoc    = regexp.MustCompile(`^environments/([^/]+)/document/$`)
	reEnvExp    = regexp.MustCompile(`^environments/([^/]+)/experiments/$`)
	reFS        = regexp.MustCompile(`^environments/([^/]+)/featurestates/(\d+)/$`)
	reVersions  = regexp.MustCompile(`^environments/([^/]+)/features/(\d+)/versions/$`)
	reVerStates = regexp.MustCompile(`^environments/([^/]+)/features/(\d+)/versions/([^/]+)/featurestates/$`)
	reVerState  = regexp.MustCompile(`^environments/([^/]+)/features/(\d+)/versions/([^/]+)/featurestates/(\d+)/$`)
	rePublish   = regexp.MustCompile(`^environments/([^/]+)/features/(\d+)/versions/([^/]+)/publish/$`)
	reFeatures  = regexp.MustCompile(`^projects/1/features/$`)
	reFeature   = regexp.MustCompile(`^projects/1/features/(\d+)/$`)
)

func (f *fakeAdmin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Api-Key ") {
		http.Error(w, "no key", http.StatusUnauthorized)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/")
	var body map[string]any
	if r.Body != nil {
		if b, _ := io.ReadAll(r.Body); len(b) > 0 {
			_ = json.Unmarshal(b, &body)
		}
	}
	if r.Method != http.MethodGet {
		f.writes = append(f.writes, r.Method+" "+path+" "+fmt.Sprint(body))
		if f.failPatch {
			http.Error(w, `{"detail":"boom"}`, http.StatusInternalServerError)
			return
		}
	}
	out, status := f.route(r.Method, path, r.URL.Query(), body)
	if status == 0 {
		status = 200
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(out)
}

func (f *fakeAdmin) route(method, path string, q url.Values, body map[string]any) (any, int) {
	if m := reEnvRoot.FindStringSubmatch(path); m != nil {
		return f.objectRoute(method, f.env, body, true), 0
	}
	switch {
	case path == "environments/":
		return []any{f.env}, 0
	case reEnvDoc.MatchString(path):
		f.syncDoc()
		return f.document(), 0
	case reEnvExp.MatchString(path):
		return map[string]any{"results": f.experiments}, 0
	case reFeatures.MatchString(path):
		var out []any
		for _, id := range []int{5, 6} {
			out = append(out, f.features[id])
		}
		return map[string]any{"results": out}, 0
	case path == "projects/1/segments/":
		return map[string]any{"results": f.segments}, 0
	}
	if m := reFeature.FindStringSubmatch(path); m != nil {
		id := atoi(m[1])
		return f.objectRoute(method, f.features[id], body, false), 0
	}
	if m := reFS.FindStringSubmatch(path); m != nil {
		return f.objectRoute(method, f.featureStates[atoi(m[2])], body, false), 0
	}
	return f.versionRoute(method, path, body)
}

func (f *fakeAdmin) versionRoute(method, path string, body map[string]any) (any, int) {
	if m := reVersions.FindStringSubmatch(path); m != nil && method == http.MethodPost {
		uuid := fmt.Sprintf("ver-%d", len(f.versions)+1)
		f.versions[uuid] = map[int]map[string]any{100: {"id": float64(100), "feature": float64(atoi(m[2])), "enabled": false, "feature_state_value": "off"},
			101: {"id": float64(101), "feature": float64(atoi(m[2])), "feature_segment": float64(7), "enabled": true}}
		return map[string]any{"uuid": uuid}, 201
	}
	if m := reVerStates.FindStringSubmatch(path); m != nil {
		var out []any
		for _, id := range []int{100, 101} {
			out = append(out, f.versions[m[3]][id])
		}
		return out, 0
	}
	if m := reVerState.FindStringSubmatch(path); m != nil && method == http.MethodPatch {
		st := f.versions[m[3]][atoi(m[4])]
		for k, v := range body {
			st[k] = v
		}
		return st, 0
	}
	if m := rePublish.FindStringSubmatch(path); m != nil && method == http.MethodPost {
		f.published = append(f.published, m[3])
		for k, v := range f.versions[m[3]][100] {
			if k != "id" {
				f.featureStates[9][k] = v
			}
		}
		return map[string]any{}, 0
	}
	return map[string]any{"detail": "not found: " + path}, http.StatusNotFound
}

func (f *fakeAdmin) objectRoute(method string, obj map[string]any, body map[string]any, isEnv bool) any {
	if method == http.MethodPatch {
		for k, v := range body {
			obj[k] = v
		}
		f.lagLeft = f.docLag
	}
	return obj
}

func (f *fakeAdmin) document() map[string]any {
	doc := clone(f.docEnv)
	var states []any
	for _, id := range []int{5, 6} {
		ft := clone(f.docFeatures[id])
		if f.docOmitsServerOnly {
			delete(ft, "is_server_key_only")
		}
		st := map[string]any{"feature": ft, "enabled": true, "feature_state_value": "x"}
		if id == 6 {
			st["enabled"], st["feature_state_value"] = f.featureStates[9]["enabled"], f.featureStates[9]["feature_state_value"]
		}
		states = append(states, st)
	}
	doc["feature_states"] = states
	return doc
}

func atoi(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}

// harness bundles the fake, a real flagsmith.Admin client pointed at it,
// and an audit-enabled store.
type harness struct {
	fake  *fakeAdmin
	admin *flagsmith.Admin
	store *Store
	log   *audit.Log
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	fake := newFakeAdmin()
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	client := httpx.New(scope.MustNew(nil, []string{u.Host}), httpx.WithRetries(0), httpx.WithTimeout(5*time.Second))
	dir := t.TempDir()
	log, err := audit.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	store.Audit = log
	return &harness{fake: fake, admin: flagsmith.NewAdmin(client, srv.URL+"/api/v1/", testOrgKey), store: store, log: log}
}

func (h *harness) planner(repo string) *Planner {
	return NewPlanner(PlannerConfig{
		Admin: h.admin, ProjectID: 1, RepoDir: repo,
		Environments: []EnvRef{{Name: "Production", Key: testEnvKey, Production: true}, {Name: "Staging", Key: "stagingkey0123456789"}},
	})
}

func (h *harness) applier(opts ...func(*Config)) *Applier {
	cfg := Config{Admin: h.admin, Store: h.store, Audit: h.log, ProjectID: 1, Timeout: 2 * time.Second, PollInterval: 5 * time.Millisecond}
	for _, o := range opts {
		o(&cfg)
	}
	return NewApplier(cfg)
}

// planFor builds, stores and returns the pending record for findings.
func (h *harness) planFor(t *testing.T, repo string, findings ...model.Finding) []*model.PlanRecord {
	t.Helper()
	plans, err := h.planner(repo).Plan(t.Context(), findings)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	recs, err := h.store.Create(plans)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func traitFinding() model.Finding {
	return model.Finding{ID: "GC-TRAIT01", Type: model.FTraitForgery, Environment: "Production", Subject: "plan", Status: model.StatusExploitable, Title: "plan trait forgeable"}
}

func leakFinding() model.Finding {
	return model.Finding{ID: "GC-LEAK0001", Type: model.FIdentityTraitLeak, Environment: "Production", Subject: "identity", Status: model.StatusExploitable, Title: "identity traits leak"}
}

func secretFinding() model.Finding {
	return model.Finding{ID: "GC-SECRET01", Type: model.FSecretExposed, Environment: "Production", Subject: "payment_config", Category: model.CatSecret, Status: model.StatusExploitable, Title: "secret in flag"}
}
