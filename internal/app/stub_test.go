package app

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/config"
	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
)

const (
	stubOrgKey    = "stub-org-key-for-app-tests"
	stubClientKey = "REDACTED_PRODUCTION_CLIENT_KEY"
)

func fixtureBytes(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fixtureMap(t testing.TB, name string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(fixtureBytes(t, name), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// stubFlagsmith is a stateful in-memory Flagsmith built from the recorded
// fixtures: the Admin API, the public Flags/Identities API and the
// environment document. The environment settings and the features'
// "Server-side only" switch are writable, and the public API honours them
// the way Flagsmith does.
type stubFlagsmith struct {
	t   testing.TB
	srv *httptest.Server

	mu          sync.Mutex
	env         map[string]any
	features    map[int]map[string]any
	doc         map[string]any
	eng         *flagsmith.Engine
	experiments bool // serve the recorded experiments
	versioning  bool // env uses v2 feature versioning
	writes      []string
	published   int
	failAdmin   bool // every admin call answers 500
}

var featPathRe = regexp.MustCompile(`^projects/1/features/(\d+)/$`)

func newStubFlagsmith(t testing.TB) *stubFlagsmith {
	s := &stubFlagsmith{t: t, features: map[int]map[string]any{}}
	s.env = fixtureMap(t, "environment_settings")
	s.doc = fixtureMap(t, "environment_document")
	eng, err := flagsmith.NewEngine(fixtureBytes(t, "environment_document"))
	if err != nil {
		t.Fatal(err)
	}
	s.eng = eng
	for _, f := range fixtureMap(t, "features")["results"].([]any) {
		m := f.(map[string]any)
		s.features[int(m["id"].(float64))] = m
	}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *stubFlagsmith) apiURL() string { return s.srv.URL + "/api/v1/" }

func (s *stubFlagsmith) host() string {
	u, _ := url.Parse(s.srv.URL)
	return u.Host
}

func (s *stubFlagsmith) setEnv(k string, v any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.env[k] = v
}

func (s *stubFlagsmith) envBool(k string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := s.env[k].(bool)
	return b
}

func (s *stubFlagsmith) writeLog() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.writes...)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// served reports the flags a client key receives, honouring "Server-side
// only" features.
func (s *stubFlagsmith) served(flags flagsmith.Flags) []map[string]any {
	var out []map[string]any
	for _, name := range flags.Names() {
		for id, f := range s.features {
			if f["name"] == name && f["is_server_key_only"] == true {
				_ = id
				goto skip
			}
		}
		{
			f := flags[name]
			id := 0
			for fid, ft := range s.features {
				if ft["name"] == name {
					id = fid
				}
			}
			out = append(out, map[string]any{
				"feature":             map[string]any{"id": id, "name": name, "type": "STANDARD"},
				"feature_state_value": f.Value, "enabled": f.Enabled, "reason": f.Reason,
			})
		}
	skip:
	}
	return out
}

func (s *stubFlagsmith) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := strings.TrimPrefix(r.URL.Path, "/api/v1/")
	key := stubClientKey

	// Public SDK API.
	switch {
	case p == "flags/" && r.Method == http.MethodGet:
		if r.Header.Get("X-Environment-Key") != key {
			writeJSON(w, 401, map[string]string{"detail": "Invalid or missing Environment Key"})
			return
		}
		writeJSON(w, 200, s.served(s.eng.EvaluateEnvironment()))
		return
	case p == "identities/" && r.Method == http.MethodPost:
		var body struct {
			Identifier string `json:"identifier"`
			Traits     []struct {
				Key   string `json:"trait_key"`
				Value any    `json:"trait_value"`
			} `json:"traits"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		traits := map[string]string{}
		if allow, _ := s.env["allow_client_traits"].(bool); allow {
			for _, tr := range body.Traits {
				traits[tr.Key] = flagsmith.ValueString(tr.Value)
			}
		}
		writeJSON(w, 200, map[string]any{"identifier": body.Identifier, "traits": []any{},
			"flags": s.served(s.eng.Evaluate(body.Identifier, traits))})
		return
	case p == "identities/" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixtureBytes(s.t, "identity_lookup_ceo"))
		return
	case p == "environment-document/":
		writeJSON(w, 200, s.docWithSettings())
		return
	}

	// Admin API.
	if s.failAdmin {
		http.Error(w, "boom", 500)
		return
	}
	if r.Header.Get("Authorization") != "Api-Key "+stubOrgKey {
		writeJSON(w, 401, map[string]string{"detail": "Invalid API key"})
		return
	}
	if r.Method != http.MethodGet {
		b, _ := io.ReadAll(r.Body)
		s.writes = append(s.writes, r.Method+" "+p+" "+string(b))
		s.write(w, r, p, b)
		return
	}
	switch {
	case p == "organisations/":
		s.raw(w, "organisations")
	case p == "projects/":
		s.raw(w, "projects")
	case p == "environments/":
		out := fixtureMap(s.t, "environments")
		for _, e := range out["results"].([]any) {
			if m := e.(map[string]any); m["name"] == "Production" {
				for k, v := range s.env {
					m[k] = v
				}
			}
		}
		writeJSON(w, 200, out)
	case p == "environments/"+key+"/":
		writeJSON(w, 200, s.env)
	case p == "environments/"+key+"/document/":
		writeJSON(w, 200, s.docWithSettings())
	case p == "projects/1/features/":
		var res []any
		for id := 1; id <= len(s.features); id++ {
			res = append(res, s.features[id])
		}
		writeJSON(w, 200, map[string]any{"count": len(res), "next": nil, "results": res})
	case featPathRe.MatchString(p):
		id, _ := strconv.Atoi(featPathRe.FindStringSubmatch(p)[1])
		writeJSON(w, 200, s.features[id])
	case p == "projects/1/segments/":
		s.raw(w, "segments")
	case p == "projects/1/tags/":
		writeJSON(w, 200, []any{})
	case p == "environments/"+key+"/experiments/":
		if s.experiments {
			s.raw(w, "experiments")
		} else {
			writeJSON(w, 404, map[string]string{"detail": "Not found."})
		}
	case p == "environments/"+key+"/featurestates/":
		s.raw(w, "featurestates")
	case strings.HasPrefix(p, "environments/"+key+"/identities/"):
		s.rawStatus(w, "identities_admin")
	default:
		writeJSON(w, 404, map[string]string{"detail": "Not found: " + p})
	}
}

func (s *stubFlagsmith) docWithSettings() map[string]any {
	d := map[string]any{}
	for k, v := range s.doc {
		d[k] = v
	}
	for _, k := range []string{"allow_client_traits", "hide_sensitive_data"} {
		d[k] = s.env[k]
	}
	return d
}

func (s *stubFlagsmith) raw(w http.ResponseWriter, name string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(fixtureBytes(s.t, name))
}

func (s *stubFlagsmith) rawStatus(w http.ResponseWriter, name string) { s.raw(w, name) }

func (s *stubFlagsmith) write(w http.ResponseWriter, r *http.Request, p string, body []byte) {
	var patch map[string]any
	_ = json.Unmarshal(body, &patch)
	switch {
	case p == "environments/"+stubClientKey+"/" && (r.Method == "PATCH" || r.Method == "PUT"):
		for k, v := range patch {
			s.env[k] = v
		}
		writeJSON(w, 200, s.env)
	case featPathRe.MatchString(p) && r.Method == "PATCH":
		id, _ := strconv.Atoi(featPathRe.FindStringSubmatch(p)[1])
		for k, v := range patch {
			s.features[id][k] = v
		}
		writeJSON(w, 200, s.features[id])
	case p == "organisations/1/webhooks/" && r.Method == "POST":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		_, _ = w.Write(fixtureBytes(s.t, "organisation_webhook_create"))
	case p == "organisations/1/webhooks/1/" && r.Method == "DELETE":
		w.WriteHeader(204)
	default:
		writeJSON(w, 404, map[string]string{"detail": "no write route for " + r.Method + " " + p})
	}
}

// newTestApp builds an App wired to the stub with every state directory in
// t.TempDir(). The AI is off, so every explanation is deterministic.
func newTestApp(t testing.TB, s *stubFlagsmith, mutate func(*config.Config)) *App {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		Flagsmith: config.Flagsmith{APIURL: s.apiURL(), AllowedAPIHosts: []string{s.host()}, Project: "Acme Shop",
			Environments: []string{"Production"}},
		StateDir: filepath.Join(dir, "state"), ReportDir: filepath.Join(dir, "reports"), AI: config.AISettings{Provider: "off"},
		PropagationTimeoutS: 20, OrgAPIKey: stubOrgKey,
		Probes: config.Probes{RatePerSec: 5000},
	}
	cfg.Defaults()
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (s *stubFlagsmith) featureField(id int, k string) any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.features[id][k]
}
