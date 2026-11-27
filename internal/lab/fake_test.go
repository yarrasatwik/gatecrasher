package lab

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeFlagsmith is a small in-memory stand-in for the Flagsmith endpoints the
// seed uses. It records every mutating request so tests can assert that a
// converged lab triggers none.
type fakeFlagsmith struct {
	mu        sync.Mutex
	next      int
	users     map[string]string
	orgs      []map[string]any
	orgKey    string
	projects  []map[string]any
	envs      []map[string]any
	envKeys   map[string][]map[string]any
	tags      []map[string]any
	segments  []map[string]any
	features  []map[string]any
	states    []map[string]any
	links     []map[string]any
	idents    map[string]map[string]map[string]any // env key -> identifier -> identity
	traits    map[string]map[string]any            // env key|identifier -> traits
	idStates  []map[string]any
	exps      []map[string]any
	mutations []string
}

func newFake() *fakeFlagsmith {
	return &fakeFlagsmith{users: map[string]string{}, envKeys: map[string][]map[string]any{},
		idents: map[string]map[string]map[string]any{}, traits: map[string]map[string]any{}}
}

func (f *fakeFlagsmith) id() int { f.next++; return f.next }

func (f *fakeFlagsmith) start(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	h := func(pattern string, fn func(r *http.Request, body map[string]any) (int, any)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			defer f.mu.Unlock()
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if r.Method != http.MethodGet && !strings.HasSuffix(r.URL.Path, "/auth/login/") {
				f.mutations = append(f.mutations, r.Method+" "+r.URL.Path)
			}
			status, out := fn(r, body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(out)
		})
	}
	h("GET /health/liveness/", func(*http.Request, map[string]any) (int, any) { return 200, map[string]string{"status": "ok"} })
	f.routeAuthAndOrg(h)
	f.routeProject(h)
	f.routeFeatures(h)
	f.routeEnvState(h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func filter(items []map[string]any, key string, want any) []map[string]any {
	out := []map[string]any{}
	for _, it := range items {
		if fmt.Sprint(it[key]) == fmt.Sprint(want) {
			out = append(out, it)
		}
	}
	return out
}

func page(items []map[string]any) map[string]any {
	return map[string]any{"count": len(items), "next": nil, "results": items}
}

func byID(items []map[string]any, id string) map[string]any {
	for _, it := range items {
		if fmt.Sprint(it["id"]) == id {
			return it
		}
	}
	return nil
}

func merge(dst, src map[string]any) {
	for k, v := range src {
		dst[k] = v
	}
}

type handler func(pattern string, fn func(r *http.Request, body map[string]any) (int, any))

func (f *fakeFlagsmith) routeAuthAndOrg(h handler) {
	h("POST /api/v1/auth/users/", func(_ *http.Request, b map[string]any) (int, any) {
		if _, exists := f.users[b["email"].(string)]; exists {
			return 400, map[string]any{"email": []string{"Email already exists. Please log in."}}
		}
		f.users[b["email"].(string)] = b["password"].(string)
		return 201, map[string]any{}
	})
	h("POST /api/v1/auth/login/", func(_ *http.Request, b map[string]any) (int, any) {
		if pw, ok := f.users[b["email"].(string)]; ok && pw == b["password"] {
			return 200, map[string]string{"key": "token-1"}
		}
		return 400, map[string]string{"detail": "bad credentials"}
	})
	h("GET /api/v1/organisations/", func(r *http.Request, _ map[string]any) (int, any) {
		if strings.HasPrefix(r.Header.Get("Authorization"), "Api-Key ") && r.Header.Get("Authorization") != "Api-Key "+f.orgKey {
			return 401, map[string]string{}
		}
		return 200, page(f.orgs)
	})
	h("POST /api/v1/organisations/", func(_ *http.Request, b map[string]any) (int, any) {
		o := map[string]any{"id": f.id(), "name": b["name"]}
		f.orgs = append(f.orgs, o)
		return 201, o
	})
	h("POST /api/v1/organisations/{id}/master-api-keys/", func(*http.Request, map[string]any) (int, any) {
		f.orgKey = "ORGKEY" + strconv.Itoa(f.id()) + ".abcdefghijklmnopqrstuvwxyz012345"
		return 201, map[string]any{"key": f.orgKey}
	})
}

func (f *fakeFlagsmith) routeProject(h handler) {
	h("GET /api/v1/projects/", func(r *http.Request, _ map[string]any) (int, any) {
		if r.Header.Get("Authorization") != "Api-Key "+f.orgKey {
			return 401, map[string]string{}
		}
		return 200, filter(f.projects, "organisation", r.URL.Query().Get("organisation"))
	})
	h("POST /api/v1/projects/", func(_ *http.Request, b map[string]any) (int, any) {
		p := map[string]any{"id": f.id(), "name": b["name"], "organisation": int(b["organisation"].(float64))}
		f.projects = append(f.projects, p)
		return 201, p
	})
	h("GET /api/v1/environments/", func(r *http.Request, _ map[string]any) (int, any) {
		return 200, page(filter(f.envs, "project", r.URL.Query().Get("project")))
	})
	h("POST /api/v1/environments/", func(_ *http.Request, b map[string]any) (int, any) {
		e := map[string]any{"id": f.id(), "name": b["name"], "project": int(b["project"].(float64)),
			"api_key": "ENVKEY" + strconv.Itoa(f.next) + "abcdefghijklmn", "allow_client_traits": true, "hide_sensitive_data": false}
		f.envs = append(f.envs, e)
		for _, ft := range f.features {
			f.addBaseState(e, ft)
		}
		return 201, e
	})
	h("PATCH /api/v1/environments/{key}/", func(r *http.Request, b map[string]any) (int, any) {
		for _, e := range f.envs {
			if e["api_key"] == r.PathValue("key") {
				merge(e, b)
				return 200, e
			}
		}
		return 404, nil
	})
	h("GET /api/v1/environments/{key}/api-keys/", func(r *http.Request, _ map[string]any) (int, any) {
		return 200, f.envKeys[r.PathValue("key")]
	})
	h("POST /api/v1/environments/{key}/api-keys/", func(r *http.Request, b map[string]any) (int, any) {
		k := map[string]any{"key": "ser." + strconv.Itoa(f.id()) + "SERVERKEYabcdef", "name": b["name"], "active": true}
		f.envKeys[r.PathValue("key")] = append(f.envKeys[r.PathValue("key")], k)
		return 201, k
	})
	h("GET /api/v1/projects/{p}/tags/", func(*http.Request, map[string]any) (int, any) { return 200, page(f.tags) })
	h("POST /api/v1/projects/{p}/tags/", func(_ *http.Request, b map[string]any) (int, any) {
		t := map[string]any{"id": f.id(), "label": b["label"]}
		f.tags = append(f.tags, t)
		return 201, t
	})
	h("GET /api/v1/projects/{p}/segments/", func(*http.Request, map[string]any) (int, any) { return 200, page(f.segments) })
	h("POST /api/v1/projects/{p}/segments/", func(_ *http.Request, b map[string]any) (int, any) {
		b["id"] = f.id()
		f.segments = append(f.segments, b)
		return 201, b
	})
	h("PUT /api/v1/projects/{p}/segments/{id}/", func(r *http.Request, b map[string]any) (int, any) {
		merge(byID(f.segments, r.PathValue("id")), b)
		return 200, b
	})
}

func (f *fakeFlagsmith) addBaseState(env, feature map[string]any) {
	f.states = append(f.states, map[string]any{"id": f.id(), "feature": feature["id"], "environment": env["id"],
		"enabled": feature["default_enabled"], "feature_state_value": feature["initial_value"],
		"feature_segment": nil, "identity": nil, "multivariate_feature_state_values": []any{}})
}

func (f *fakeFlagsmith) routeFeatures(h handler) {
	h("GET /api/v1/projects/{p}/features/", func(*http.Request, map[string]any) (int, any) { return 200, page(f.features) })
	h("POST /api/v1/projects/{p}/features/", func(_ *http.Request, b map[string]any) (int, any) {
		b["id"] = f.id()
		b["tags"] = nonNilSlice(b["tags"])
		opts := []any{}
		if raw, ok := b["multivariate_options"].([]any); ok {
			for _, o := range raw {
				om := o.(map[string]any)
				om["id"] = f.id()
				opts = append(opts, om)
			}
		}
		b["multivariate_options"] = opts
		f.features = append(f.features, b)
		for _, e := range f.envs {
			f.addBaseState(e, b)
		}
		return 201, b
	})
	h("PATCH /api/v1/projects/{p}/features/{id}/", func(r *http.Request, b map[string]any) (int, any) {
		ft := byID(f.features, r.PathValue("id"))
		merge(ft, b)
		return 200, ft
	})
}

func nonNilSlice(v any) any {
	if v == nil {
		return []any{}
	}
	return v
}

func (f *fakeFlagsmith) routeEnvState(h handler) {
	h("GET /api/v1/environments/{key}/featurestates/", func(r *http.Request, _ map[string]any) (int, any) {
		return 200, page(filter(f.statesFor(r.PathValue("key")), "feature", r.URL.Query().Get("feature")))
	})
	h("PATCH /api/v1/environments/{key}/featurestates/{id}/", func(r *http.Request, b map[string]any) (int, any) {
		merge(byID(f.states, r.PathValue("id")), b)
		return 200, b
	})
	h("GET /api/v1/features/feature-segments/", func(r *http.Request, _ map[string]any) (int, any) {
		return 200, page(filter(filter(f.links, "environment", r.URL.Query().Get("environment")), "feature", r.URL.Query().Get("feature")))
	})
	h("POST /api/v1/environments/{key}/features/{fid}/create-segment-override/", func(r *http.Request, b map[string]any) (int, any) {
		env := f.envByKey(r.PathValue("key"))
		fid, _ := strconv.Atoi(r.PathValue("fid"))
		seg := int(b["feature_segment"].(map[string]any)["segment"].(float64))
		link := map[string]any{"id": f.id(), "segment": seg, "environment": env["id"], "feature": fid}
		f.links = append(f.links, link)
		f.states = append(f.states, map[string]any{"id": f.id(), "feature": fid, "environment": env["id"],
			"enabled": b["enabled"], "feature_segment": link["id"], "identity": nil, "feature_state_value": nil})
		return 201, link
	})
	h("GET /api/v1/identities/", func(r *http.Request, _ map[string]any) (int, any) {
		key, ident := r.Header.Get("X-Environment-Key"), r.URL.Query().Get("identifier")
		f.ensureIdentity(key, ident)
		return 200, map[string]any{"identifier": ident, "traits": f.traitList(key, ident)}
	})
	h("POST /api/v1/identities/", func(r *http.Request, b map[string]any) (int, any) {
		key, ident := r.Header.Get("X-Environment-Key"), b["identifier"].(string)
		f.ensureIdentity(key, ident)
		tr := map[string]any{}
		for _, t := range b["traits"].([]any) {
			tm := t.(map[string]any)
			tr[tm["trait_key"].(string)] = tm["trait_value"]
		}
		f.traits[key+"|"+ident] = tr
		return 200, map[string]any{"identifier": ident, "traits": f.traitList(key, ident)}
	})
	f.routeIdentityOverrides(h)
	f.routeExperiments(h)
}

func (f *fakeFlagsmith) envByKey(key string) map[string]any {
	for _, e := range f.envs {
		if e["api_key"] == key {
			return e
		}
	}
	return nil
}

func (f *fakeFlagsmith) statesFor(key string) []map[string]any {
	return filter(f.states, "environment", f.envByKey(key)["id"])
}

func (f *fakeFlagsmith) ensureIdentity(key, ident string) {
	if f.idents[key] == nil {
		f.idents[key] = map[string]map[string]any{}
	}
	if f.idents[key][ident] == nil {
		f.idents[key][ident] = map[string]any{"id": f.id(), "identifier": ident}
	}
}

func (f *fakeFlagsmith) traitList(key, ident string) []map[string]any {
	out := []map[string]any{}
	for k, v := range f.traits[key+"|"+ident] {
		out = append(out, map[string]any{"trait_key": k, "trait_value": v})
	}
	return out
}

func (f *fakeFlagsmith) routeIdentityOverrides(h handler) {
	h("GET /api/v1/environments/{key}/identities/", func(r *http.Request, _ map[string]any) (int, any) {
		out := []map[string]any{}
		for ident, row := range f.idents[r.PathValue("key")] {
			if strings.Contains(ident, r.URL.Query().Get("q")) {
				out = append(out, row)
			}
		}
		return 200, page(out)
	})
	h("GET /api/v1/environments/{key}/identities/{iid}/featurestates/", func(r *http.Request, _ map[string]any) (int, any) {
		return 200, page(filter(f.idStates, "identity_id", r.PathValue("iid")))
	})
	h("POST /api/v1/environments/{key}/identities/{iid}/featurestates/", func(r *http.Request, b map[string]any) (int, any) {
		b["id"] = f.id()
		b["identity_id"] = r.PathValue("iid")
		f.idStates = append(f.idStates, b)
		return 201, b
	})
	h("PATCH /api/v1/environments/{key}/identities/{iid}/featurestates/{id}/", func(r *http.Request, b map[string]any) (int, any) {
		merge(byID(f.idStates, r.PathValue("id")), b)
		return 200, b
	})
}

func (f *fakeFlagsmith) routeExperiments(h handler) {
	h("GET /api/v1/environments/{key}/experiments/", func(r *http.Request, _ map[string]any) (int, any) {
		return 200, page(filter(f.exps, "env", r.PathValue("key")))
	})
	h("POST /api/v1/environments/{key}/experiments/", func(r *http.Request, b map[string]any) (int, any) {
		if b["experiment_rollout"] == nil {
			return 400, map[string]string{"experiment_rollout": "required"}
		}
		e := map[string]any{"id": f.id(), "env": r.PathValue("key"), "status": "created", "feature": map[string]any{"id": b["feature"]}}
		f.exps = append(f.exps, e)
		return 201, map[string]any{"id": e["id"], "feature": b["feature"]}
	})
	h("POST /api/v1/environments/{key}/experiments/{id}/start/", func(r *http.Request, _ map[string]any) (int, any) {
		e := byID(f.exps, r.PathValue("id"))
		e["status"] = "running"
		return 200, e
	})
}
