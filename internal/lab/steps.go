package lab

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

const (
	orgKeyName    = "gatecrasher-lab"
	serverKeyName = "gatecrasher-lab"
	tagColour     = "#FF5C5C"
)

type apiNamed struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type apiEnv struct {
	ID                int    `json:"id"`
	Name              string `json:"name"`
	APIKey            string `json:"api_key"`
	AllowClientTraits bool   `json:"allow_client_traits"`
	HideSensitiveData bool   `json:"hide_sensitive_data"`
}

type apiKey struct {
	Key    string `json:"key"`
	Name   string `json:"name"`
	Active bool   `json:"active"`
}

type apiTag struct {
	ID    int    `json:"id"`
	Label string `json:"label"`
}

func (s *seeder) ensureAdmin(ctx context.Context) error {
	creds := map[string]string{"email": s.state.AdminEmail, "password": s.state.AdminPassword}
	tok, err := s.login(ctx, creds)
	if err == nil {
		s.token = tok
		return nil
	}
	signup := map[string]string{"email": s.state.AdminEmail, "password": s.state.AdminPassword,
		"re_password": s.state.AdminPassword, "first_name": "Lab", "last_name": "Admin"}
	if err := s.api.call(ctx, nil, "POST", "auth/users/", signup, nil); err != nil {
		return fmt.Errorf("cannot log in or sign up %s (a different lab owns this email: reset it with `docker compose -p gatecrasher-lab down -v` and delete lab/.state.json): %w", s.state.AdminEmail, err)
	}
	s.changed("created lab admin user %s", s.state.AdminEmail)
	if s.token, err = s.login(ctx, creds); err != nil {
		return err
	}
	return nil
}

func (s *seeder) login(ctx context.Context, creds map[string]string) (string, error) {
	var out struct {
		Key string `json:"key"`
	}
	if err := s.api.call(ctx, nil, "POST", "auth/login/", creds, &out); err != nil {
		return "", err
	}
	return out.Key, nil
}

func (s *seeder) ensureOrganisation(ctx context.Context) error {
	orgs, err := list[apiNamed](ctx, s.api, tokenAuth(s.token), "organisations/")
	if err != nil {
		return err
	}
	org, ok := findNamed(orgs, s.opts.data.Organisation)
	if !ok {
		if err := s.api.call(ctx, tokenAuth(s.token), "POST", "organisations/", map[string]string{"name": s.opts.data.Organisation}, &org); err != nil {
			return err
		}
		s.changed("created organisation %q", org.Name)
	}
	s.state.OrgID = org.ID
	if s.state.OrgAPIKey != "" {
		status, err := s.api.status(ctx, orgKeyAuth(s.state.OrgAPIKey), "GET", fmt.Sprintf("projects/?organisation=%d", org.ID), nil)
		if err != nil {
			return err
		}
		if status == 200 {
			s.admin = orgKeyAuth(s.state.OrgAPIKey)
			return nil
		}
	}
	var created struct {
		Key string `json:"key"`
	}
	body := map[string]any{"name": orgKeyName, "is_admin": true}
	if err := s.api.call(ctx, tokenAuth(s.token), "POST", fmt.Sprintf("organisations/%d/master-api-keys/", org.ID), body, &created); err != nil {
		return err
	}
	s.state.OrgAPIKey = created.Key
	s.state.registerSecrets()
	s.admin = orgKeyAuth(created.Key)
	s.changed("created organisation API key")
	return nil
}

func (s *seeder) ensureProject(ctx context.Context) error {
	projects, err := list[apiNamed](ctx, s.api, s.admin, fmt.Sprintf("projects/?organisation=%d", s.state.OrgID))
	if err != nil {
		return err
	}
	p, ok := findNamed(projects, s.opts.data.Project)
	if !ok {
		body := map[string]any{"name": s.opts.data.Project, "organisation": s.state.OrgID}
		if err := s.api.call(ctx, s.admin, "POST", "projects/", body, &p); err != nil {
			return err
		}
		s.changed("created project %q", p.Name)
	}
	s.state.ProjectID = p.ID
	return nil
}

func (s *seeder) ensureEnvironments(ctx context.Context) error {
	envs, err := list[apiEnv](ctx, s.api, s.admin, fmt.Sprintf("environments/?project=%d", s.state.ProjectID))
	if err != nil {
		return err
	}
	want := s.opts.data.EnvironmentSettings
	for _, name := range s.opts.data.Environments {
		env, ok := findEnv(envs, name)
		if !ok {
			body := map[string]any{"name": name, "project": s.state.ProjectID}
			if err := s.api.call(ctx, s.admin, "POST", "environments/", body, &env); err != nil {
				return err
			}
			s.changed("created environment %q", name)
		}
		if env.AllowClientTraits != want.AllowClientTraits || env.HideSensitiveData != want.HideSensitiveData {
			patch := map[string]bool{"allow_client_traits": want.AllowClientTraits, "hide_sensitive_data": want.HideSensitiveData}
			if err := s.api.call(ctx, s.admin, "PATCH", "environments/"+env.APIKey+"/", patch, nil); err != nil {
				return err
			}
			s.changed("%s: allow_client_traits=%t hide_sensitive_data=%t", name, want.AllowClientTraits, want.HideSensitiveData)
		}
		server, err := s.ensureServerKey(ctx, name, env.APIKey)
		if err != nil {
			return err
		}
		s.state.Environments[name] = EnvState{ID: env.ID, ClientKey: env.APIKey, ServerKey: server}
	}
	return nil
}

func (s *seeder) ensureServerKey(ctx context.Context, envName, envKey string) (string, error) {
	keys, err := list[apiKey](ctx, s.api, s.admin, "environments/"+envKey+"/api-keys/")
	if err != nil {
		return "", err
	}
	for _, k := range keys {
		if k.Name == serverKeyName && k.Active {
			return k.Key, nil
		}
	}
	var k apiKey
	if err := s.api.call(ctx, s.admin, "POST", "environments/"+envKey+"/api-keys/", map[string]string{"name": serverKeyName}, &k); err != nil {
		return "", err
	}
	s.changed("created server-side key for environment %s", envName)
	return k.Key, nil
}

func (s *seeder) ensureTags(ctx context.Context) error {
	path := fmt.Sprintf("projects/%d/tags/", s.state.ProjectID)
	tags, err := list[apiTag](ctx, s.api, s.admin, path)
	if err != nil {
		return err
	}
	for _, t := range tags {
		s.tagIDs[t.Label] = t.ID
	}
	for _, label := range s.opts.data.Tags {
		if _, ok := s.tagIDs[label]; ok {
			continue
		}
		var t apiTag
		body := map[string]any{"label": label, "color": tagColour, "project": s.state.ProjectID}
		if err := s.api.call(ctx, s.admin, "POST", path, body, &t); err != nil {
			return err
		}
		s.tagIDs[label] = t.ID
		s.changed("created tag %q", label)
	}
	return nil
}

type apiCondition struct {
	Property string `json:"property"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

type apiRule struct {
	Type       string         `json:"type"`
	Rules      []apiRule      `json:"rules"`
	Conditions []apiCondition `json:"conditions"`
}

type apiSegment struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	Rules     []apiRule `json:"rules"`
	Feature   *int      `json:"feature"`
	ManagedBy any       `json:"managed_by"`
}

// segmentRules builds the canonical ALL -> ANY -> conditions rule tree.
func segmentRules(conds []ConditionData) []apiRule {
	cs := make([]apiCondition, len(conds))
	for i, c := range conds {
		cs[i] = apiCondition(c)
	}
	return []apiRule{{Type: "ALL", Conditions: []apiCondition{}, Rules: []apiRule{{Type: "ANY", Conditions: cs, Rules: []apiRule{}}}}}
}

// ruleSig is an order-sensitive signature of a rule tree used to detect drift.
func ruleSig(rules []apiRule) string {
	var b strings.Builder
	for _, r := range rules {
		fmt.Fprintf(&b, "%s(", r.Type)
		for _, c := range r.Conditions {
			fmt.Fprintf(&b, "[%s %s %s]", c.Property, c.Operator, c.Value)
		}
		b.WriteString(ruleSig(r.Rules))
		b.WriteString(")")
	}
	return b.String()
}

func (s *seeder) ensureSegments(ctx context.Context) error {
	path := fmt.Sprintf("projects/%d/segments/", s.state.ProjectID)
	have, err := list[apiSegment](ctx, s.api, s.admin, path)
	if err != nil {
		return err
	}
	for _, want := range s.opts.data.Segments {
		rules := segmentRules(want.Conditions)
		body := map[string]any{"name": want.Name, "project": s.state.ProjectID, "rules": rules}
		var cur *apiSegment
		for i := range have {
			if have[i].Name == want.Name {
				cur = &have[i]
			}
		}
		switch {
		case cur == nil:
			var created apiSegment
			if err := s.api.call(ctx, s.admin, "POST", path, body, &created); err != nil {
				return err
			}
			s.segmentIDs[want.Name] = created.ID
			s.changed("created segment %q", want.Name)
		case ruleSig(cur.Rules) != ruleSig(rules):
			if err := s.api.call(ctx, s.admin, "PUT", fmt.Sprintf("%s%d/", path, cur.ID), body, nil); err != nil {
				return err
			}
			s.segmentIDs[want.Name] = cur.ID
			s.changed("restored rules of segment %q", want.Name)
		default:
			s.segmentIDs[want.Name] = cur.ID
		}
	}
	return s.removeUndeclaredSegments(ctx, path, have)
}

// removeUndeclaredSegments deletes lab-project segments that are not in
// seed_data.yaml (for example ones added while recording the watch-mode
// demo), so a reset restores exactly the declared state. Feature-specific
// and system-managed (experiment) segments are never touched.
func (s *seeder) removeUndeclaredSegments(ctx context.Context, path string, have []apiSegment) error {
	declared := map[string]bool{}
	for _, d := range s.opts.data.Segments {
		declared[d.Name] = true
	}
	for _, seg := range have {
		if declared[seg.Name] || seg.Feature != nil || (seg.ManagedBy != nil && seg.ManagedBy != "") {
			continue
		}
		if err := s.api.call(ctx, s.admin, "DELETE", fmt.Sprintf("%s%d/", path, seg.ID), nil, nil); err != nil {
			return err
		}
		s.changed("removed undeclared segment %q", seg.Name)
	}
	return nil
}

type apiMVOption struct {
	ID          int    `json:"id"`
	StringValue string `json:"string_value"`
}

type apiFeature struct {
	ID              int           `json:"id"`
	Name            string        `json:"name"`
	Description     *string       `json:"description"`
	Tags            []int         `json:"tags"`
	IsServerKeyOnly bool          `json:"is_server_key_only"`
	MVOptions       []apiMVOption `json:"multivariate_options"`
}

func (s *seeder) ensureFeatures(ctx context.Context) error {
	path := fmt.Sprintf("projects/%d/features/", s.state.ProjectID)
	have, err := list[apiFeature](ctx, s.api, s.admin, path+"?page_size=100")
	if err != nil {
		return err
	}
	s.features = map[string]apiFeature{}
	for _, want := range s.opts.data.Features {
		var cur *apiFeature
		for i := range have {
			if have[i].Name == want.Name {
				cur = &have[i]
			}
		}
		if cur == nil {
			var created apiFeature
			if err := s.api.call(ctx, s.admin, "POST", path, s.featureBody(want), &created); err != nil {
				return err
			}
			s.features[want.Name] = created
			s.changed("created feature %q", want.Name)
			continue
		}
		s.features[want.Name] = *cur
		patch := s.featureDrift(want, *cur)
		if patch == nil {
			continue
		}
		if err := s.api.call(ctx, s.admin, "PATCH", fmt.Sprintf("%s%d/", path, cur.ID), patch, nil); err != nil {
			return err
		}
		s.changed("restored feature %q (server-side only off, tags, description)", want.Name)
	}
	return nil
}

func (s *seeder) tagIDsFor(labels []string) []int {
	ids := make([]int, 0, len(labels))
	for _, l := range labels {
		ids = append(ids, s.tagIDs[l])
	}
	sort.Ints(ids)
	return ids
}

func (s *seeder) featureBody(f FeatureData) map[string]any {
	body := map[string]any{
		"name": f.Name, "type": "STANDARD", "default_enabled": f.DefaultEnabled,
		"description": f.Description, "tags": s.tagIDsFor(f.Tags), "is_server_key_only": false,
	}
	if f.Value != "" {
		body["initial_value"] = RenderValue(f.Value, s.state.PaymentSecret)
	}
	if f.Multivariate {
		body["type"] = "MULTIVARIATE"
		opts := make([]map[string]any, len(f.Variants))
		for i, v := range f.Variants {
			opts[i] = map[string]any{"type": "unicode", "string_value": v.Value, "default_percentage_allocation": v.Percentage}
		}
		body["multivariate_options"] = opts
	}
	return body
}

// featureDrift returns the PATCH body that undoes drift, or nil if none.
func (s *seeder) featureDrift(want FeatureData, cur apiFeature) map[string]any {
	patch := map[string]any{}
	if cur.IsServerKeyOnly {
		patch["is_server_key_only"] = false
	}
	wantTags := s.tagIDsFor(want.Tags)
	haveTags := append([]int{}, cur.Tags...)
	sort.Ints(haveTags)
	if fmt.Sprint(wantTags) != fmt.Sprint(haveTags) {
		patch["tags"] = wantTags
	}
	if cur.Description == nil || *cur.Description != want.Description {
		patch["description"] = want.Description
	}
	if len(patch) == 0 {
		return nil
	}
	return patch
}

type apiTrait struct {
	Key   string `json:"trait_key"`
	Value any    `json:"trait_value"`
}

func (s *seeder) ensureIdentities(ctx context.Context) error {
	for _, name := range s.opts.data.Environments {
		env := s.state.Environments[name]
		for _, id := range s.opts.data.Identities {
			if err := s.ensureIdentity(ctx, name, env, id); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *seeder) ensureIdentity(ctx context.Context, envName string, env EnvState, id IdentityData) error {
	h := clientKeyAuth(env.ClientKey)
	var cur struct {
		Traits []apiTrait `json:"traits"`
	}
	if err := s.api.call(ctx, h, "GET", "identities/?identifier="+url.QueryEscape(id.Identifier), nil, &cur); err != nil {
		return err
	}
	have := map[string]string{}
	for _, t := range cur.Traits {
		have[t.Key] = fmt.Sprint(t.Value)
	}
	keys := make([]string, 0, len(id.Traits))
	for k := range id.Traits {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	traits := make([]apiTrait, 0, len(keys))
	drift := false
	for _, k := range keys {
		traits = append(traits, apiTrait{Key: k, Value: id.Traits[k]})
		drift = drift || have[k] != fmt.Sprint(id.Traits[k])
	}
	if !drift {
		return nil
	}
	body := map[string]any{"identifier": id.Identifier, "traits": traits}
	if err := s.api.call(ctx, h, "POST", "identities/", body, nil); err != nil {
		return err
	}
	s.changed("%s: persisted identity %s with traits", envName, id.Identifier)
	return nil
}

func findNamed(items []apiNamed, name string) (apiNamed, bool) {
	for _, it := range items {
		if it.Name == name {
			return it, true
		}
	}
	return apiNamed{}, false
}

func findEnv(items []apiEnv, name string) (apiEnv, bool) {
	for _, it := range items {
		if it.Name == name {
			return it, true
		}
	}
	return apiEnv{}, false
}
