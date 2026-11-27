package flagsmith

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/yarrasatwik/gatecrasher/internal/httpx"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

// Admin is a client for the Flagsmith Admin API using an organisation API
// key ("Authorization: Api-Key <key>", verified on 2.295.2).
type Admin struct {
	http *httpx.Client
	api  string
	key  string
}

// NewAdmin builds an Admin client. The key is registered for redaction.
func NewAdmin(c *httpx.Client, apiURL, orgAPIKey string) *Admin {
	redact.Register(orgAPIKey, "ORG_API_KEY")
	return &Admin{http: c, api: apiURL, key: orgAPIKey}
}

// ErrNoAdminKey is returned when an inside-view call has no key.
var ErrNoAdminKey = errors.New("no organisation API key: set GATECRASHER_ORG_API_KEY for the inside view")

// APIURL returns the API base URL.
func (a *Admin) APIURL() string { return a.api }

// Do performs an Admin API call relative to the API base and decodes out.
func (a *Admin) Do(ctx context.Context, method, path string, body, out any) error {
	if a == nil || a.key == "" {
		return ErrNoAdminKey
	}
	u := path
	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		u = httpx.JoinURL(a.api, path)
	}
	_, err := a.http.JSON(ctx, httpx.Request{Method: method, URL: u, Body: body,
		Header: map[string]string{"Authorization": "Api-Key " + a.key}}, out)
	return err
}

// Get is Do with GET.
func (a *Admin) Get(ctx context.Context, path string, out any) error {
	return a.Do(ctx, "GET", path, nil, out)
}

// list fetches a list endpoint that may be paginated ({results,next}) or a
// bare array, following "next" links.
func list[T any](ctx context.Context, a *Admin, path string) ([]T, error) {
	var all []T
	next := path
	for page := 0; next != "" && page < 100; page++ {
		var raw json.RawMessage
		if err := a.Get(ctx, next, &raw); err != nil {
			return nil, err
		}
		trimmed := strings.TrimSpace(string(raw))
		if strings.HasPrefix(trimmed, "[") {
			var items []T
			if err := json.Unmarshal(raw, &items); err != nil {
				return nil, err
			}
			return append(all, items...), nil
		}
		var pg struct {
			Results []T     `json:"results"`
			Next    *string `json:"next"`
		}
		if err := json.Unmarshal(raw, &pg); err != nil {
			return nil, err
		}
		all = append(all, pg.Results...)
		next = ""
		if pg.Next != nil && *pg.Next != "" {
			next = *pg.Next
		}
	}
	return all, nil
}

// Organisation is an organisation.
type Organisation struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// Project is a project.
type Project struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	Organisation int    `json:"organisation"`
}

// Environment carries the security-relevant environment settings.
type Environment struct {
	ID                       int    `json:"id"`
	Name                     string `json:"name"`
	APIKey                   string `json:"api_key"`
	Project                  int    `json:"project"`
	AllowClientTraits        bool   `json:"allow_client_traits"`
	HideSensitiveData        bool   `json:"hide_sensitive_data"`
	HideDisabledFlags        bool   `json:"hide_disabled_flags"`
	UseV2FeatureVersioning   bool   `json:"use_v2_feature_versioning"`
	UseIdentityCompositeKey  bool   `json:"use_identity_composite_key_for_hashing"`
}

// MVOption is a multivariate option.
type MVOption struct {
	ID                   int     `json:"id"`
	Type                 string  `json:"type"`
	StringValue          *string `json:"string_value"`
	IntegerValue         *int    `json:"integer_value"`
	BooleanValue         *bool   `json:"boolean_value"`
	DefaultPercentage    float64 `json:"default_percentage_allocation"`
}

// Feature is a project feature.
type Feature struct {
	ID                  int        `json:"id"`
	Name                string     `json:"name"`
	Type                string     `json:"type"`
	DefaultEnabled      bool       `json:"default_enabled"`
	InitialValue        any        `json:"initial_value"`
	Description         *string    `json:"description"`
	Tags                []int      `json:"tags"`
	IsServerKeyOnly     bool       `json:"is_server_key_only"`
	IsArchived          bool       `json:"is_archived"`
	MultivariateOptions []MVOption `json:"multivariate_options"`
	NumSegmentOverrides *int       `json:"num_segment_overrides"`
	NumIdentityOverrides *int      `json:"num_identity_overrides"`
}

// Tag is a project tag.
type Tag struct {
	ID    int    `json:"id"`
	Label string `json:"label"`
}

// Condition is a segment rule condition.
type Condition struct {
	ID       *int   `json:"id,omitempty"`
	Property string `json:"property"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

// Rule is a (possibly nested) segment rule. Type is ALL, ANY or NONE.
type Rule struct {
	ID         *int        `json:"id,omitempty"`
	Type       string      `json:"type"`
	Rules      []Rule      `json:"rules"`
	Conditions []Condition `json:"conditions"`
}

// Segment is a project segment.
type Segment struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Project int    `json:"project"`
	Feature *int   `json:"feature"`
	Rules   []Rule `json:"rules"`
}

// FeatureState is an environment/segment/identity feature state.
type FeatureState struct {
	ID             int  `json:"id"`
	Feature        int  `json:"feature"`
	Enabled        bool `json:"enabled"`
	Environment    *int `json:"environment"`
	Identity       *int `json:"identity"`
	FeatureSegment *int `json:"feature_segment"`
	Value          any  `json:"feature_state_value"`
}

// Experiment is a Flagsmith Experimentation experiment.
type Experiment struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Feature any    `json:"feature"`
}

// FeatureID extracts the experiment's feature id (int or {id}).
func (e Experiment) FeatureID() int {
	switch f := e.Feature.(type) {
	case float64:
		return int(f)
	case map[string]any:
		if id, ok := f["id"].(float64); ok {
			return int(id)
		}
	}
	return 0
}

// Running reports whether the experiment is live.
func (e Experiment) Running() bool {
	s := strings.ToUpper(e.Status)
	return s == "RUNNING" || s == "STARTED" || s == "ACTIVE" || s == "IN_PROGRESS"
}

// Organisations lists organisations.
func (a *Admin) Organisations(ctx context.Context) ([]Organisation, error) {
	return list[Organisation](ctx, a, "organisations/")
}

// Projects lists projects.
func (a *Admin) Projects(ctx context.Context) ([]Project, error) {
	return list[Project](ctx, a, "projects/")
}

// ProjectByName finds a project by exact name (or the only project if name is empty).
func (a *Admin) ProjectByName(ctx context.Context, name string) (*Project, error) {
	ps, err := a.Projects(ctx)
	if err != nil {
		return nil, err
	}
	if name == "" && len(ps) == 1 {
		return &ps[0], nil
	}
	for i := range ps {
		if ps[i].Name == name {
			return &ps[i], nil
		}
	}
	return nil, fmt.Errorf("project %q not found (have %d projects)", name, len(ps))
}

// Environments lists environments in a project.
func (a *Admin) Environments(ctx context.Context, projectID int) ([]Environment, error) {
	return list[Environment](ctx, a, fmt.Sprintf("environments/?project=%d", projectID))
}

// EnvironmentByName finds an environment by name in a project.
func (a *Admin) EnvironmentByName(ctx context.Context, projectID int, name string) (*Environment, error) {
	es, err := a.Environments(ctx, projectID)
	if err != nil {
		return nil, err
	}
	for i := range es {
		if strings.EqualFold(es[i].Name, name) {
			redact.Register(es[i].APIKey, "CLIENT_KEY")
			return &es[i], nil
		}
	}
	return nil, fmt.Errorf("environment %q not found", name)
}

// Environment fetches one environment by API key.
func (a *Admin) Environment(ctx context.Context, apiKey string) (*Environment, error) {
	var e Environment
	if err := a.Get(ctx, "environments/"+url.PathEscape(apiKey)+"/", &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// Features lists features in a project.
func (a *Admin) Features(ctx context.Context, projectID int) ([]Feature, error) {
	return list[Feature](ctx, a, fmt.Sprintf("projects/%d/features/?page_size=999", projectID))
}

// Tags lists tags in a project.
func (a *Admin) Tags(ctx context.Context, projectID int) ([]Tag, error) {
	return list[Tag](ctx, a, fmt.Sprintf("projects/%d/tags/", projectID))
}

// Segments lists segments (with rules) in a project.
func (a *Admin) Segments(ctx context.Context, projectID int) ([]Segment, error) {
	return list[Segment](ctx, a, fmt.Sprintf("projects/%d/segments/?page_size=999", projectID))
}

// FeatureStates lists the environment's feature states.
func (a *Admin) FeatureStates(ctx context.Context, envKey string) ([]FeatureState, error) {
	return list[FeatureState](ctx, a, "environments/"+url.PathEscape(envKey)+"/featurestates/?page_size=999")
}

// Experiments lists Experimentation experiments; returns (nil, err) when the
// endpoint is unavailable so callers can report "experiment status unknown".
func (a *Admin) Experiments(ctx context.Context, envKey string) ([]Experiment, error) {
	return list[Experiment](ctx, a, "environments/"+url.PathEscape(envKey)+"/experiments/")
}

// EnvironmentDocument fetches the environment document with the admin key
// (GET environments/{key}/document/, verified equal to the ser.-key
// environment-document/ payload).
func (a *Admin) EnvironmentDocument(ctx context.Context, envKey string) (json.RawMessage, error) {
	var raw json.RawMessage
	if err := a.Get(ctx, "environments/"+url.PathEscape(envKey)+"/document/", &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// EnvironmentDocumentServerKey fetches the document with a server-side key.
func EnvironmentDocumentServerKey(ctx context.Context, c *httpx.Client, apiURL, serverKey string) (json.RawMessage, error) {
	redact.Register(serverKey, "SERVER_KEY")
	var raw json.RawMessage
	_, err := c.JSON(ctx, httpx.Request{URL: httpx.JoinURL(apiURL, "environment-document/"),
		Header: map[string]string{"X-Environment-Key": serverKey}}, &raw)
	return raw, err
}
