package lab

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

type apiMVState struct {
	Option     int     `json:"multivariate_feature_option"`
	Percentage float64 `json:"percentage_allocation"`
}

type apiState struct {
	ID             int             `json:"id"`
	Enabled        bool            `json:"enabled"`
	Value          any             `json:"feature_state_value"`
	Feature        int             `json:"feature"`
	FeatureSegment json.RawMessage `json:"feature_segment"`
	Identity       json.RawMessage `json:"identity"`
	MV             []apiMVState    `json:"multivariate_feature_state_values"`
}

// hasIdentity reports whether the state is an identity override.
func (st apiState) hasIdentity() bool {
	return len(st.Identity) > 0 && string(st.Identity) != "null"
}

// segmentLink returns the feature-segment id this state belongs to, or 0 for
// a base (environment-wide) state. The API returns either an id or an object.
func (st apiState) segmentLink() int {
	var id int
	if json.Unmarshal(st.FeatureSegment, &id) == nil {
		return id
	}
	var obj struct {
		ID int `json:"id"`
	}
	if json.Unmarshal(st.FeatureSegment, &obj) == nil {
		return obj.ID
	}
	return 0
}

// valueString renders a feature-state value the way seed data declares it.
func valueString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		return fmt.Sprintf("%g", t)
	default:
		return fmt.Sprint(t)
	}
}

type apiFeatureSegment struct {
	ID      int `json:"id"`
	Segment int `json:"segment"`
}

type apiIdentity struct {
	ID         int    `json:"id"`
	Identifier string `json:"identifier"`
}

type apiExperiment struct {
	ID      int    `json:"id"`
	Status  string `json:"status"`
	Feature struct {
		ID int `json:"id"`
	} `json:"feature"`
}

func (s *seeder) ensureEnvironmentState(ctx context.Context) error {
	for _, envName := range s.opts.data.Environments {
		env := s.state.Environments[envName]
		for _, f := range s.opts.data.Features {
			if err := s.ensureFeatureInEnv(ctx, envName, env, f); err != nil {
				return fmt.Errorf("%s/%s: %w", envName, f.Name, err)
			}
		}
	}
	return nil
}

func (s *seeder) ensureFeatureInEnv(ctx context.Context, envName string, env EnvState, f FeatureData) error {
	feat := s.features[f.Name]
	states, err := list[apiState](ctx, s.api, s.admin, fmt.Sprintf("environments/%s/featurestates/?feature=%d&page_size=100", env.ClientKey, feat.ID))
	if err != nil {
		return err
	}
	running, err := s.runningExperiment(ctx, env, feat.ID)
	if err != nil {
		return err
	}
	if !running {
		if err := s.ensureBaseState(ctx, envName, env, f, feat, states); err != nil {
			return err
		}
	}
	for _, o := range f.SegmentOverrides {
		if err := s.ensureSegmentOverride(ctx, envName, env, f, feat, o, states); err != nil {
			return err
		}
	}
	for _, o := range f.IdentityOverrides {
		if err := s.ensureIdentityOverride(ctx, envName, env, f, feat, o); err != nil {
			return err
		}
	}
	if f.Experiment != nil {
		return s.ensureExperiment(ctx, envName, env, f, feat)
	}
	return nil
}

func (s *seeder) ensureBaseState(ctx context.Context, envName string, env EnvState, f FeatureData, feat apiFeature, states []apiState) error {
	var base *apiState
	for i := range states {
		if !states[i].hasIdentity() && states[i].segmentLink() == 0 {
			base = &states[i]
		}
	}
	if base == nil {
		return fmt.Errorf("no environment state found for feature %s", f.Name)
	}
	patch := map[string]any{}
	if base.Enabled != f.DefaultEnabled {
		patch["enabled"] = f.DefaultEnabled
	}
	if want := RenderValue(f.Value, s.state.PaymentSecret); valueString(base.Value) != want {
		patch["feature_state_value"] = want
	}
	if f.Multivariate {
		if mv := s.variantDrift(f, feat, *base); mv != nil {
			patch["multivariate_feature_state_values"] = mv
		}
	}
	if len(patch) == 0 {
		return nil
	}
	path := fmt.Sprintf("environments/%s/featurestates/%d/", env.ClientKey, base.ID)
	if err := s.api.call(ctx, s.admin, "PATCH", path, patch, nil); err != nil {
		return err
	}
	s.changed("%s: restored %s value/enabled", envName, f.Name)
	return nil
}

// variantDrift returns the multivariate allocation body when it differs.
func (s *seeder) variantDrift(f FeatureData, feat apiFeature, base apiState) []apiMVState {
	want := make([]apiMVState, 0, len(f.Variants))
	for _, v := range f.Variants {
		for _, o := range feat.MVOptions {
			if o.StringValue == v.Value {
				want = append(want, apiMVState{Option: o.ID, Percentage: v.Percentage})
			}
		}
	}
	have := map[int]float64{}
	for _, m := range base.MV {
		have[m.Option] = m.Percentage
	}
	for _, w := range want {
		if p, ok := have[w.Option]; !ok || p != w.Percentage {
			return want
		}
	}
	return nil
}

func (s *seeder) ensureSegmentOverride(ctx context.Context, envName string, env EnvState, f FeatureData, feat apiFeature, o SegmentOverrideData, states []apiState) error {
	segID := s.segmentIDs[o.Segment]
	links, err := list[apiFeatureSegment](ctx, s.api, s.admin, fmt.Sprintf("features/feature-segments/?environment=%d&feature=%d", env.ID, feat.ID))
	if err != nil {
		return err
	}
	linkID := 0
	for _, l := range links {
		if l.Segment == segID {
			linkID = l.ID
		}
	}
	if linkID == 0 {
		body := map[string]any{
			"feature_segment":     map[string]int{"segment": segID},
			"enabled":             o.Enabled,
			"feature_state_value": map[string]any{"type": "unicode", "string_value": nil},
		}
		path := fmt.Sprintf("environments/%s/features/%d/create-segment-override/", env.ClientKey, feat.ID)
		if err := s.api.call(ctx, s.admin, "POST", path, body, nil); err != nil {
			return err
		}
		s.changed("%s: %s targets segment %q", envName, f.Name, o.Segment)
		return nil
	}
	for _, st := range states {
		if st.segmentLink() == linkID && st.Enabled != o.Enabled {
			path := fmt.Sprintf("environments/%s/featurestates/%d/", env.ClientKey, st.ID)
			if err := s.api.call(ctx, s.admin, "PATCH", path, map[string]bool{"enabled": o.Enabled}, nil); err != nil {
				return err
			}
			s.changed("%s: restored %s override for segment %q", envName, f.Name, o.Segment)
		}
	}
	return nil
}

func (s *seeder) ensureIdentityOverride(ctx context.Context, envName string, env EnvState, f FeatureData, feat apiFeature, o IdentityOverrideData) error {
	idents, err := list[apiIdentity](ctx, s.api, s.admin, fmt.Sprintf("environments/%s/identities/?q=%s", env.ClientKey, url.QueryEscape(o.Identifier)))
	if err != nil {
		return err
	}
	iid := 0
	for _, i := range idents {
		if i.Identifier == o.Identifier {
			iid = i.ID
		}
	}
	if iid == 0 {
		return fmt.Errorf("identity %s was not persisted", o.Identifier)
	}
	base := fmt.Sprintf("environments/%s/identities/%d/featurestates/", env.ClientKey, iid)
	states, err := list[apiState](ctx, s.api, s.admin, base)
	if err != nil {
		return err
	}
	for _, st := range states {
		if st.Feature != feat.ID {
			continue
		}
		if st.Enabled != o.Enabled {
			if err := s.api.call(ctx, s.admin, "PATCH", fmt.Sprintf("%s%d/", base, st.ID), map[string]bool{"enabled": o.Enabled}, nil); err != nil {
				return err
			}
			s.changed("%s: restored %s override for %s", envName, f.Name, o.Identifier)
		}
		return nil
	}
	body := map[string]any{"feature": feat.ID, "enabled": o.Enabled, "environment": env.ID, "identity": iid}
	if err := s.api.call(ctx, s.admin, "POST", base, body, nil); err != nil {
		return err
	}
	s.changed("%s: %s overridden for identity %s", envName, f.Name, o.Identifier)
	return nil
}

// runningExperiment reports whether an experiment currently runs on a feature.
func (s *seeder) runningExperiment(ctx context.Context, env EnvState, featureID int) (bool, error) {
	exps, err := list[apiExperiment](ctx, s.api, s.admin, "environments/"+env.ClientKey+"/experiments/")
	if err != nil {
		return false, err
	}
	for _, e := range exps {
		if e.Feature.ID == featureID && e.Status == "running" {
			return true, nil
		}
	}
	return false, nil
}

// ensureExperiment makes sure a Flagsmith Experimentation experiment exists
// and is running on the multivariate feature. Experiments are per environment.
func (s *seeder) ensureExperiment(ctx context.Context, envName string, env EnvState, f FeatureData, feat apiFeature) error {
	base := "environments/" + env.ClientKey + "/experiments/"
	exps, err := list[apiExperiment](ctx, s.api, s.admin, base)
	if err != nil {
		return err
	}
	for _, e := range exps {
		if e.Feature.ID != feat.ID || e.Status == "completed" {
			continue
		}
		if e.Status == "running" {
			return nil
		}
		return s.startExperiment(ctx, envName, env, e.ID)
	}
	values := make([]map[string]any, 0, len(f.Variants))
	for _, v := range f.Variants {
		for _, o := range feat.MVOptions {
			if o.StringValue == v.Value {
				values = append(values, map[string]any{"multivariate_feature_option": o.ID, "percentage_allocation": v.Percentage})
			}
		}
	}
	body := map[string]any{
		"feature": feat.ID, "name": f.Experiment.Name, "hypothesis": f.Experiment.Hypothesis,
		"experiment_rollout": map[string]any{
			"enabled": true, "rollout_percentage": 100,
			"feature_state_value":               map[string]string{"type": "string", "value": f.Value},
			"multivariate_feature_state_values": values,
		},
	}
	var created struct {
		ID int `json:"id"`
	}
	if err := s.api.call(ctx, s.admin, "POST", base, body, &created); err != nil {
		return err
	}
	s.changed("%s: created experiment %q on %s", envName, f.Experiment.Name, f.Name)
	return s.startExperiment(ctx, envName, env, created.ID)
}

func (s *seeder) startExperiment(ctx context.Context, envName string, env EnvState, id int) error {
	path := fmt.Sprintf("environments/%s/experiments/%d/start/", env.ClientKey, id)
	if err := s.api.call(ctx, s.admin, "POST", path, map[string]any{}, nil); err != nil {
		return err
	}
	s.changed("%s: started experiment %d", envName, id)
	return nil
}
