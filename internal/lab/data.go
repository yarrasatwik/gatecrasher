// Package lab builds and resets the deliberately vulnerable "Acme Shop"
// Flagsmith lab (spec section 7). It talks to a running self-hosted Flagsmith
// through the public REST API only, and is safe to run repeatedly.
package lab

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// SecretPlaceholder is replaced in feature values by the generated fake secret.
const SecretPlaceholder = "{{payment_secret}}"

// Data is the declared lab state loaded from lab/seed_data.yaml.
type Data struct {
	Organisation        string              `yaml:"organisation"`
	Project             string              `yaml:"project"`
	AdminEmail          string              `yaml:"admin_email"`
	Environments        []string            `yaml:"environments"`
	EnvironmentSettings EnvironmentSettings `yaml:"environment_settings"`
	Tags                []string            `yaml:"tags"`
	Segments            []SegmentData       `yaml:"segments"`
	Identities          []IdentityData      `yaml:"identities"`
	Features            []FeatureData       `yaml:"features"`
}

// EnvironmentSettings are the two security-relevant environment switches.
type EnvironmentSettings struct {
	AllowClientTraits bool `yaml:"allow_client_traits"`
	HideSensitiveData bool `yaml:"hide_sensitive_data"`
}

// SegmentData is a segment made of one ANY group of conditions.
type SegmentData struct {
	Name       string          `yaml:"name"`
	Conditions []ConditionData `yaml:"conditions"`
}

// ConditionData is one segment condition.
type ConditionData struct {
	Property string `yaml:"property"`
	Operator string `yaml:"operator"`
	Value    string `yaml:"value"`
}

// IdentityData is an identity persisted with fake traits.
type IdentityData struct {
	Identifier string         `yaml:"identifier"`
	Traits     map[string]any `yaml:"traits"`
}

// VariantData is one multivariate option.
type VariantData struct {
	Value      string  `yaml:"value"`
	Percentage float64 `yaml:"percentage"`
}

// ExperimentData describes a Flagsmith Experimentation experiment.
type ExperimentData struct {
	Name       string `yaml:"name"`
	Hypothesis string `yaml:"hypothesis"`
}

// SegmentOverrideData turns a feature on or off for a segment.
type SegmentOverrideData struct {
	Segment string `yaml:"segment"`
	Enabled bool   `yaml:"enabled"`
}

// IdentityOverrideData turns a feature on or off for one identity.
type IdentityOverrideData struct {
	Identifier string `yaml:"identifier"`
	Enabled    bool   `yaml:"enabled"`
}

// FeatureData is one declared feature and its targeting.
type FeatureData struct {
	Name              string                 `yaml:"name"`
	Description       string                 `yaml:"description"`
	Multivariate      bool                   `yaml:"multivariate"`
	DefaultEnabled    bool                   `yaml:"default_enabled"`
	Value             string                 `yaml:"value"`
	Tags              []string               `yaml:"tags"`
	Variants          []VariantData          `yaml:"variants"`
	Experiment        *ExperimentData        `yaml:"experiment"`
	SegmentOverrides  []SegmentOverrideData  `yaml:"segment_overrides"`
	IdentityOverrides []IdentityOverrideData `yaml:"identity_overrides"`
}

// LoadData reads and validates a seed_data.yaml file.
func LoadData(path string) (*Data, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read seed data: %w", err)
	}
	return ParseData(raw)
}

// ParseData parses and validates seed data from YAML bytes.
func ParseData(raw []byte) (*Data, error) {
	var d Data
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("parse seed data: %w", err)
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return &d, nil
}

// Validate checks that the declared state is internally consistent.
func (d *Data) Validate() error {
	var errs []error
	need := func(ok bool, format string, a ...any) {
		if !ok {
			errs = append(errs, fmt.Errorf(format, a...))
		}
	}
	need(d.Organisation != "", "organisation is required")
	need(d.Project != "", "project is required")
	need(strings.Contains(d.AdminEmail, "@"), "admin_email must be an email address")
	need(len(d.Environments) > 0, "at least one environment is required")
	segments := map[string]bool{}
	for _, s := range d.Segments {
		need(s.Name != "" && len(s.Conditions) > 0, "segment %q needs a name and conditions", s.Name)
		need(!segments[s.Name], "duplicate segment %q", s.Name)
		segments[s.Name] = true
		for _, c := range s.Conditions {
			need(c.Operator != "", "segment %q has a condition without an operator", s.Name)
		}
	}
	identities := map[string]bool{}
	for _, i := range d.Identities {
		need(i.Identifier != "", "identity without identifier")
		identities[i.Identifier] = true
	}
	tags := map[string]bool{}
	for _, t := range d.Tags {
		tags[t] = true
	}
	features := map[string]bool{}
	for _, f := range d.Features {
		errs = append(errs, validateFeature(f, segments, identities, tags, features)...)
	}
	return errors.Join(errs...)
}

func validateFeature(f FeatureData, segments, identities, tags, seen map[string]bool) []error {
	var errs []error
	add := func(format string, a ...any) {
		errs = append(errs, fmt.Errorf("feature %q: "+format, append([]any{f.Name}, a...)...))
	}
	if f.Name == "" || f.Name != strings.ToLower(f.Name) {
		add("name must be non-empty and lower case")
	}
	if seen[f.Name] {
		add("declared twice")
	}
	seen[f.Name] = true
	for _, o := range f.SegmentOverrides {
		if !segments[o.Segment] {
			add("segment override references unknown segment %q", o.Segment)
		}
	}
	for _, o := range f.IdentityOverrides {
		if !identities[o.Identifier] {
			add("identity override references unknown identity %q", o.Identifier)
		}
	}
	for _, t := range f.Tags {
		if !tags[t] {
			add("uses undeclared tag %q", t)
		}
	}
	validateVariants(f, add)
	return errs
}

func validateVariants(f FeatureData, add func(string, ...any)) {
	if f.Multivariate {
		total := 0.0
		for _, v := range f.Variants {
			total += v.Percentage
		}
		if len(f.Variants) < 2 || total != 100 {
			add("multivariate features need at least two variants summing to 100 percent")
		}
		found := false
		for _, v := range f.Variants {
			found = found || v.Value == f.Value
		}
		if !found {
			add("default value %q is not one of the variants", f.Value)
		}
	} else if len(f.Variants) > 0 || f.Experiment != nil {
		add("variants and experiments require multivariate: true")
	}
	if f.Experiment != nil && (f.Experiment.Name == "" || f.Experiment.Hypothesis == "") {
		add("experiment needs a name and a hypothesis")
	}
}

// RenderValue substitutes the generated secret into a declared value.
func RenderValue(value, secret string) string {
	return strings.ReplaceAll(value, SecretPlaceholder, secret)
}
