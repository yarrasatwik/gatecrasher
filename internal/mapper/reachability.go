package mapper

import (
	"fmt"
	"strings"

	"github.com/Flagsmith/flagsmith-go-client/v5/flagengine/features"

	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
	"github.com/yarrasatwik/gatecrasher/internal/model"
)

// Options tunes Map.
type Options struct {
	// Environment names the environment being mapped; it selects the matching
	// entry of the settings and labels results.
	Environment string
	// ServerOnlyTraits are traits only servers set; clients cannot forge them.
	ServerOnlyTraits []string
	// ClientSetsIdentifier says the client chooses its own identity identifier.
	ClientSetsIdentifier bool
	// MaxSearch bounds identifier searches (DefaultMaxSearch when <= 0).
	MaxSearch int
	// Classifications maps flag names to sensitivity, used to rank findings.
	Classifications map[string]model.Category
}

const defaultIdentifier = probePrefix + "0"

// Map computes every flag state an attacker can reach through a segment
// override (and every multivariate variant reachable by choosing an
// identifier) that differs from the environment default, with the smallest
// forged input found. Each result was produced by Flagsmith's own engine over
// the environment document, which also settles segment priorities.
// segments supplies rules from the Admin API; segments missing from it use the
// rules embedded in the document. Archived features in features are skipped.
func Map(eng *flagsmith.Engine, segments []flagsmith.Segment, features []flagsmith.Feature, settings []model.EnvSettings, opts Options) []model.Reachable {
	m := &mapping{eng: eng, opts: opts, settings: settingsFor(settings, opts.Environment), archived: map[string]bool{}, defaults: map[string]flagsmith.Flag{}}
	for _, f := range features {
		if f.IsArchived {
			m.archived[f.Name] = true
		}
	}
	for _, fs := range eng.Doc.FeatureStates {
		m.defaults[fs.Feature.Name] = stateOf(fs, nil)
	}
	admin := map[int]Segment{}
	for _, s := range FromAdmin(segments) {
		admin[s.ID] = s
	}
	if eng.Doc.Project != nil {
		for _, ds := range fromDocumentWithStates(eng.Doc.Project.Segments) {
			if a, ok := admin[ds.seg.ID]; ok {
				ds.seg.Rules = a.Rules
			}
			m.segment(ds)
		}
	}
	m.environmentVariants()
	return m.out
}

type mapping struct {
	eng      *flagsmith.Engine
	opts     Options
	settings *model.EnvSettings
	archived map[string]bool
	defaults map[string]flagsmith.Flag
	out      []model.Reachable
}

type docSegment struct {
	seg    Segment
	states []*features.FeatureStateModel
}

func settingsFor(all []model.EnvSettings, env string) *model.EnvSettings {
	for i := range all {
		if strings.EqualFold(all[i].Environment, env) {
			return &all[i]
		}
	}
	if len(all) == 1 {
		return &all[0]
	}
	return nil
}

// stateOf renders a feature state as a comparable flag. With multivariate
// values, variant picks one option (nil means the control value).
func stateOf(fs *features.FeatureStateModel, variant *features.MultivariateFeatureStateValueModel) flagsmith.Flag {
	v := fs.RawValue
	if variant != nil {
		v = variant.MultivariateFeatureOption.Value
	}
	return flagsmith.Flag{Name: fs.Feature.Name, Enabled: fs.Enabled, Value: v}
}

// segment maps every override of one segment.
func (m *mapping) segment(ds docSegment) {
	cands := Solve(ds.seg, m.eng.Doc.APIKey, m.opts.MaxSearch)
	for _, fs := range ds.states {
		if m.archived[fs.Feature.Name] || len(cands) == 0 {
			continue
		}
		if len(fs.MultivariateFeatureStateValues) > 0 {
			m.segmentVariants(ds.seg, fs, cands)
			continue
		}
		want := stateOf(fs, nil).State()
		if want == m.defaults[fs.Feature.Name].State() {
			continue
		}
		for _, c := range cands {
			flags := m.eng.Evaluate(identifierFor(c), c.Traits)
			if f, ok := flags[fs.Feature.Name]; ok && viaSegment(f, ds.seg.Name) && f.State() == want {
				m.add(ds.seg.Name, fs.Feature.Name, f, c)
				break
			}
		}
	}
}

// segmentVariants finds identifiers that reach each variant of a multivariate
// segment override, using the cheapest candidate that enters the segment.
// The engine labels a variant pick "SPLIT", not with the segment, so a state
// counts as served by the segment only when it is one of the override's
// variant states and not also one of the environment's own variant states.
func (m *mapping) segmentVariants(seg Segment, fs *features.FeatureStateModel, cands []Candidate) {
	wanted := m.wantedStates(fs)
	own := m.environmentStates(fs.Feature.Name)
	for _, c := range cands {
		entered := false
		for n := 0; n < m.searchLimit(c); n++ {
			id := searchIdentifier(c, n)
			f, ok := m.eng.Evaluate(id, c.Traits)[fs.Feature.Name]
			if !ok {
				continue
			}
			hit := wanted[f.State()] && !own[f.State()]
			if !hit && !viaSegment(f, seg.Name) {
				continue
			}
			entered = true
			if hit {
				vc := c
				vc.Identifier, vc.IdentifierForged = id, true
				vc.Props = appendUnique(append([]string{}, c.Props...), identifierProp)
				m.add(seg.Name, fs.Feature.Name, f, vc)
				delete(wanted, f.State())
			}
			if len(wanted) == 0 {
				return
			}
		}
		if entered {
			return
		}
	}
}

// environmentStates lists every state the environment default of a feature
// can serve, including each multivariate variant.
func (m *mapping) environmentStates(name string) map[string]bool {
	out := map[string]bool{}
	for _, fs := range m.eng.Doc.FeatureStates {
		if fs.Feature.Name != name {
			continue
		}
		out[stateOf(fs, nil).State()] = true
		for _, v := range fs.MultivariateFeatureStateValues {
			out[stateOf(fs, v).State()] = true
		}
	}
	return out
}

// environmentVariants finds identifiers reaching each variant of
// multivariate features served without any segment.
func (m *mapping) environmentVariants() {
	for _, fs := range m.eng.Doc.FeatureStates {
		if len(fs.MultivariateFeatureStateValues) == 0 || m.archived[fs.Feature.Name] {
			continue
		}
		wanted := m.wantedStates(fs)
		for n := 0; n < m.searchLimit(Candidate{}) && len(wanted) > 0; n++ {
			id := fmt.Sprintf("%s%d", probePrefix, n)
			f, ok := m.eng.Evaluate(id, nil)[fs.Feature.Name]
			if !ok || strings.HasPrefix(f.Reason, "TARGETING_MATCH") {
				continue
			}
			if _, want := wanted[f.State()]; want {
				m.add("", fs.Feature.Name, f, Candidate{Traits: map[string]string{}, Identifier: id, IdentifierForged: true, Props: []string{identifierProp}})
				delete(wanted, f.State())
			}
		}
	}
}

// wantedStates lists the variant states of fs that differ from the
// environment default.
func (m *mapping) wantedStates(fs *features.FeatureStateModel) map[string]bool {
	def := m.defaults[fs.Feature.Name].State()
	wanted := map[string]bool{}
	for _, v := range fs.MultivariateFeatureStateValues {
		if s := stateOf(fs, v).State(); s != def {
			wanted[s] = true
		}
	}
	if s := stateOf(fs, nil).State(); s != def {
		wanted[s] = true
	}
	return wanted
}

func (m *mapping) searchLimit(c Candidate) int {
	if c.Identifier != "" && c.IdentifierForged {
		return 1
	}
	if m.opts.MaxSearch > 0 {
		return m.opts.MaxSearch
	}
	return DefaultMaxSearch
}

func searchIdentifier(c Candidate, n int) string {
	if c.Identifier != "" && c.IdentifierForged {
		return c.Identifier
	}
	return fmt.Sprintf("%s%d", probePrefix, n)
}

func identifierFor(c Candidate) string {
	if c.Identifier != "" {
		return c.Identifier
	}
	return defaultIdentifier
}

// viaSegment reports whether the engine served f from the named segment.
func viaSegment(f flagsmith.Flag, name string) bool {
	return f.Reason == "TARGETING_MATCH; segment="+name
}

func (m *mapping) add(segment, flag string, f flagsmith.Flag, c Candidate) {
	def := m.defaults[flag]
	r := model.Reachable{
		Environment: m.opts.Environment, Flag: flag, Enabled: f.Enabled, Value: flagsmith.ValueString(f.Value),
		DefaultEnabled: def.Enabled, DefaultValue: flagsmith.ValueString(def.Value),
		Segment: segment, Forgeable: m.forgeability(c), EngineVerified: true,
	}
	if len(c.Traits) > 0 {
		r.ForgedTraits = c.Traits
	}
	if c.IdentifierForged {
		r.Identifier = c.Identifier
	}
	if c.IdentifierRule {
		r.IdentifierExample = m.plainIdentifier(segment, flag, f, c)
	}
	m.out = append(m.out, r)
}

// plainIdentifier returns the identifier to show for a candidate whose
// identifier is constrained by a segment rule: the candidate's identifier
// without the transient probe prefix when the engine proves that plainer
// form reaches the same state through the same segment, otherwise the
// candidate's identifier unchanged.
func (m *mapping) plainIdentifier(segment, flag string, f flagsmith.Flag, c Candidate) string {
	plain := strings.TrimPrefix(c.Identifier, transientPrefix)
	if plain == c.Identifier || plain == "" {
		return c.Identifier
	}
	got, ok := m.eng.Evaluate(plain, c.Traits)[flag]
	if ok && viaSegment(got, segment) && got.State() == f.State() {
		return plain
	}
	return c.Identifier
}

// forgeability judges a whole candidate: every property it depends on must
// be forgeable. Without settings, trait forgeability is unknown.
func (m *mapping) forgeability(c Candidate) string {
	parts := make([]string, 0, len(c.Props))
	for _, p := range c.Props {
		cond := Condition{Property: p, Operator: OpEqual}
		if kind, _ := propertyKind(p); kind == kindTrait && (m.settings == nil || m.settings.AllowClientTraits == nil) {
			if contains(m.opts.ServerOnlyTraits, p) {
				parts = append(parts, "no")
			} else {
				parts = append(parts, "unknown")
			}
			continue
		}
		allow := m.settings != nil && m.settings.AllowClientTraits != nil && *m.settings.AllowClientTraits
		parts = append(parts, Forgeability(cond, allow, m.opts.ServerOnlyTraits, m.opts.ClientSetsIdentifier))
	}
	return combineForgeability(parts)
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}
