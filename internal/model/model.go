// Package model holds the canonical data types shared by every Gatecrasher
// stage: inventory, findings, reports, fix plans and approvals. These types
// are the JSON contract between stages and must stay backwards compatible.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SchemaVersion is the version of the canonical report JSON.
const SchemaVersion = "1.0"

// Severity is a deterministic finding severity. Higher is worse.
type Severity int

// Severity levels, ordered.
const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

var sevNames = [...]string{"info", "low", "medium", "high", "critical"}

// String returns the lowercase severity name.
func (s Severity) String() string {
	if s < SevInfo || s > SevCritical {
		return "unknown"
	}
	return sevNames[s]
}

// MarshalJSON encodes the severity as its name.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// UnmarshalJSON decodes a severity name.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return err
	}
	v, err := ParseSeverity(name)
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// ParseSeverity parses a severity name (case-insensitive).
func ParseSeverity(name string) (Severity, error) {
	for i, n := range sevNames {
		if strings.EqualFold(n, strings.TrimSpace(name)) {
			return Severity(i), nil
		}
	}
	return SevInfo, fmt.Errorf("unknown severity %q (want info|low|medium|high|critical)", name)
}

// Category classifies a flag name or value by sensitivity.
type Category string

// Classification categories (spec §8.2).
const (
	CatSecret            Category = "SECRET"
	CatInternalURL       Category = "INTERNAL_URL"
	CatUnreleasedProduct Category = "UNRELEASED_PRODUCT"
	CatPricing           Category = "PRICING"
	CatPII               Category = "PII"
	CatSecurityControl   Category = "SECURITY_CONTROL"
	CatHarmless          Category = "HARMLESS"
	// CatPossibleSecret is a value that only looks random: no known secret
	// pattern, secret-named key or URL credential backs it. It needs a
	// human review and is never rated above LOW.
	CatPossibleSecret Category = "POSSIBLE_SECRET"
)

// AllCategories lists every valid category.
var AllCategories = []Category{CatSecret, CatInternalURL, CatUnreleasedProduct, CatPricing, CatPII, CatSecurityControl, CatPossibleSecret, CatHarmless}

// Valid reports whether c is a known category.
func (c Category) Valid() bool {
	for _, k := range AllCategories {
		if k == c {
			return true
		}
	}
	return false
}

// FindingType names a class of vulnerability.
type FindingType string

// Finding types (spec §8, docs/findings-catalog.md).
const (
	FTraitForgery          FindingType = "TRAIT_FORGERY"
	FPercentageReroll      FindingType = "PERCENTAGE_REROLL"
	FVariantReroll         FindingType = "VARIANT_REROLL"
	FExperimentRigging     FindingType = "EXPERIMENT_RIGGING"
	FIdentityTraitLeak     FindingType = "IDENTITY_TRAIT_LEAK"
	FIdentityOverrideLeak  FindingType = "IDENTITY_OVERRIDE_LEAK"
	FSecretExposed         FindingType = "SECRET_IN_CLIENT_VALUE"
	FInternalURL           FindingType = "INTERNAL_URL_LEAK"
	FUnreleasedProduct     FindingType = "UNRELEASED_PRODUCT_LEAK"
	FPricingLeak           FindingType = "PRICING_LEAK"
	FPIILeak               FindingType = "PII_IN_CLIENT_VALUE"
	FSettingClientTraitsOn FindingType = "SETTING_CLIENT_TRAITS_ON"
	FSettingSensitiveData  FindingType = "SETTING_SENSITIVE_DATA_VISIBLE"
	FFlagNotServerOnly     FindingType = "FLAG_NOT_SERVER_ONLY"
	FSegmentForgeable      FindingType = "SEGMENT_FORGEABLE"
	FControlOK             FindingType = "CONTROL_OK"
	// FPossibleSecret is a high-entropy client-visible value with no other
	// evidence that it is a credential: LOW, "needs review".
	FPossibleSecret FindingType = "POSSIBLE_SECRET_IN_CLIENT_VALUE"
)

// Method records which mechanism produced or confirmed a finding.
type Method string

// Detection methods.
const (
	MethodProbe         Method = "live-probe"
	MethodEngine        Method = "flagsmith-engine"
	MethodDeterministic Method = "deterministic"
	MethodAI            Method = "ai"
	MethodSettings      Method = "admin-settings"
)

// Status is the exploitability state of a finding.
type Status string

// Finding statuses.
const (
	StatusExploitable Status = "EXPLOITABLE"
	StatusBlocked     Status = "BLOCKED"
	StatusUnknown     Status = "UNKNOWN"
)

// Evidence is one redacted request/response pair or observation.
// Every string here MUST already have passed through redact.
type Evidence struct {
	Kind     string `json:"kind"` // "request", "engine", "setting", "bundle"
	Request  string `json:"request,omitempty"`
	Response string `json:"response,omitempty"`
	Note     string `json:"note,omitempty"`
}

// FlagChange is a flag whose state differed between baseline and probe.
type FlagChange struct {
	Flag   string `json:"flag"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// Explanation is the plain-English text for a finding. Source is "ai" when
// Claude wrote it and "template" when deterministic templates did.
type Explanation struct {
	Title          string `json:"title"`
	WhatHappened   string `json:"what_happened"`
	WhyItMatters   string `json:"why_it_matters"`
	BusinessImpact string `json:"business_impact"`
	FixSummary     string `json:"fix_summary"`
	Source         string `json:"source"`
}

// Finding is a confirmed (or explicitly unknown) security issue.
type Finding struct {
	ID          string            `json:"id"`
	Type        FindingType       `json:"type"`
	Severity    Severity          `json:"severity"`
	Title       string            `json:"title"`
	Environment string            `json:"environment,omitempty"`
	Subject     string            `json:"subject"` // flag, setting or segment name
	Category    Category          `json:"category,omitempty"`
	DetectedBy  []Method          `json:"detected_by"`
	Confirmed   bool              `json:"confirmed"`
	Status      Status            `json:"status"`
	Traits      map[string]string `json:"forged_traits,omitempty"`
	Unlocked    []FlagChange      `json:"unlocked,omitempty"`
	HitRate     float64           `json:"hit_rate,omitempty"`
	Attempts    float64           `json:"expected_attempts,omitempty"`
	ProofID     string            `json:"proof_identifier,omitempty"`
	Variants    map[string]int    `json:"variant_counts,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Explanation *Explanation      `json:"explanation,omitempty"`
	Repro       string            `json:"repro,omitempty"`
	Evidence    []Evidence        `json:"evidence,omitempty"`
	FixPlanID   string            `json:"fix_plan_id,omitempty"`
	Notes       []string          `json:"notes,omitempty"`
}

// MakeFindingID returns a stable short ID derived from the finding identity,
// so re-running an audit yields the same IDs for the same issues.
func MakeFindingID(t FindingType, env, subject string, extra ...string) string {
	h := sha256.New()
	h.Write([]byte(string(t) + "\x00" + env + "\x00" + subject))
	for _, e := range extra {
		h.Write([]byte("\x00" + e))
	}
	return "GC-" + strings.ToUpper(hex.EncodeToString(h.Sum(nil))[:8])
}

// FlagView is one flag as seen through the public (client-side) API.
type FlagView struct {
	Name      string `json:"name"`
	FeatureID int    `json:"feature_id"`
	Type      string `json:"type,omitempty"` // STANDARD | MULTIVARIATE
	Enabled   bool   `json:"enabled"`
	ValueType string `json:"value_type"` // null|bool|number|string|json
	Preview   string `json:"preview"`    // redacted, truncated
	Size      int    `json:"size"`
	// RawValue is the unredacted value. It never leaves the process:
	// it is excluded from JSON and must never be logged or sent to the AI.
	RawValue any `json:"-"`
}

// PublicInventory is what an outsider can see with the public key.
type PublicInventory struct {
	TargetURL      string     `json:"target_url"`
	APIURL         string     `json:"api_url"`
	KeyFingerprint string     `json:"key_fingerprint"` // redacted
	KeySources     []string   `json:"key_sources"`     // e.g. "app.js:12 environmentID"
	TraitKeys      []string   `json:"trait_keys_in_bundle,omitempty"`
	Flags          []FlagView `json:"flags"`
	FetchedAt      time.Time  `json:"fetched_at"`
	// Key is the discovered client key. Never serialised.
	Key string `json:"-"`
}

// Classification is the sensitivity class of one flag.
type Classification struct {
	Flag       string   `json:"flag"`
	Category   Category `json:"category"`
	Confidence float64  `json:"confidence"`
	Rationale  string   `json:"rationale"`
	Method     Method   `json:"method"`
	Signals    []string `json:"signals,omitempty"`
}

// EnvSettings captures the security-relevant settings of one environment.
type EnvSettings struct {
	Environment       string   `json:"environment"`
	AllowClientTraits *bool    `json:"allow_client_traits"`
	HideSensitiveData *bool    `json:"hide_sensitive_data"`
	UseV2Versioning   bool     `json:"use_v2_feature_versioning"`
	ServerOnlyFlags   []string `json:"server_only_flags"`
	ClientVisible     []string `json:"client_visible_flags"`
}

// Reachable is a flag state an attacker can reach, with the minimal input.
type Reachable struct {
	Environment    string            `json:"environment"`
	Flag           string            `json:"flag"`
	Enabled        bool              `json:"enabled"`
	Value          string            `json:"value"`
	DefaultEnabled bool              `json:"default_enabled"`
	DefaultValue   string            `json:"default_value"`
	Segment        string            `json:"segment,omitempty"`
	ForgedTraits   map[string]string `json:"forged_traits,omitempty"`
	Identifier     string            `json:"identifier,omitempty"` // for percentage splits
	Forgeable      string            `json:"forgeable"`            // yes|no|unknown
	EngineVerified bool              `json:"engine_verified"`
	LiveVerified   *bool             `json:"live_verified,omitempty"`
}

// VerifyRow is one before/after row produced by re-attacking.
type VerifyRow struct {
	FindingID string `json:"finding_id"`
	Title     string `json:"title"`
	Before    Status `json:"before"`
	After     Status `json:"after"`
	Proof     string `json:"proof"`
}

// Stats holds measured numbers for the README and report.
type Stats struct {
	ProbesSent       int64            `json:"probes_sent"`
	DurationMS       int64            `json:"duration_ms"`
	StageMS          map[string]int64 `json:"stage_ms,omitempty"`
	BySeverity       map[string]int   `json:"by_severity"`
	ParityChecked    int              `json:"parity_checked,omitempty"`
	ParityAgreed     int              `json:"parity_agreed,omitempty"`
	AIHeuristicAgree *float64         `json:"ai_heuristic_agreement,omitempty"`
}

// Report is the canonical audit output; every other format derives from it.
type Report struct {
	SchemaVersion   string           `json:"schema_version"`
	ID              string           `json:"id"`
	Tool            string           `json:"tool"`
	Version         string           `json:"version"`
	CreatedAt       time.Time        `json:"created_at"`
	Target          string           `json:"target,omitempty"`
	Project         string           `json:"project,omitempty"`
	Environment     string           `json:"environment,omitempty"`
	AIMode          string           `json:"ai_mode"` // "on (model)" | "off (heuristics)"
	Scope           []string         `json:"scope"`
	Inventory       *PublicInventory `json:"inventory,omitempty"`
	Classifications []Classification `json:"classifications,omitempty"`
	Findings        []Finding        `json:"findings"`
	Settings        []EnvSettings    `json:"settings,omitempty"`
	Reachability    []Reachable      `json:"reachability,omitempty"`
	BeforeAfter     []VerifyRow      `json:"before_after,omitempty"`
	Stats           Stats            `json:"stats"`
	Notes           []string         `json:"notes,omitempty"`
}

// CountAtOrAbove returns how many findings are at or above min severity.
func (r *Report) CountAtOrAbove(min Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity >= min && f.Type != FControlOK {
			n++
		}
	}
	return n
}

// ImpactItem is a place in the app's code that a fix would affect.
type ImpactItem struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet"`
	Message string `json:"message"`
	Breaks  bool   `json:"breaks"`
}

// Operation is one write a plan performs. Automatic=false means it is
// guidance only (PR draft, rotate secret) and is never executed.
type Operation struct {
	Kind        string         `json:"kind"` // env.patch | feature.patch | segment.patch | pr.draft | manual
	Description string         `json:"description"`
	Method      string         `json:"method,omitempty"`
	Path        string         `json:"path,omitempty"` // Admin API path, relative to api_url
	Body        map[string]any `json:"body,omitempty"`
	Before      map[string]any `json:"before,omitempty"`
	Automatic   bool           `json:"automatic"`
	Via         string         `json:"via,omitempty"` // "flagsmith-cli" | "admin-api"
	Draft       string         `json:"draft,omitempty"`
}

// Plan is an immutable fix plan. Hash covers every field except Hash.
type Plan struct {
	ID                string         `json:"plan_id"`
	CreatedAt         time.Time      `json:"created_at"`
	Environment       string         `json:"environment"`
	EnvironmentKey    string         `json:"-"`
	Production        bool           `json:"production"`
	Title             string         `json:"title"`
	TargetObject      string         `json:"target_object"`
	BeforeSnapshot    map[string]any `json:"before_snapshot"`
	Operations        []Operation    `json:"operations"`
	Impact            []ImpactItem   `json:"impact"`
	FindingsAddressed []string       `json:"findings_addressed"`
	ExperimentWarning string         `json:"experiment_warning,omitempty"`
	Hash              string         `json:"hash"`
}

// ComputeHash returns the canonical SHA-256 of the plan without its Hash.
func (p Plan) ComputeHash() string {
	p.Hash = ""
	b, _ := json.Marshal(p)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Approval binds a human decision to exactly one plan hash.
type Approval struct {
	PlanID               string    `json:"plan_id"`
	PlanHash             string    `json:"plan_hash"`
	ApprovedAt           time.Time `json:"approved_at"`
	ExpiresAt            time.Time `json:"expires_at"`
	ConfirmedEnvironment string    `json:"confirmed_environment,omitempty"`
	ContaminateConfirmed bool      `json:"contaminate_experiment_confirmed,omitempty"`
	By                   string    `json:"by"`
	Channel              string    `json:"channel"` // cli | web
}

// PlanState is the lifecycle state of a plan on disk.
type PlanState string

// Plan states.
const (
	PlanPending    PlanState = "pending"
	PlanApproved   PlanState = "approved"
	PlanRejected   PlanState = "rejected"
	PlanApplied    PlanState = "applied"
	PlanVerified   PlanState = "verified"
	PlanRolledBack PlanState = "rolled_back"
	PlanStale      PlanState = "stale"
)

// PlanRecord is a plan plus its mutable lifecycle metadata.
type PlanRecord struct {
	Plan      Plan        `json:"plan"`
	State     PlanState   `json:"state"`
	Approval  *Approval   `json:"approval,omitempty"`
	AppliedAt *time.Time  `json:"applied_at,omitempty"`
	TookMS    int64       `json:"propagation_ms,omitempty"`
	Verify    []VerifyRow `json:"verify,omitempty"`
	Error     string      `json:"error,omitempty"`
}
