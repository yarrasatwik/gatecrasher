package lab

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

// DefaultAPIURL is the self-hosted lab's API base.
const DefaultAPIURL = "http://localhost:8000/api/v1/"

// Options configures Seed and Reset. Zero values pick the repository defaults.
type Options struct {
	// APIURL is the Flagsmith API base (default http://localhost:8000/api/v1/).
	APIURL string
	// RepoRoot is the repository root; found by walking up to go.mod when empty.
	RepoRoot string
	// DataPath is the declared state (default <root>/lab/seed_data.yaml).
	DataPath string
	// StatePath is the generated-credentials file (default <root>/lab/.state.json).
	StatePath string
	// EnvPath is the .env file to write (default <root>/.env). Use "-" to skip.
	EnvPath string
	// Log receives progress lines; every line is redacted first. May be nil.
	Log func(format string, args ...any)
}

// resolved holds Options with defaults applied.
type resolved struct {
	Options
	data *Data
}

func (o Options) resolve() (*resolved, error) {
	if o.APIURL == "" {
		o.APIURL = DefaultAPIURL
	}
	if o.RepoRoot == "" {
		root, err := FindRepoRoot()
		if err != nil {
			return nil, err
		}
		o.RepoRoot = root
	}
	if o.DataPath == "" {
		o.DataPath = filepath.Join(o.RepoRoot, "lab", "seed_data.yaml")
	}
	if o.StatePath == "" {
		o.StatePath = filepath.Join(o.RepoRoot, "lab", ".state.json")
	}
	if o.EnvPath == "" {
		o.EnvPath = filepath.Join(o.RepoRoot, ".env")
	}
	d, err := LoadData(o.DataPath)
	if err != nil {
		return nil, err
	}
	return &resolved{Options: o, data: d}, nil
}

// FindRepoRoot walks up from the working directory to the directory holding go.mod.
func FindRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("repository root (go.mod) not found; pass Options.RepoRoot")
		}
		dir = parent
	}
}

// seeder carries the per-run context for the idempotent convergence steps.
type seeder struct {
	opts  *resolved
	api   *api
	state *State
	admin auth
	token string // lab admin user token, used only for bootstrap
	// ids resolved during the run
	features   map[string]apiFeature
	tagIDs     map[string]int
	segmentIDs map[string]int
}

func (s *seeder) logf(format string, args ...any) {
	if s.opts.Log != nil {
		s.opts.Log("%s", redact.String(fmt.Sprintf(format, args...)))
	}
}

// changed records and logs one state change made by this run.
func (s *seeder) changed(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	s.state.Changes = append(s.state.Changes, msg)
	s.logf("  + %s", msg)
}

// Seed converges a running Flagsmith to the declared vulnerable Acme Shop
// state, creating only what is missing and correcting anything that drifted.
// It writes the git-ignored lab/.state.json and .env. Safe to run repeatedly.
func Seed(ctx context.Context, opts Options) (*State, error) {
	r, err := opts.resolve()
	if err != nil {
		return nil, err
	}
	state, err := LoadState(r.StatePath)
	if err != nil {
		return nil, err
	}
	if state == nil {
		state = &State{
			AdminEmail:    r.data.AdminEmail,
			AdminPassword: "Lab-" + randomHex(10),
			PaymentSecret: newPaymentSecret(),
			Environments:  map[string]EnvState{},
		}
	}
	state.APIURL = r.APIURL
	state.registerSecrets()
	a, err := newAPI(r.APIURL)
	if err != nil {
		return nil, err
	}
	s := &seeder{opts: r, api: a, state: state, tagIDs: map[string]int{}, segmentIDs: map[string]int{}}
	state.order = r.data.Environments
	runErr := s.run(ctx)
	state.registerSecrets()
	// Persist even after a partial run so generated credentials are never lost.
	if err := state.Save(r.StatePath); err != nil {
		return nil, errors.Join(runErr, err)
	}
	if runErr != nil {
		return nil, runErr
	}
	if r.EnvPath != "-" {
		if err := os.WriteFile(r.EnvPath, []byte(state.EnvFile()), 0o600); err != nil {
			return nil, fmt.Errorf("write .env: %w", err)
		}
	}
	return state, nil
}

// Reset restores every planted vulnerability (environment settings,
// server-side-only flags, segment rules, flag values and targeting) so the walkthrough
// can be recorded again. The lab must have been seeded before.
func Reset(ctx context.Context, opts Options) (*State, error) {
	r, err := opts.resolve()
	if err != nil {
		return nil, err
	}
	st, err := LoadState(r.StatePath)
	if err != nil {
		return nil, err
	}
	if st == nil {
		return nil, fmt.Errorf("no lab state at %s: run the seed first", r.StatePath)
	}
	return Seed(ctx, opts)
}

func (s *seeder) run(ctx context.Context) error {
	steps := []struct {
		name string
		fn   func(context.Context) error
	}{
		{"wait for Flagsmith", s.waitReady},
		{"admin user", s.ensureAdmin},
		{"organisation and API key", s.ensureOrganisation},
		{"project", s.ensureProject},
		{"environments", s.ensureEnvironments},
		{"tags", s.ensureTags},
		{"segments", s.ensureSegments},
		{"features", s.ensureFeatures},
		{"identities", s.ensureIdentities},
		{"per-environment state", s.ensureEnvironmentState},
	}
	for _, st := range steps {
		s.logf("%s", st.name)
		if err := st.fn(ctx); err != nil {
			return fmt.Errorf("%s: %w", st.name, err)
		}
	}
	return nil
}

func (s *seeder) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(90 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		status, err := s.api.status(ctx, nil, "GET", s.api.origin()+"/health/liveness/", nil)
		if err == nil && status == 200 {
			return nil
		}
		last = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("flagsmith at %s is not healthy (is the lab up? make lab-up): %v", s.api.origin(), last)
}
