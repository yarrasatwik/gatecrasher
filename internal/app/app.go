// Package app wires every Gatecrasher stage together: recon, classification,
// the inside map, live cross-checks, reports, fix plans, approvals, apply,
// verify, rollback and watch mode. The CLI, the web UI and the GitHub Action
// all drive this one orchestrator.
package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/ai"
	"github.com/yarrasatwik/gatecrasher/internal/audit"
	"github.com/yarrasatwik/gatecrasher/internal/config"
	"github.com/yarrasatwik/gatecrasher/internal/fixes"
	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
	"github.com/yarrasatwik/gatecrasher/internal/httpx"
	"github.com/yarrasatwik/gatecrasher/internal/watch"
)

// Version is the Gatecrasher version, set by -ldflags at release time.
var Version = "dev"

// App is the orchestrator. It is safe for concurrent use by the web UI.
type App struct {
	Cfg   *config.Config
	HTTP  *httpx.Client
	Admin *flagsmith.Admin
	AI    *ai.Client
	Log   *audit.Log
	Store *fixes.Store

	mu       sync.Mutex
	project  *flagsmith.Project
	envs     map[string]flagsmith.Environment
	receiver *watch.Receiver
	alerts   *alertHub
}

// New builds an App from a loaded configuration. The inside view is
// available only when an organisation API key is configured.
func New(cfg *config.Config) (*App, error) {
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("state dir: %w", err)
	}
	lg, err := audit.Open(cfg.StateDir)
	if err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	st, err := fixes.NewStore(cfg.StateDir)
	if err != nil {
		return nil, fmt.Errorf("plan store: %w", err)
	}
	// Plans, approvals, refusals and rejections go to the audit log too.
	st.Audit = lg
	hc := httpx.New(cfg.Lock(), httpx.WithRate(cfg.Probes.RatePerSec), httpx.WithTimeout(15*time.Second))
	aiClient, err := newAI(cfg)
	if err != nil {
		return nil, err
	}
	a := &App{Cfg: cfg, HTTP: hc, AI: aiClient, Log: lg, Store: st, alerts: newAlertHub()}
	if cfg.OrgAPIKey != "" {
		a.Admin = flagsmith.NewAdmin(hc, cfg.Flagsmith.APIURL, cfg.OrgAPIKey)
	}
	return a, nil
}

// newAI picks the AI provider from configuration.
func newAI(cfg *config.Config) (*ai.Client, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.AI)) {
	case "claude-code", "claude-cli", "claude":
		return ai.NewClaudeCode("", cfg.Model)
	case "off", "none":
		return ai.New("", cfg.Model), nil
	case "", "api":
		return ai.New(cfg.AnthropicKey, cfg.Model), nil
	}
	return nil, fmt.Errorf("unknown ai provider %q (want api, claude-code or off)", cfg.AI)
}

// InsideView reports whether admin access is configured.
func (a *App) InsideView() bool { return a.Admin != nil }

// Project resolves (and caches) the configured project and its environments.
func (a *App) Project(ctx context.Context) (*flagsmith.Project, map[string]flagsmith.Environment, error) {
	if a.Admin == nil {
		return nil, nil, flagsmith.ErrNoAdminKey
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.project != nil {
		return a.project, a.envs, nil
	}
	p, err := a.Admin.ProjectByName(ctx, a.Cfg.Flagsmith.Project)
	if err != nil {
		return nil, nil, err
	}
	list, err := a.Admin.Environments(ctx, p.ID)
	if err != nil {
		return nil, nil, err
	}
	envs := map[string]flagsmith.Environment{}
	for _, e := range list {
		envs[e.Name] = e
	}
	a.project, a.envs = p, envs
	return p, envs, nil
}

// Environment returns the environment with the given name (case-insensitive).
func (a *App) Environment(ctx context.Context, name string) (flagsmith.Environment, error) {
	_, envs, err := a.Project(ctx)
	if err != nil {
		return flagsmith.Environment{}, err
	}
	for n, e := range envs {
		if strings.EqualFold(n, name) {
			return e, nil
		}
	}
	names := make([]string, 0, len(envs))
	for n := range envs {
		names = append(names, n)
	}
	sort.Strings(names)
	return flagsmith.Environment{}, fmt.Errorf("environment %q not found in project (have: %s)", name, strings.Join(names, ", "))
}

// EnvRefs lists the configured environments for the planner.
func (a *App) EnvRefs(ctx context.Context) ([]fixes.EnvRef, map[string]string, error) {
	_, envs, err := a.Project(ctx)
	if err != nil {
		return nil, nil, err
	}
	var refs []fixes.EnvRef
	keys := map[string]string{}
	for name, e := range envs {
		refs = append(refs, fixes.EnvRef{Name: name, Key: e.APIKey, Production: a.Cfg.IsProduction(name)})
		keys[name] = e.APIKey
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Name < refs[j].Name })
	return refs, keys, nil
}

// ReportDir is where reports are written.
func (a *App) ReportDir() string { return a.Cfg.ReportDir }

// Applier builds a fixes.Applier bound to this app.
func (a *App) Applier(ctx context.Context) (*fixes.Applier, error) {
	if a.Admin == nil {
		return nil, flagsmith.ErrNoAdminKey
	}
	p, _, err := a.Project(ctx)
	if err != nil {
		return nil, err
	}
	_, keys, err := a.EnvRefs(ctx)
	if err != nil {
		return nil, err
	}
	cfg := fixes.Config{Admin: a.Admin, Store: a.Store, Audit: a.Log, ProjectID: p.ID, EnvKeys: keys,
		UseCLI: a.Cfg.Flagsmith.UseCLI, Timeout: a.Cfg.PropagationTimeout(), PollInterval: 500 * time.Millisecond}
	if a.Cfg.Flagsmith.UseCLI {
		if cli, err := fixes.NewExecCLI(ctx, a.Cfg.Flagsmith.APIURL, a.Cfg.OrgAPIKey, p.ID); err == nil {
			cfg.CLI = cli
		}
	}
	return fixes.NewApplier(cfg), nil
}

// EngineVersion reports the evaluation engine module version from build info.
func EngineVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if strings.HasPrefix(d.Path, "github.com/Flagsmith/flagsmith-go-client") {
				return d.Path + " " + d.Version
			}
		}
	}
	return flagsmith.EngineVersion
}

// reportPath returns the canonical JSON path of a report id.
func (a *App) reportPath(id string) (string, error) {
	if id == "" || id == "latest" {
		return filepath.Join(a.Cfg.ReportDir, "latest.json"), nil
	}
	if strings.ContainsAny(id, `/\.`) {
		return "", errors.New("invalid report id")
	}
	return filepath.Join(a.Cfg.ReportDir, id+".json"), nil
}
