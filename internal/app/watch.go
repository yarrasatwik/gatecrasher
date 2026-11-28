package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/audit"
	"github.com/yarrasatwik/gatecrasher/internal/httpx"
	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/report"
	"github.com/yarrasatwik/gatecrasher/internal/watch"
)

// Watcher is a running watch mode: a signed-webhook receiver registered as a
// Flagsmith organisation webhook.
type Watcher struct {
	Receiver *watch.Receiver
	reg      *watch.Registration
	a        *App
	stop     func()
}

// StartWatch builds the receiver, seeds it with the current findings (so
// only new issues alert), and registers the organisation webhook pointing
// at publicURL. baseURL prefixes "Review fix" links (the web UI).
func (a *App) StartWatch(ctx context.Context, publicURL, baseURL string) (*Watcher, error) {
	p, _, err := a.Project(ctx)
	if err != nil {
		return nil, err
	}
	secret := a.Cfg.WebhookSecret
	if secret == "" {
		if secret, err = watch.GenerateSecret(); err != nil {
			return nil, err
		}
	}
	opts := watch.Options{Secret: secret, Recheck: a.recheckChange, BaseURL: baseURL, Logger: slog.Default()}
	if a.Cfg.SlackWebhook != "" {
		if s, err := watch.NewSlack(a.Cfg.SlackWebhook); err == nil {
			opts.Slack = s
		}
	}
	rcv, err := watch.NewReceiver(opts)
	if err != nil {
		return nil, err
	}
	base, err := a.Audit(ctx, AuditOptions{Inside: true, Fast: true})
	if err != nil {
		rcv.Close()
		return nil, fmt.Errorf("baseline map: %w", err)
	}
	if n := report.IncompleteNote(base); n != "" {
		rcv.Close()
		return nil, fmt.Errorf("baseline map %s Raise probes.max_requests so the baseline can finish.", n)
	}
	rcv.Seed(findingIDs(base))
	reg, err := watch.Register(ctx, a.Admin, p.Organisation, publicURL, secret)
	if err != nil {
		rcv.Close()
		return nil, fmt.Errorf("register organisation webhook: %w", err)
	}
	ch, unsub := rcv.Subscribe()
	go func() {
		for al := range ch {
			a.alerts.publish(al)
			_, _ = a.Log.Append("watch", audit.ActionWatchAlert, "", map[string]any{
				"change": al.Change.Kind, "feature": al.Change.Feature, "segment": al.Change.Segment,
				"new_findings": len(al.Findings), "latency_ms": al.LatencyMS})
		}
	}()
	a.receiver = rcv
	return &Watcher{Receiver: rcv, reg: reg, a: a, stop: unsub}, nil
}

// Handler is the webhook HTTP handler.
func (w *Watcher) Handler() http.Handler { return w.Receiver }

// Close removes the Flagsmith webhook and stops the receiver.
func (w *Watcher) Close(ctx context.Context) error {
	w.stop()
	w.Receiver.Close()
	w.a.receiver = nil
	if w.reg != nil {
		return w.reg.Remove(ctx, w.a.Admin)
	}
	return nil
}

// recheckChange re-maps the environment a change touched and returns the
// findings related to the changed feature or segment (or all, if unknown).
func (a *App) recheckChange(ctx context.Context, c watch.Change) ([]model.Finding, error) {
	env := a.defaultEnv()
	if c.Environment != "" {
		if e, err := a.environmentByKeyOrName(ctx, c.Environment); err == nil {
			env = e
		}
	}
	hb := a.hourlyBudget()
	left := hb.remaining()
	if left <= 0 {
		return nil, errHourly(a.Cfg.Watch.MaxRequestsPerHour)
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	b := httpx.NewBudget(int64(left))
	r, err := a.Audit(ctx, AuditOptions{Inside: true, Environment: env, Fast: true, budget: b})
	hb.record(int(b.Used()))
	if err != nil {
		return nil, err
	}
	if n := report.IncompleteNote(r); n != "" {
		// Findings the cut-off re-check could not examine are unknown; an
		// error alert says so instead of a clean "nothing new".
		return nil, fmt.Errorf("re-check %s", n)
	}
	if c.Feature == "" && c.Segment == "" {
		return r.Findings, nil
	}
	var out []model.Finding
	for _, f := range r.Findings {
		if related(f, c) {
			out = append(out, f)
		}
	}
	return out, nil
}

func related(f model.Finding, c watch.Change) bool {
	if c.Segment != "" && strings.EqualFold(f.Subject, c.Segment) {
		return true
	}
	if c.Feature != "" {
		if strings.EqualFold(f.Subject, c.Feature) {
			return true
		}
		for _, u := range f.Unlocked {
			if strings.EqualFold(u.Flag, c.Feature) {
				return true
			}
		}
	}
	return f.Type == model.FSettingClientTraitsOn || f.Type == model.FSettingSensitiveData
}

func (a *App) environmentByKeyOrName(ctx context.Context, s string) (string, error) {
	_, envs, err := a.Project(ctx)
	if err != nil {
		return "", err
	}
	for name, e := range envs {
		if strings.EqualFold(name, s) || e.APIKey == s || fmt.Sprint(e.ID) == s {
			return name, nil
		}
	}
	return "", fmt.Errorf("unknown environment %q", s)
}

func parseTime(s string) (time.Time, error) { return time.Parse(time.RFC3339Nano, s) }
