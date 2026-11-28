package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/app"
	"github.com/yarrasatwik/gatecrasher/internal/config"
	"github.com/yarrasatwik/gatecrasher/internal/fixes"
	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/parity"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
	"github.com/yarrasatwik/gatecrasher/internal/report"
	"github.com/yarrasatwik/gatecrasher/internal/verify"
)

// common holds flags every command accepts.
type common struct {
	config string
	json   bool
}

func newFlags(name string) (*flag.FlagSet, *common) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	c := &common{}
	fs.StringVar(&c.config, "config", "", "config file (default gatecrasher.yaml, then gatecrasher.example.yaml)")
	fs.BoolVar(&c.json, "json", false, "compact machine-readable output")
	return fs, c
}

func load(c *common) (*app.App, error) {
	path := c.config
	if path == "" {
		for _, p := range []string{"gatecrasher.yaml", "gatecrasher.yml", "gatecrasher.example.yaml"} {
			if _, err := os.Stat(p); err == nil {
				path = p
				break
			}
		}
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	return app.New(cfg)
}

func cmdVersion(ctx context.Context, args []string) error {
	fmt.Println("gatecrasher", app.Version, "· engine", app.EngineVersion())
	return nil
}

func cmdAudit(ctx context.Context, args []string) error {
	fs, c := newFlags("audit")
	target := fs.String("target", "", "site to audit (default target_url)")
	env := fs.String("env", "", "environment for the inside map (default: first production env)")
	paritySamples := fs.Int("parity", 200, "engine-vs-live parity samples (0 to skip)")
	failOn := fs.String("fail-on", "", "exit 1 when findings at/above this severity exist")
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := load(c)
	if err != nil {
		return err
	}
	r, err := a.Audit(ctx, app.AuditOptions{Target: *target, Environment: *env, Outside: true, Inside: true,
		ParitySamples: *paritySamples, Explain: true, Progress: progress(c.json)})
	if err != nil {
		return err
	}
	return finish(a, r, c.json, *failOn)
}

func cmdRecon(ctx context.Context, args []string) error {
	fs, c := newFlags("recon")
	target := fs.String("target", "", "site to audit (default target_url)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := load(c)
	if err != nil {
		return err
	}
	r, err := a.Audit(ctx, app.AuditOptions{Target: *target, Outside: true, Explain: true, Progress: progress(c.json)})
	if err != nil {
		return err
	}
	return finish(a, r, c.json, "")
}

func cmdMap(ctx context.Context, args []string) error {
	fs, c := newFlags("map")
	env := fs.String("env", "", "environment to map")
	paritySamples := fs.Int("parity", 0, "engine-vs-live parity samples")
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := load(c)
	if err != nil {
		return err
	}
	r, err := a.Audit(ctx, app.AuditOptions{Environment: *env, Inside: true, ParitySamples: *paritySamples, Explain: true, Progress: progress(c.json)})
	if err != nil {
		return err
	}
	return finish(a, r, c.json, "")
}

func cmdCI(ctx context.Context, args []string) error {
	fs, c := newFlags("ci")
	env := fs.String("env", "", "environment to map")
	failOn := fs.String("fail-on", "high", "exit 1 when findings at/above this severity exist (none to never fail)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := load(c)
	if err != nil {
		return err
	}
	r, err := a.Audit(ctx, app.AuditOptions{Environment: *env, Inside: true, Explain: true})
	if err != nil {
		return err
	}
	if p := os.Getenv("GITHUB_STEP_SUMMARY"); p != "" {
		if f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			_ = report.WriteMarkdown(f, r)
			_ = f.Close()
		}
	}
	return finish(a, r, c.json, *failOn)
}

// finish saves every format, prints the summary and applies --fail-on.
func finish(a *app.App, r *model.Report, asJSON bool, failOn string) error {
	paths, err := a.SaveReport(r)
	if err != nil {
		return err
	}
	if asJSON {
		if err := report.WriteCompactJSON(os.Stdout, r); err != nil {
			return err
		}
	} else {
		printSummary(r, paths)
	}
	if failOn == "" || strings.EqualFold(failOn, "none") {
		return nil
	}
	min, err := model.ParseSeverity(failOn)
	if err != nil {
		return err
	}
	if n := openAtOrAbove(r, min); n > 0 {
		return findingsErr{n}
	}
	return nil
}

func openAtOrAbove(r *model.Report, min model.Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity >= min && f.Open() {
			n++
		}
	}
	return n
}

func printSummary(r *model.Report, paths []string) {
	fmt.Print(summaryText(r, paths))
}

// summaryText renders the audit summary: the headline "N ways in · M
// findings" (N = exploitable root causes, M = confirmed findings), then every
// finding under its root cause, highest severity first.
func summaryText(r *model.Report, paths []string) string {
	var b strings.Builder
	sum := report.Summarize(r)
	fmt.Fprintln(&b)
	head := "  " + report.HeadlineOf(sum.WaysIn, sum.Findings) + "  "
	if sum.WaysIn == 0 {
		fmt.Fprintln(&b, bgGreen(head)+"  no exploitable root cause")
	} else {
		fmt.Fprintln(&b, bgRed(head)+"  "+sevLine(r))
	}
	fmt.Fprintln(&b, dim(fmt.Sprintf("  target %s · env %s · AI %s · %d requests · %.1fs",
		nonEmpty(r.Target, "—"), nonEmpty(r.Environment, "—"), r.AIMode, r.Stats.ProbesSent, float64(r.Stats.DurationMS)/1000)))
	if r.Stats.ParityChecked > 0 {
		fmt.Fprintln(&b, dim(fmt.Sprintf("  engine vs live parity: %d/%d agree", r.Stats.ParityAgreed, r.Stats.ParityChecked)))
	}
	for _, g := range report.GroupByRootCause(r) {
		if g.Kind == "control held" {
			continue
		}
		fmt.Fprintln(&b)
		fmt.Fprintf(&b, "  %s %s %s\n", sevTag(g.Cause.Severity), bold(safe(g.Cause.Title)), dim("("+g.Kind+" · "+g.Cause.ID+")"))
		for _, f := range g.Findings {
			proof := ""
			for _, m := range f.DetectedBy {
				if m == model.MethodProbe {
					proof = green(" ✓ reproduced live")
				}
			}
			status := ""
			switch f.Status {
			case model.StatusBlocked:
				status = green(" [BLOCKED]")
			case model.StatusHidden:
				status = yellow(" [HIDDEN: not served to client SDKs, still open]")
			case model.StatusUnknown:
				status = yellow(" [unconfirmed]")
			}
			fmt.Fprintf(&b, "     %s %s %s%s%s\n", sevTag(f.Severity), dim(f.ID), safe(f.Title), proof, status)
		}
	}
	var review []model.Finding
	for _, f := range r.Findings {
		if f.Status == model.StatusNeedsReview {
			review = append(review, f)
		}
	}
	if len(review) > 0 {
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, dim(fmt.Sprintf("  Claude suggests reviewing (%d) — not counted; confirm in the web UI if real", len(review))))
		for _, f := range review {
			fmt.Fprintf(&b, "   %s  %s %s\n", yellow("?"), dim(f.ID), safe(f.Title))
		}
	}
	fmt.Fprintln(&b)
	for _, p := range paths {
		if strings.Contains(filepath.Base(p), "latest") {
			fmt.Fprintln(&b, dim("  wrote "+p))
		}
	}
	fmt.Fprintln(&b, dim("  next: gatecrasher plan   (builds fix plans; nothing changes until a human approves)"))
	return b.String()
}

func sevLine(r *model.Report) string {
	var parts []string
	for _, s := range []model.Severity{model.SevCritical, model.SevHigh, model.SevMedium, model.SevLow} {
		if c := r.Stats.BySeverity[s.String()]; c > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c, s))
		}
	}
	return strings.Join(parts, " · ")
}

func progress(quiet bool) app.Progress {
	if quiet {
		return nil
	}
	return func(stage, msg string) {
		fmt.Fprintf(os.Stderr, "%s %s\n", cyan(fmt.Sprintf("%-9s", stage)), safe(msg))
	}
}

func cmdPlan(ctx context.Context, args []string) error {
	fs, c := newFlags("plan")
	finding := fs.String("finding", "", "plan only this finding ID")
	reportID := fs.String("report", "latest", "report to plan from")
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := load(c)
	if err != nil {
		return err
	}
	recs, err := a.MakePlans(ctx, *reportID, *finding)
	if err != nil {
		return err
	}
	if c.json {
		return json.NewEncoder(os.Stdout).Encode(planBriefs(recs))
	}
	for _, rec := range recs {
		printPlan(rec)
	}
	fmt.Println(dim("  approve with: gatecrasher approve <plan_id> --confirm <environment name>"))
	return nil
}

func cmdPlans(ctx context.Context, args []string) error {
	fs, c := newFlags("plans")
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := load(c)
	if err != nil {
		return err
	}
	recs, err := a.Store.List()
	if err != nil {
		return err
	}
	if c.json {
		return json.NewEncoder(os.Stdout).Encode(planBriefs(recs))
	}
	for _, rec := range recs {
		fmt.Printf("  %s  %-11s %-12s %s\n", bold(rec.Plan.ID), rec.State, rec.Plan.Environment, safe(rec.Plan.Title))
	}
	return nil
}

type planBrief struct {
	ID       string          `json:"id"`
	State    model.PlanState `json:"state"`
	Env      string          `json:"env"`
	Title    string          `json:"title"`
	Findings int             `json:"findings"`
	Auto     int             `json:"auto_ops"`
}

func planBriefs(recs []*model.PlanRecord) []planBrief {
	out := make([]planBrief, 0, len(recs))
	for _, r := range recs {
		auto := 0
		for _, op := range r.Plan.Operations {
			if op.Automatic {
				auto++
			}
		}
		out = append(out, planBrief{r.Plan.ID, r.State, r.Plan.Environment, redact.String(r.Plan.Title), len(r.Plan.FindingsAddressed), auto})
	}
	return out
}

func printPlan(rec *model.PlanRecord) {
	p := rec.Plan
	fmt.Println()
	fmt.Printf("  %s  %s  %s\n", bold(p.ID), envTag(p.Environment, p.Production), bold(safe(p.Title)))
	fmt.Printf("    fixes %d finding(s): %s\n", len(p.FindingsAddressed), dim(strings.Join(p.FindingsAddressed, ", ")))
	if len(p.PartiallyMitigated) > 0 {
		fmt.Printf("    %s %d finding(s), does not close them: %s\n", yellow("partially mitigates"), len(p.PartiallyMitigated), dim(strings.Join(p.PartiallyMitigated, ", ")))
	}
	for _, op := range p.Operations {
		mark := "  manual "
		if op.Automatic {
			mark = green("  change ")
		}
		fmt.Printf("  %s %s %s\n", mark, safe(op.Description), dim(diffLine(op)))
	}
	for _, im := range p.Impact {
		if im.Breaks {
			fmt.Printf("    %s %s:%d — %s\n", yellow("⚠ will break"), im.File, im.Line, safe(im.Message))
		}
	}
	if p.ExperimentWarning != "" {
		fmt.Printf("    %s %s\n", red("⚠ experiment"), safe(p.ExperimentWarning))
	}
}

func diffLine(op model.Operation) string {
	if len(op.Body) == 0 {
		return ""
	}
	var parts []string
	keys := make([]string, 0, len(op.Body))
	for k := range op.Body {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s: %v → %v", k, op.Before[k], op.Body[k]))
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

func cmdApprove(ctx context.Context, args []string) error {
	fs, c := newFlags("approve")
	confirm := fs.String("confirm", "", "type the exact environment name (required for production)")
	contaminate := fs.String("contaminate", "", "type contaminate-experiment when the plan touches a running experiment")
	by := fs.String("by", currentUser(), "approver name for the audit log")
	id, rest := splitID(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if id == "" {
		return errors.New("usage: gatecrasher approve <plan_id> [--confirm <env>]")
	}
	a, err := load(c)
	if err != nil {
		return err
	}
	rec, err := a.Approve(id, *by, "cli", *confirm, *contaminate)
	if err != nil {
		return err
	}
	fmt.Printf("  %s approved by %s until %s (hash %s…)\n", bold(rec.Plan.ID), *by,
		rec.Approval.ExpiresAt.Local().Format("15:04"), rec.Plan.Hash[:12])
	return nil
}

func cmdReject(ctx context.Context, args []string) error {
	fs, c := newFlags("reject")
	reason := fs.String("reason", "rejected from CLI", "reason for the audit log")
	id, rest := splitID(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	a, err := load(c)
	if err != nil {
		return err
	}
	_, err = a.Reject(id, currentUser(), *reason)
	return err
}

func cmdApply(ctx context.Context, args []string) error {
	fs, c := newFlags("apply")
	id, rest := splitID(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	a, err := load(c)
	if err != nil {
		return err
	}
	rec, err := a.Apply(ctx, id)
	if err != nil {
		return err
	}
	fmt.Printf("  %s applied; live in %.1fs\n", bold(rec.Plan.ID), float64(rec.TookMS)/1000)
	return nil
}

func cmdVerify(ctx context.Context, args []string) error {
	fs, c := newFlags("verify")
	id, rest := splitID(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	a, err := load(c)
	if err != nil {
		return err
	}
	rec, err := a.Verify(ctx, id, currentUser())
	if err != nil {
		return err
	}
	printVerify(rec.Verify, c.json)
	if !verify.AllBlocked(rec.Verify) {
		return findingsErr{len(rec.Verify)}
	}
	return nil
}

func printVerify(rows []model.VerifyRow, asJSON bool) {
	if asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(rows)
		return
	}
	for _, r := range rows {
		after := red(string(r.After))
		switch r.After {
		case model.StatusBlocked:
			after = green(string(r.After))
		case model.StatusHidden:
			after = yellow(string(r.After) + " (still open)")
		}
		fmt.Printf("  %s  %s → %s  %s\n", dim(r.FindingID), r.Before, after, safe(r.Title))
		fmt.Printf("      %s\n", dim(safe(r.Proof)))
	}
	if n := verify.StillOpen(rows); n > 0 {
		fmt.Printf("  %s\n", yellow(fmt.Sprintf("%d finding(s) still open after this plan", n)))
	}
}

func cmdRollback(ctx context.Context, args []string) error {
	fs, c := newFlags("rollback")
	id, rest := splitID(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	a, err := load(c)
	if err != nil {
		return err
	}
	rec, err := a.Rollback(ctx, id, currentUser())
	if err != nil {
		return err
	}
	fmt.Printf("  %s rolled back (state: %s)\n", bold(rec.Plan.ID), rec.State)
	return nil
}

// cmdFixAll walks every pending plan: show the card, ask a human to type
// the environment name, apply, then verify. Nothing is auto-approved.
func cmdFixAll(ctx context.Context, args []string) error {
	fs, c := newFlags("fix-all")
	in := bufio.NewReader(os.Stdin)
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := load(c)
	if err != nil {
		return err
	}
	recs, err := pendingPlans(a)
	if err != nil {
		return err
	}
	if len(recs) == 0 {
		if recs, err = a.MakePlans(ctx, "latest", ""); err != nil {
			return err
		}
	}
	var applied []string
	for _, rec := range recs {
		if !hasAutomatic(rec.Plan) {
			printPlan(rec)
			fmt.Println(dim("    guidance only (PR draft / manual step) — nothing to apply"))
			continue
		}
		printPlan(rec)
		fmt.Printf("    type %s to approve, or press Enter to skip: ", bold(rec.Plan.Environment))
		typed, _ := in.ReadString('\n')
		typed = strings.TrimSpace(typed)
		if typed == "" {
			fmt.Println(dim("    skipped"))
			continue
		}
		contaminate := ""
		if rec.Plan.ExperimentWarning != "" {
			fmt.Printf("    type %s to accept the experiment impact: ", fixes.ContaminateToken)
			contaminate, _ = in.ReadString('\n')
			contaminate = strings.TrimSpace(contaminate)
		}
		if _, err := a.Approve(rec.Plan.ID, currentUser(), "cli", typed, contaminate); err != nil {
			fmt.Println("    " + red(safe(err.Error())))
			continue
		}
		done, err := a.Apply(ctx, rec.Plan.ID)
		if err != nil {
			fmt.Println("    " + red(safe(err.Error())))
			continue
		}
		fmt.Printf("    %s live in %.1fs\n", green("applied"), float64(done.TookMS)/1000)
		applied = append(applied, rec.Plan.ID)
	}
	allBlocked := true
	for _, id := range applied {
		rec, err := a.Verify(ctx, id, currentUser())
		if err != nil {
			return err
		}
		fmt.Println()
		fmt.Println(bold("  re-attack " + id))
		printVerify(rec.Verify, false)
		allBlocked = allBlocked && verify.AllBlocked(rec.Verify)
	}
	if len(applied) > 0 && !allBlocked {
		return findingsErr{1}
	}
	return nil
}

// pendingPlans returns plans still waiting for a decision, so fix-all reuses
// plans built earlier (CLI or web UI) instead of duplicating them.
func pendingPlans(a *app.App) ([]*model.PlanRecord, error) {
	all, err := a.Store.List()
	if err != nil {
		return nil, err
	}
	var out []*model.PlanRecord
	for _, r := range all {
		if r.State == model.PlanPending {
			out = append(out, r)
		}
	}
	return out, nil
}

func hasAutomatic(p model.Plan) bool {
	for _, op := range p.Operations {
		if op.Automatic {
			return true
		}
	}
	return false
}

func cmdReport(ctx context.Context, args []string) error {
	fs, c := newFlags("report")
	format := fs.String("format", "html", "html|md|json|sarif")
	id := fs.String("id", "latest", "report id")
	out := fs.String("o", "", "write to file instead of stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := load(c)
	if err != nil {
		return err
	}
	r, err := a.LoadReport(*id)
	if err != nil {
		return err
	}
	var w io.Writer = os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	switch *format {
	case "html":
		return report.WriteHTML(w, r)
	case "md", "markdown":
		return report.WriteMarkdown(w, r)
	case "json":
		if c.json {
			return report.WriteCompactJSON(w, r)
		}
		return report.WriteJSON(w, r)
	case "sarif":
		return report.WriteSARIF(w, r)
	}
	return fmt.Errorf("unknown format %q", *format)
}

func cmdParity(ctx context.Context, args []string) error {
	fs, c := newFlags("parity")
	env := fs.String("env", "", "environment")
	n := fs.Int("n", 1000, "random identities to compare")
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := load(c)
	if err != nil {
		return err
	}
	if *env == "" {
		*env = a.Cfg.Flagsmith.Environments[len(a.Cfg.Flagsmith.Environments)-1]
	}
	e, err := a.Environment(ctx, *env)
	if err != nil {
		return err
	}
	p, _, _ := a.Project(ctx)
	segs, err := a.Admin.Segments(ctx, p.ID)
	if err != nil {
		return err
	}
	doc, err := a.Admin.EnvironmentDocument(ctx, e.APIKey)
	if err != nil {
		return err
	}
	eng, err := flagsmith.NewEngine(doc)
	if err != nil {
		return err
	}
	fresh, err := a.Admin.Environment(ctx, e.APIKey)
	if err != nil {
		return err
	}
	feats, err := a.Admin.Features(ctx, p.ID)
	if err != nil {
		return err
	}
	start := time.Now()
	res, err := parity.RunLive(ctx, eng, flagsmith.NewSDK(a.HTTP, a.Cfg.Flagsmith.APIURL, e.APIKey), *n, segs, parity.LiveFor(*fresh, feats))
	if err != nil {
		return err
	}
	if c.json {
		return json.NewEncoder(os.Stdout).Encode(res)
	}
	fmt.Printf("  engine vs live: %s agree (%d errors) in %.1fs — %s\n", bold(fmt.Sprintf("%d of %d", res.Agreed, res.Checked)),
		res.Errors, time.Since(start).Seconds(), app.EngineVersion())
	for i, m := range res.Mismatches {
		if i == 10 {
			break
		}
		fmt.Printf("    mismatch: %s\n", safe(fmt.Sprintf("%+v", m)))
	}
	if res.Agreed != res.Checked {
		return findingsErr{res.Checked - res.Agreed}
	}
	return nil
}

func cmdAuditLog(ctx context.Context, args []string) error {
	fs, c := newFlags("audit-log")
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := load(c)
	if err != nil {
		return err
	}
	es, err := a.Log.Entries()
	if err != nil {
		return err
	}
	ok, broken, err := a.Log.Verify()
	if c.json {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"valid": ok && err == nil, "broken_at": broken, "entries": len(es)})
	}
	for _, e := range es {
		fmt.Printf("  %4d %s %-12s %-10s %s %s\n", e.Seq, dim(e.Time), e.Action, e.Actor, e.PlanID, dim(e.Hash[:12]))
	}
	if ok && err == nil {
		fmt.Println(green(fmt.Sprintf("  chain valid: %d entries", len(es))))
		return nil
	}
	return fmt.Errorf("audit chain BROKEN at entry %d", broken)
}

func splitID(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

func currentUser() string {
	for _, k := range []string{"GATECRASHER_USER", "USER", "USERNAME"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return "cli"
}

func nonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
