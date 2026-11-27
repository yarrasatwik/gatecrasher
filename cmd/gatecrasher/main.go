// Command gatecrasher audits your own Flagsmith setup the way an outsider
// would, maps every flag value a user can reach, and — only with a human's
// approval — fixes each hole and proves it is closed.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// Exit codes (spec §8.15).
const (
	exitOK       = 0
	exitFindings = 1
	exitError    = 2
)

type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string) error
}

var commands []command

func init() {
	commands = []command{
		{"lab", "self-hosted Flagsmith lab: up | seed | reset | down | nuke", cmdLab},
		{"audit", "recon + attack + map + report (read-only)", cmdAudit},
		{"recon", "outside view only: key from bundle, public flags, classification", cmdRecon},
		{"map", "inside view only: settings, engine reachability, live cross-check", cmdMap},
		{"plan", "build fix plans from the latest report", cmdPlan},
		{"plans", "list fix plans and their state", cmdPlans},
		{"approve", "approve one plan (Production needs --confirm <env name>)", cmdApprove},
		{"reject", "reject one plan", cmdReject},
		{"apply", "apply an approved plan (re-checks live state first)", cmdApply},
		{"verify", "re-run the checks behind a plan: before/after", cmdVerify},
		{"rollback", "restore a plan's before-snapshot (safe to repeat)", cmdRollback},
		{"fix-all", "plan → approve (interactive) → apply → verify, for every open finding", cmdFixAll},
		{"report", "re-render the latest report: --format html|md|json|sarif", cmdReport},
		{"parity", "engine vs live agreement over N random identities", cmdParity},
		{"watch", "register a signed Flagsmith webhook and alert on new holes", cmdWatch},
		{"serve", "web UI on 127.0.0.1:8787 (with optional --watch)", cmdServe},
		{"ci", "inside-view audit for CI: SARIF + job summary, exit 1 at --fail-on", cmdCI},
		{"audit-log", "show and verify the hash-chained audit log", cmdAuditLog},
		{"version", "print version", cmdVersion},
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:]))
}

func run(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		usage()
		return exitOK
	}
	for _, c := range commands {
		if c.name == args[0] {
			err := c.run(ctx, args[1:])
			var fe findingsErr
			switch {
			case err == nil:
				return exitOK
			case errors.As(err, &fe):
				return exitFindings
			default:
				fmt.Fprintln(os.Stderr, red("error: ")+safe(err.Error()))
				return exitError
			}
		}
	}
	fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
	usage()
	return exitError
}

func usage() {
	fmt.Println(bold("gatecrasher") + " — what if your users changed plan=silver to plan=gold?")
	fmt.Println()
	fmt.Println("Usage: gatecrasher <command> [flags]   (every command accepts -config and --json)")
	fmt.Println()
	for _, c := range commands {
		fmt.Printf("  %-10s %s\n", c.name, c.summary)
	}
	fmt.Println()
	fmt.Println("Exit codes: 0 no findings at/above threshold · 1 findings · 2 config or API error")
}

// findingsErr signals exit code 1 without printing an error.
type findingsErr struct{ n int }

func (e findingsErr) Error() string { return fmt.Sprintf("%d findings at or above threshold", e.n) }
