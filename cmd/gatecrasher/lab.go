package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/lab"
)

// cmdLab manages the self-hosted Flagsmith lab: official images via Docker
// Compose plus the deliberately vulnerable "Acme Shop" seed.
func cmdLab(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: gatecrasher lab up|seed|reset|down|nuke")
	}
	root, err := lab.FindRepoRoot()
	if err != nil {
		return err
	}
	compose := filepath.Join(root, "lab", "compose.yaml")
	logf := func(format string, a ...any) { fmt.Fprintf(os.Stderr, dim("lab       ")+format+"\n", a...) }
	switch args[0] {
	case "up":
		start := time.Now()
		if err := docker(ctx, "compose", "-f", compose, "up", "-d", "--wait"); err != nil {
			return err
		}
		fmt.Printf("  Flagsmith is up at http://localhost:8000 (%.0fs). Next: gatecrasher lab seed\n", time.Since(start).Seconds())
	case "seed", "reset":
		opts := lab.Options{RepoRoot: root, Log: logf}
		var st *lab.State
		if args[0] == "seed" {
			st, err = lab.Seed(ctx, opts)
		} else {
			st, err = lab.Reset(ctx, opts)
		}
		if err != nil {
			return err
		}
		fmt.Printf("  Acme Shop lab %sed: %d change(s). Keys are in .env (git-ignored).\n", args[0], len(st.Changes))
		fmt.Println(dim("  next: go run ./lab/shop   then   gatecrasher audit"))
	case "down":
		return docker(ctx, "compose", "-f", compose, "down")
	case "nuke":
		return docker(ctx, "compose", "-f", compose, "down", "-v")
	default:
		return fmt.Errorf("unknown lab command %q (want up|seed|reset|down|nuke)", args[0])
	}
	return nil
}

func docker(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker %s: %w", args[0], err)
	}
	return nil
}
