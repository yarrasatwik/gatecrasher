// Command seed builds (or resets) the vulnerable Acme Shop lab in a running
// self-hosted Flagsmith. It never prints key values.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/lab"
)

func main() {
	reset := flag.Bool("reset", false, "restore every planted vulnerability (lab must already be seeded)")
	apiURL := flag.String("api", lab.DefaultAPIURL, "Flagsmith API base URL")
	data := flag.String("data", "", "seed data file (default lab/seed_data.yaml)")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	opts := lab.Options{
		APIURL:   *apiURL,
		DataPath: *data,
		Log:      func(format string, args ...any) { fmt.Printf(format+"\n", args...) },
	}
	run := lab.Seed
	verb := "seeded"
	if *reset {
		run, verb = lab.Reset, "reset"
	}
	state, err := run(ctx, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	took, err := lab.WaitLive(ctx, state, *apiURL, 90*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Printf("lab %s: %d change(s), live after %.1fs; wrote .env and lab/.state.json (keys not shown)\n", verb, len(state.Changes), took.Seconds())
}
