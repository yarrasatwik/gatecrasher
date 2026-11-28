package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/app"
	"github.com/yarrasatwik/gatecrasher/internal/fixes"
	"github.com/yarrasatwik/gatecrasher/internal/server"
)

func cmdServe(ctx context.Context, args []string) error {
	fs, c := newFlags("serve")
	addr := fs.String("addr", server.DefaultAddr, "listen address (loopback by default)")
	withWatch := fs.Bool("watch", false, "also run watch mode (registers a Flagsmith webhook)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := loadForWrites(c)
	if err != nil {
		return err
	}
	if note := keySplitNote(a); note != "" {
		fmt.Fprintln(os.Stderr, note)
	}
	opts := server.Options{
		Backend: &app.Backend{A: a, Audit: app.AuditOptions{Outside: true, Inside: a.InsideView(), ParitySamples: a.Cfg.ParitySamples(), Explain: true}},
		Addr:    *addr,
		// Web approvals are recorded under the OS account running the server.
		Operator: fixes.OSUser(),
		Files:    http.StripPrefix("/files/", http.FileServer(http.Dir(a.ReportDir()))),
	}
	if *withWatch {
		w, err := a.StartWatch(ctx, a.Cfg.Watch.PublicURL, "http://"+*addr)
		if err != nil {
			return err
		}
		defer closeWatch(w)
		opts.Webhook = w.Handler()
		// Flagsmith delivers to watch.public_url, which points at watch.listen,
		// so that address must be served too, not just the web UI's.
		if l := a.Cfg.Watch.Listen; l != "" && l != *addr {
			hs := webhookServer(l, w.Handler())
			stop := shutdownOnDone(ctx, hs)
			defer stop()
			errc := make(chan error, 1)
			go func() { errc <- hs.ListenAndServe() }()
			select {
			case err := <-errc:
				return fmt.Errorf("watch listener %s: %w", l, err)
			case <-time.After(150 * time.Millisecond):
			}
			fmt.Fprintf(os.Stderr, "%s     listening on %s for Flagsmith webhooks\n", green("watch"), l)
		}
		fmt.Fprintln(os.Stderr, green("watch")+"     Flagsmith webhook registered → "+a.Cfg.Watch.PublicURL)
	}
	srv, err := server.New(opts)
	if err != nil {
		return err
	}
	defer srv.Close()
	fmt.Fprintf(os.Stderr, "%s     http://%s  (Ctrl+C to stop)\n", green("serve"), *addr)
	if err := srv.ListenAndServe(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// keySplitNote is the one-line note `serve` prints when applies and
// rollbacks use the same key as audits. It is empty when the keys are split
// or no org key is configured at all.
func keySplitNote(a *app.App) string {
	if a.KeysSplit() || !a.InsideView() {
		return ""
	}
	return yellow("note") + "      GATECRASHER_WRITE_API_KEY is not set, so applies and rollbacks use GATECRASHER_ORG_API_KEY: the keys are not split."
}

func cmdWatch(ctx context.Context, args []string) error {
	fs, c := newFlags("watch")
	listen := fs.String("listen", "", "webhook listen address (default watch.listen)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := load(c)
	if err != nil {
		return err
	}
	if *listen == "" {
		*listen = a.Cfg.Watch.Listen
	}
	w, err := a.StartWatch(ctx, a.Cfg.Watch.PublicURL, "http://"+server.DefaultAddr)
	if err != nil {
		return err
	}
	defer closeWatch(w)
	hs := webhookServer(*listen, w.Handler())
	stop := shutdownOnDone(ctx, hs)
	defer stop()
	ch, unsub := w.Receiver.Subscribe()
	defer unsub()
	go func() {
		for al := range ch {
			if al.Error != "" {
				fmt.Printf("%s %s re-check failed: %s\n", yellow("alert"), al.Change.Kind, safe(al.Error))
				continue
			}
			fmt.Printf("%s %s %s/%s → %d new finding(s) in %dms\n", red("ALERT"), al.Change.Kind,
				nonEmpty(al.Change.Feature, "-"), nonEmpty(al.Change.Segment, "-"), len(al.Findings), al.LatencyMS)
			for _, f := range al.Findings {
				fmt.Printf("      %s %s\n", sevTag(f.Severity), safe(f.Title))
			}
			if al.ReviewURL != "" {
				fmt.Println(dim("      review fix: " + al.ReviewURL))
			}
		}
	}()
	fmt.Fprintf(os.Stderr, "%s     listening on %s; webhook registered → %s (Ctrl+C removes it)\n", green("watch"), *listen, a.Cfg.Watch.PublicURL)
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// webhookServer serves the watch receiver at /webhook and at the web UI's
// webhook path, so either form of watch.public_url reaches it.
func webhookServer(addr string, h http.Handler) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/webhook", h)
	mux.Handle(server.WebhookPath, h)
	return &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
}

// shutdownOnDone shuts hs down when ctx ends; the returned func stops it too.
func shutdownOnDone(ctx context.Context, hs *http.Server) func() {
	done := make(chan struct{})
	var once sync.Once
	go func() {
		select {
		case <-ctx.Done():
		case <-done:
		}
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}()
	return func() { once.Do(func() { close(done) }) }
}

func closeWatch(w *app.Watcher) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := w.Close(ctx); err != nil {
		fmt.Fprintln(os.Stderr, yellow("warning: ")+"could not remove the Flagsmith webhook: "+safe(err.Error()))
	} else {
		fmt.Fprintln(os.Stderr, dim("watch     Flagsmith webhook removed"))
	}
}
