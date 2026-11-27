package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/app"
	"github.com/yarrasatwik/gatecrasher/internal/server"
)

func cmdServe(ctx context.Context, args []string) error {
	fs, c := newFlags("serve")
	addr := fs.String("addr", server.DefaultAddr, "listen address (loopback by default)")
	withWatch := fs.Bool("watch", false, "also run watch mode (registers a Flagsmith webhook)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := load(c)
	if err != nil {
		return err
	}
	opts := server.Options{
		Backend: &app.Backend{A: a, Audit: app.AuditOptions{Outside: true, Inside: a.InsideView(), ParitySamples: 200, Explain: true}},
		Addr:    *addr,
		Files:   http.StripPrefix("/files/", http.FileServer(http.Dir(a.ReportDir()))),
	}
	if *withWatch {
		w, err := a.StartWatch(ctx, a.Cfg.Watch.PublicURL, "http://"+*addr)
		if err != nil {
			return err
		}
		defer closeWatch(w)
		opts.Webhook = w.Handler()
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
	mux := http.NewServeMux()
	mux.Handle("/webhook", w.Handler())
	mux.Handle(server.WebhookPath, w.Handler())
	hs := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}()
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

func closeWatch(w *app.Watcher) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := w.Close(ctx); err != nil {
		fmt.Fprintln(os.Stderr, yellow("warning: ")+"could not remove the Flagsmith webhook: "+safe(err.Error()))
	} else {
		fmt.Fprintln(os.Stderr, dim("watch     Flagsmith webhook removed"))
	}
}
