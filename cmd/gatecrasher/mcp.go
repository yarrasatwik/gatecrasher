package main

import (
	"context"
	"os"

	"github.com/yarrasatwik/gatecrasher/internal/app"
	"github.com/yarrasatwik/gatecrasher/internal/mcp"
	"github.com/yarrasatwik/gatecrasher/internal/model"
)

// mcpBackend adapts the App to the read-only MCP server.
type mcpBackend struct{ a *app.App }

func (b mcpBackend) Audit(ctx context.Context, env string) (*model.Report, error) {
	r, err := b.a.Audit(ctx, app.AuditOptions{Environment: env, Outside: b.a.Cfg.TargetURL != "", Inside: b.a.InsideView(), Explain: true})
	if err != nil {
		return nil, err
	}
	_, err = b.a.SaveReport(r)
	return r, err
}

func (b mcpBackend) Latest() (*model.Report, error) { return b.a.LoadReport("latest") }

// cmdMCP serves Gatecrasher's read-only tools to coding agents over stdio:
//
//	claude mcp add gatecrasher -- gatecrasher mcp -config /path/to/gatecrasher.yaml
func cmdMCP(ctx context.Context, args []string) error {
	fs, c := newFlags("mcp")
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := load(c)
	if err != nil {
		return err
	}
	return mcp.New(mcpBackend{a}, app.Version).Serve(ctx, os.Stdin, os.Stdout)
}
