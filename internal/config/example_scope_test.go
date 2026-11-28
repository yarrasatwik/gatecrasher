package config

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/yarrasatwik/gatecrasher/internal/scope"
)

// The shipped lab config must pin its scope to the lab's ports. A bare
// "localhost" would put every other service on the machine in scope.
func TestExampleConfigScopeIsPinnedToLabPorts(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "gatecrasher.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		t.Fatal(err)
	}
	entries := append(append([]string{}, c.AllowedDomains...), c.Flagsmith.AllowedAPIHosts...)
	if len(entries) == 0 {
		t.Fatal("example config has no scope entries")
	}
	for _, e := range entries {
		if _, port, err := net.SplitHostPort(e); err != nil || port == "" {
			t.Errorf("scope entry %q has no port: pin it as host:port", e)
		}
	}
	lock, err := scope.New(c.AllowedDomains, c.Flagsmith.AllowedAPIHosts)
	if err != nil {
		t.Fatal(err)
	}
	for _, ok := range []string{c.TargetURL, c.Flagsmith.APIURL, "http://localhost:3030/app.js", "http://localhost:8000/api/v1/flags/"} {
		if err := lock.CheckURL(ok); err != nil {
			t.Errorf("%s must be in scope: %v", ok, err)
		}
	}
	for _, out := range []string{
		"http://localhost/",           // port 80
		"https://localhost/",          // port 443
		"http://localhost:5432/",      // the lab's own Postgres
		"http://localhost:8787/",      // Gatecrasher's web UI
		"http://localhost:8788/",      // Gatecrasher's webhook receiver
		"http://localhost:9200/_cat",  // anything else on this machine
		"http://127.0.0.1:3030/",      // a different host name
		"http://localhost:30300/",     // not a prefix match
		"http://localhost.evil.test/", // not a suffix match
	} {
		if err := lock.CheckURL(out); err == nil {
			t.Errorf("%s must be out of scope", out)
		}
	}
}
