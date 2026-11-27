// Command shop serves the fictional Acme Shop storefront, the demo target of
// Gatecrasher's lab. It loads the Production client-side key into app.js at
// serve time (so nothing is committed) and exposes /api/checkout-config, which
// reads payment_config with the server-side key and returns only non-secret
// fields.
package main

import (
	"bufio"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

//go:embed index.html app.js
var assets embed.FS

// shop holds the lab credentials the storefront needs.
type shop struct {
	apiURL    string
	clientKey string
	serverKey string
	http      *http.Client
}

func main() {
	env := loadEnv()
	apiURL := env["GATECRASHER_API_URL"]
	if apiURL == "" {
		apiURL = "http://localhost:8000/api/v1/"
	}
	s := &shop{
		apiURL:    strings.TrimRight(apiURL, "/") + "/",
		clientKey: pair(env["GATECRASHER_CLIENT_KEYS"], "Production"),
		serverKey: pair(env["GATECRASHER_SERVER_KEYS"], "Production"),
		http:      &http.Client{Timeout: 10 * time.Second},
	}
	if s.clientKey == "" || s.serverKey == "" {
		log.Fatal("Production keys missing from .env: run `go run ./lab/seed` first")
	}
	addr := ":3030"
	if v := os.Getenv("SHOP_ADDR"); v != "" {
		addr = v
	}
	log.Printf("Acme Shop on http://localhost%s (Flagsmith %s)", addr, s.apiURL)
	log.Fatal(http.ListenAndServe(addr, s.routes()))
}

func (s *shop) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.serveAsset("index.html", "text/html; charset=utf-8", false))
	mux.HandleFunc("GET /app.js", s.serveAsset("app.js", "text/javascript; charset=utf-8", true))
	mux.HandleFunc("GET /api/checkout-config", s.checkoutConfig)
	return mux
}

// serveAsset serves an embedded file, optionally substituting the lab keys
// in place (one token per line, so line numbers never shift).
func (s *shop) serveAsset(name, contentType string, template bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, err := assets.ReadFile(name)
		if err != nil {
			http.Error(w, "missing asset", http.StatusInternalServerError)
			return
		}
		if template {
			raw = []byte(strings.NewReplacer(
				"__FLAGSMITH_CLIENT_KEY__", s.clientKey,
				"__FLAGSMITH_API_URL__", s.apiURL,
			).Replace(string(raw)))
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(raw)
	}
}

// checkoutConfig returns the non-secret part of payment_config, read with the
// server-side key. It keeps working once payment_config is server-side only.
func (s *shop) checkoutConfig(w http.ResponseWriter, r *http.Request) {
	value, err := s.serverFlagValue(r.Context(), "payment_config")
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	var cfg struct {
		Provider string `json:"provider"`
		Webhook  string `json:"webhook"`
	}
	if err := json.Unmarshal([]byte(value), &cfg); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "payment_config is not valid JSON"})
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

// serverFlagValue reads one flag value through the SDK flags endpoint using
// the server-side key, which can see server-key-only flags.
func (s *shop) serverFlagValue(ctx context.Context, feature string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.apiURL+"flags/", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Environment-Key", s.serverKey)
	resp, err := s.http.Do(req)
	if err != nil {
		return "", errors.New("Flagsmith is unreachable")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Flagsmith answered HTTP %d", resp.StatusCode)
	}
	var flags []struct {
		Feature struct {
			Name string `json:"name"`
		} `json:"feature"`
		Value any `json:"feature_state_value"`
	}
	if err := json.Unmarshal(body, &flags); err != nil {
		return "", errors.New("unexpected Flagsmith response")
	}
	for _, f := range flags {
		if f.Feature.Name == feature {
			if v, ok := f.Value.(string); ok {
				return v, nil
			}
		}
	}
	return "", fmt.Errorf("flag %s not visible to the server-side key", feature)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// pair extracts one value from a "Name=value,Name=value" list.
func pair(list, name string) string {
	for _, part := range strings.Split(list, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.TrimSpace(k) == name {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// loadEnv reads KEY=VALUE lines from the .env at or above the working directory.
func loadEnv() map[string]string {
	out := map[string]string{}
	dir, err := os.Getwd()
	if err != nil {
		return out
	}
	for {
		if f, err := os.Open(filepath.Join(dir, ".env")); err == nil {
			defer f.Close()
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if k, v, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(line, "#") {
					out[strings.TrimSpace(k)] = strings.TrimSpace(v)
				}
			}
			return out
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return out
		}
		dir = parent
	}
}
