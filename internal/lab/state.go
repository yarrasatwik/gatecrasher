package lab

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

// State is everything the seed learned or generated about the lab. It is
// persisted to the git-ignored lab/.state.json so later runs are idempotent
// and keep the same generated credentials.
type State struct {
	APIURL        string              `json:"api_url"`
	AdminEmail    string              `json:"admin_email"`
	AdminPassword string              `json:"admin_password"`
	OrgID         int                 `json:"org_id"`
	OrgAPIKey     string              `json:"org_api_key"`
	ProjectID     int                 `json:"project_id"`
	PaymentSecret string              `json:"payment_secret"`
	Environments  map[string]EnvState `json:"environments"`
	Changes       []string            `json:"-"` // what this run changed
	order         []string
}

// EnvState holds one environment's identifiers and keys.
type EnvState struct {
	ID        int    `json:"id"`
	ClientKey string `json:"client_key"`
	ServerKey string `json:"server_key"`
}

// LoadState reads a persisted state file. A missing file yields (nil, nil).
func LoadState(path string) (*State, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read lab state: %w", err)
	}
	var s State
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("parse lab state %s: %w", path, err)
	}
	if s.Environments == nil {
		s.Environments = map[string]EnvState{}
	}
	return &s, nil
}

// Save writes the state file with owner-only permissions.
func (s *State) Save(path string) error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}

// registerSecrets makes every credential in the state redactable.
func (s *State) registerSecrets() {
	redact.Register(s.AdminPassword, "LAB_PASSWORD")
	redact.Register(s.OrgAPIKey, "ORG_API_KEY")
	redact.Register(s.PaymentSecret, "SECRET")
	for _, e := range s.Environments {
		redact.Register(e.ClientKey, "CLIENT_KEY")
		redact.Register(e.ServerKey, "SERVER_KEY")
	}
}

// EnvFile renders the .env content Gatecrasher reads. Environment names are
// emitted in declaration order.
func (s *State) EnvFile() string {
	names := s.order
	if len(names) == 0 {
		for n := range s.Environments {
			names = append(names, n)
		}
		sort.Strings(names)
	}
	var servers, clients []string
	for _, n := range names {
		e := s.Environments[n]
		servers = append(servers, n+"="+e.ServerKey)
		clients = append(clients, n+"="+e.ClientKey)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Written by `go run ./lab/seed`. Lab-only credentials; never commit.\n")
	fmt.Fprintf(&b, "GATECRASHER_API_URL=%s\n", s.APIURL)
	fmt.Fprintf(&b, "GATECRASHER_ORG_API_KEY=%s\n", s.OrgAPIKey)
	fmt.Fprintf(&b, "GATECRASHER_SERVER_KEYS=%s\n", strings.Join(servers, ","))
	fmt.Fprintf(&b, "GATECRASHER_CLIENT_KEYS=%s\n", strings.Join(clients, ","))
	return b.String()
}

// randomHex returns n random bytes as 2n hex characters.
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand unavailable: %v", err))
	}
	return hex.EncodeToString(b)
}

// newPaymentSecret builds the generated secret: acme_live_ + 32 hex characters.
func newPaymentSecret() string { return "acme_live_" + randomHex(16) }
