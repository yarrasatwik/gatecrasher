// Package watch implements Gatecrasher's watch mode (spec §8.12): it
// registers a Flagsmith organisation webhook, verifies and debounces the
// change events Flagsmith sends, re-checks only what changed through an
// injected Rechecker, and raises alerts for findings that are new.
package watch

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

// SignatureHeader is the header Flagsmith puts the webhook signature in.
//
// Verified against Flagsmith's open-source code (api/core/constants.py,
// api/core/signing.py and api/webhooks/webhooks.py): when a webhook has a
// secret, Flagsmith serialises the payload with json.dumps(sort_keys=True),
// sends exactly those bytes as the request body, and sets
// "X-Flagsmith-Signature" to the lowercase hex of
// HMAC-SHA256(key=secret, message=body). There is no "sha256=" prefix and no
// timestamp. Webhooks without a secret are sent unsigned, which is why this
// package refuses to run without one.
const SignatureHeader = "X-Flagsmith-Signature"

// MaxBodyBytes caps a webhook request body (1 MiB).
const MaxBodyBytes = 1 << 20

// AdminDoer is the part of flagsmith.Admin that webhook registration needs.
type AdminDoer interface {
	Do(ctx context.Context, method, path string, body, out any) error
}

// Registration describes an organisation webhook created by Register.
type Registration struct {
	OrganisationID int
	HookID         int
	URL            string
	// Secret is the HMAC key the receiver must use. It is registered with
	// the redactor and must never be logged.
	Secret string
}

// GenerateSecret returns a random 256-bit webhook secret as hex.
func GenerateSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate webhook secret: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Register creates an enabled Flagsmith organisation webhook that calls url.
// If secret is empty a random one is generated; the secret actually
// registered is returned in the Registration.
func Register(ctx context.Context, admin AdminDoer, orgID int, url, secret string) (*Registration, error) {
	if strings.TrimSpace(url) == "" {
		return nil, fmt.Errorf("register webhook: empty receiver URL")
	}
	if secret == "" {
		var err error
		if secret, err = GenerateSecret(); err != nil {
			return nil, err
		}
	}
	redact.Register(secret, "WEBHOOK_SECRET")
	var out struct {
		ID int `json:"id"`
	}
	body := map[string]any{"url": url, "enabled": true, "secret": secret}
	if err := admin.Do(ctx, "POST", fmt.Sprintf("organisations/%d/webhooks/", orgID), body, &out); err != nil {
		return nil, fmt.Errorf("register webhook: %w", err)
	}
	return &Registration{OrganisationID: orgID, HookID: out.ID, URL: url, Secret: secret}, nil
}

// Remove deletes the webhook created by Register.
func (r *Registration) Remove(ctx context.Context, admin AdminDoer) error {
	path := fmt.Sprintf("organisations/%d/webhooks/%d/", r.OrganisationID, r.HookID)
	if err := admin.Do(ctx, "DELETE", path, nil, nil); err != nil {
		return fmt.Errorf("remove webhook %d: %w", r.HookID, err)
	}
	return nil
}

// Sign returns the signature Flagsmith would send for body.
func Sign(secret string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// VerifySignature reports whether header is the valid hex HMAC-SHA256 of
// body under secret. It compares in constant time and returns false for an
// empty secret, an empty header or malformed hex.
func VerifySignature(secret string, body []byte, header string) bool {
	if secret == "" {
		return false
	}
	got, err := hex.DecodeString(strings.TrimSpace(header))
	if err != nil || len(got) == 0 {
		return false
	}
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return hmac.Equal(got, m.Sum(nil))
}
