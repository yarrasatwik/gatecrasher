// Package verify re-attacks the findings a plan addressed and produces the
// before/after table (spec §8.11).
//
// Every finding type re-runs the mechanism that originally proved it, not a
// visibility check. A flag that merely disappeared from client SDK responses
// is not fixed while a server can still be steered the same way; that state
// is reported as HIDDEN and stays open.
package verify

import (
	"context"
	"errors"
	"fmt"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

// RerollSearch is how many identifiers a re-roll re-run tries on the server
// path before it concludes that no identifier reaches the exploited state.
const RerollSearch = 2000

// RerollIdentifier is the n-th identifier a re-roll re-run tries.
func RerollIdentifier(n int) string { return fmt.Sprintf("gc-probe-verify-%d", n) }

// Settings are the environment settings a re-run reads fresh.
type Settings struct {
	AllowClientTraits bool
	HideSensitiveData bool
}

// Target is the live Flagsmith access a re-run needs. Flag maps are
// name → state ("on", "off", "on: value"); a flag the caller cannot see is
// absent from the map.
type Target interface {
	// Settings reads the environment settings from the Admin API.
	Settings(ctx context.Context) (Settings, error)
	// ClientFlags lists what the public client key receives without an identity.
	ClientFlags(ctx context.Context) (flags map[string]string, request string, err error)
	// ClientIdentify evaluates an identity through the client SDK path, with
	// a transient identity so nothing is stored.
	ClientIdentify(ctx context.Context, identifier string, traits map[string]string) (flags map[string]string, request string, err error)
	// ServerEvaluate evaluates the same identity the way a server-side SDK
	// does: Flagsmith's engine over the environment document, which includes
	// Server-side only flags.
	ServerEvaluate(ctx context.Context, identifier string, traits map[string]string) (map[string]string, error)
	// ReplayLookup replays the recorded read-only identity lookup behind an
	// identity leak. ok is false when the finding has no lookup to replay.
	ReplayLookup(ctx context.Context, f model.Finding) (status model.Status, proof string, ok bool, err error)
	// ClientSetsIdentifier reports whether browsers choose their own
	// identifier (the client_sets_identifier configuration).
	ClientSetsIdentifier() bool
}

// Check re-runs the original attack behind one finding against t and returns
// its status now, with a redacted proof. A check that cannot be completed
// returns UNKNOWN and an error, never a silent pass.
func Check(ctx context.Context, t Target, f model.Finding) (model.Status, string, error) {
	switch f.Type {
	case model.FSettingClientTraitsOn:
		s, err := t.Settings(ctx)
		if err != nil {
			return unknown(err)
		}
		return statusIf(s.AllowClientTraits, fmt.Sprintf("allow_client_traits=%v", s.AllowClientTraits))
	case model.FSettingSensitiveData:
		return sensitiveData(ctx, t)
	case model.FIdentityTraitLeak, model.FIdentityOverrideLeak:
		// Replay the exact read-only lookup when there is one: the public
		// endpoint can serve cached data after the setting changes.
		if st, proof, ok, err := t.ReplayLookup(ctx, f); ok && err == nil {
			return st, redact.String(proof), nil
		}
		return sensitiveData(ctx, t)
	case model.FSecretExposed, model.FInternalURL, model.FUnreleasedProduct, model.FPricingLeak, model.FPIILeak, model.FFlagNotServerOnly:
		// The attack is reading the value with the public key.
		flags, req, err := t.ClientFlags(ctx)
		if err != nil {
			return unknown(err)
		}
		_, visible := flags[f.Subject]
		return statusIf(visible, fmt.Sprintf("%s → %s visible to client key: %v", req, f.Subject, visible))
	case model.FSegmentForgeable, model.FTraitForgery:
		return forgery(ctx, t, f)
	case model.FPercentageReroll, model.FVariantReroll, model.FExperimentRigging:
		return reroll(ctx, t, f)
	}
	return unknown(fmt.Errorf("no automatic re-check for %s", f.Type))
}

func sensitiveData(ctx context.Context, t Target) (model.Status, string, error) {
	s, err := t.Settings(ctx)
	if err != nil {
		return unknown(err)
	}
	return statusIf(!s.HideSensitiveData, fmt.Sprintf("hide_sensitive_data=%v", s.HideSensitiveData))
}

// forgery replays the forged identity. When the flag is no longer served to
// client SDKs, it asks whether a server evaluating the same client-written
// traits is still steered.
func forgery(ctx context.Context, t Target, f model.Finding) (model.Status, string, error) {
	if len(f.Unlocked) == 0 {
		return unknown(errors.New("finding has no flag change to re-check"))
	}
	want := f.Unlocked[0]
	id := f.ProofID
	if id == "" {
		id = RerollIdentifier(0)
	}
	flags, req, err := t.ClientIdentify(ctx, id, f.Traits)
	if err != nil {
		return unknown(err)
	}
	if got, served := flags[want.Flag]; served {
		return statusIf(got == want.After, fmt.Sprintf("%s → %s is %s (exploited state %s)", req, want.Flag, got, want.After))
	}
	if len(f.Traits) > 0 {
		s, err := t.Settings(ctx)
		if err != nil {
			return unknown(err)
		}
		if !s.AllowClientTraits {
			return statusIf(false, fmt.Sprintf("%s → %s is not served to client SDKs and allow_client_traits=false, so clients can no longer write the traits", req, want.Flag))
		}
	}
	server, err := t.ServerEvaluate(ctx, id, f.Traits)
	if err != nil {
		return unknown(fmt.Errorf("%s is not served to client SDKs and the server path could not be evaluated: %w", want.Flag, err))
	}
	if server[want.Flag] != want.After {
		return statusIf(false, fmt.Sprintf("%s → %s is not served to client SDKs and server-side evaluation of the same input gives %s", req, want.Flag, stateOrMissing(server, want.Flag)))
	}
	return model.StatusHidden, redact.String(fmt.Sprintf(
		"%s → %s is no longer served to client SDKs, but server-side evaluation of the same client-written input still returns %s. A server that evaluates this flag for a browser-supplied identity is still steered.",
		req, want.Flag, want.After)), nil
}

// reroll repeats the re-roll attack: keep choosing identifiers until one
// lands in the exploited state. It closes only when identifiers are assigned
// on the server or no identifier reaches the state any more (the rollout is
// gone). A flag that is merely hidden from client SDKs is HIDDEN.
func reroll(ctx context.Context, t Target, f model.Finding) (model.Status, string, error) {
	if len(f.Unlocked) == 0 {
		return unknown(errors.New("finding has no flag change to re-check"))
	}
	want := f.Unlocked[0]
	if !t.ClientSetsIdentifier() {
		return statusIf(false, "identifiers are assigned on the server (client_sets_identifier: false), so a browser cannot re-roll "+want.Flag)
	}
	id := f.ProofID
	if id == "" {
		id = RerollIdentifier(0)
	}
	flags, req, err := t.ClientIdentify(ctx, id, nil)
	if err != nil {
		return unknown(err)
	}
	got, served := flags[want.Flag]
	if served && got == want.After {
		return statusIf(true, fmt.Sprintf("%s → %s is %s (exploited state %s)", req, want.Flag, got, want.After))
	}
	// The recorded identifier no longer wins (or cannot be seen): re-roll.
	hit, tried, err := searchIdentifier(ctx, t, id, want)
	if err != nil {
		if served {
			return unknown(fmt.Errorf("could not re-roll %s: %w", want.Flag, err))
		}
		return unknown(fmt.Errorf("%s is not served to client SDKs and the server path could not be evaluated: %w", want.Flag, err))
	}
	if hit == "" {
		return statusIf(false, fmt.Sprintf("%s → %s is %s; none of %d re-rolled identifiers reaches %s any more: the rollout is gone",
			req, want.Flag, stateOrMissing(flags, want.Flag), tried, want.After))
	}
	if !served {
		return model.StatusHidden, redact.String(fmt.Sprintf(
			"%s → %s is no longer served to client SDKs, but server-side evaluation still returns %s for identifier %s: the rollout still exists. A server that evaluates this flag for a browser-chosen identifier can still be re-rolled. Assign identifiers on the server or remove the rollout to close it.",
			req, want.Flag, want.After, hit)), nil
	}
	flags, req, err = t.ClientIdentify(ctx, hit, nil)
	if err != nil {
		return unknown(err)
	}
	if flags[want.Flag] == want.After {
		return statusIf(true, fmt.Sprintf("%s → %s is %s after re-rolling to identifier %s (exploited state %s)", req, want.Flag, flags[want.Flag], hit, want.After))
	}
	return model.StatusUnknown, redact.String(fmt.Sprintf(
		"%s → %s is %s live, but the engine still gives %s to identifier %s: live and engine disagree, re-run verify later",
		req, want.Flag, stateOrMissing(flags, want.Flag), want.After, hit)), nil
}

// searchIdentifier looks on the server path for an identifier that receives
// the exploited state, starting with the recorded proof identifier.
func searchIdentifier(ctx context.Context, t Target, first string, want model.FlagChange) (hit string, tried int, err error) {
	for n := -1; n < RerollSearch; n++ {
		id := first
		if n >= 0 {
			id = RerollIdentifier(n)
		}
		if err := ctx.Err(); err != nil {
			return "", tried, err
		}
		flags, err := t.ServerEvaluate(ctx, id, nil)
		if err != nil {
			return "", tried, err
		}
		tried++
		if flags[want.Flag] == want.After {
			return id, tried, nil
		}
	}
	return "", tried, nil
}

func stateOrMissing(flags map[string]string, name string) string {
	if s, ok := flags[name]; ok {
		return s
	}
	return "absent"
}

func statusIf(exploitable bool, proof string) (model.Status, string, error) {
	if exploitable {
		return model.StatusExploitable, redact.String(proof), nil
	}
	return model.StatusBlocked, redact.String(proof), nil
}

func unknown(err error) (model.Status, string, error) {
	return model.StatusUnknown, "", err
}

// Recheck re-runs exactly the attack behind one finding and returns its new
// status plus a redacted proof (request/response summary).
type Recheck func(ctx context.Context, f model.Finding) (model.Status, string, error)

// Rerun re-checks every finding the plan addressed, in plan order, then the
// findings it only partially mitigates, and returns one before/after row
// each. A failing recheck yields an UNKNOWN "after" status with the redacted
// error as proof, never a silent success.
func Rerun(ctx context.Context, rec *model.PlanRecord, findings []model.Finding, recheck Recheck) []model.VerifyRow {
	byID := make(map[string]model.Finding, len(findings))
	for _, f := range findings {
		byID[f.ID] = f
	}
	rows := make([]model.VerifyRow, 0, len(rec.Plan.FindingsAddressed)+len(rec.Plan.PartiallyMitigated))
	add := func(ids []string, partial bool) {
		for _, id := range ids {
			row := model.VerifyRow{FindingID: id, Title: "unknown finding",
				Before: model.StatusUnknown, After: model.StatusUnknown,
				Proof: "finding " + id + " was not supplied to the re-run"}
			if f, ok := byID[id]; ok {
				row = rerunOne(ctx, f, recheck)
			}
			row.PartiallyMitigated = partial
			rows = append(rows, row)
		}
	}
	add(rec.Plan.FindingsAddressed, false)
	add(rec.Plan.PartiallyMitigated, true)
	return rows
}

func rerunOne(ctx context.Context, f model.Finding, recheck Recheck) model.VerifyRow {
	row := model.VerifyRow{FindingID: f.ID, Title: redact.String(f.Title), Before: f.Status}
	if err := ctx.Err(); err != nil {
		row.After, row.Proof = model.StatusUnknown, "re-check skipped: "+redact.String(err.Error())
		return row
	}
	after, proof, err := recheck(ctx, f)
	if err != nil {
		row.After, row.Proof = model.StatusUnknown, "re-check failed: "+redact.String(err.Error())
		return row
	}
	row.After, row.Proof = after, redact.String(proof)
	return row
}

// AllBlocked reports whether every finding the plan claimed to close ended
// BLOCKED (and there is at least one). Partially mitigated rows are not
// claims: they are reported by StillOpen instead.
func AllBlocked(rows []model.VerifyRow) bool {
	claimed := 0
	for _, r := range rows {
		if r.PartiallyMitigated {
			continue
		}
		claimed++
		if r.After != model.StatusBlocked {
			return false
		}
	}
	return claimed > 0
}

// StillOpen counts the rows that did not end BLOCKED: EXPLOITABLE, HIDDEN
// and UNKNOWN all remain open.
func StillOpen(rows []model.VerifyRow) int {
	n := 0
	for _, r := range rows {
		if r.After != model.StatusBlocked {
			n++
		}
	}
	return n
}
