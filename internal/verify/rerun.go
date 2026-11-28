// Package verify re-attacks the findings a plan addressed and produces the
// before/after table (spec §8.11).
package verify

import (
	"context"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

// Recheck re-runs exactly the attack behind one finding and returns its new
// status plus a redacted proof (request/response summary).
type Recheck func(ctx context.Context, f model.Finding) (model.Status, string, error)

// Rerun re-checks every finding the plan addressed, in plan order, and
// returns one before/after row each. A failing recheck yields an UNKNOWN
// "after" status with the redacted error as proof, never a silent success.
func Rerun(ctx context.Context, rec *model.PlanRecord, findings []model.Finding, recheck Recheck) []model.VerifyRow {
	byID := make(map[string]model.Finding, len(findings))
	for _, f := range findings {
		byID[f.ID] = f
	}
	rows := make([]model.VerifyRow, 0, len(rec.Plan.FindingsAddressed))
	for _, id := range rec.Plan.FindingsAddressed {
		f, ok := byID[id]
		if !ok {
			rows = append(rows, model.VerifyRow{FindingID: id, Title: "unknown finding",
				Before: model.StatusUnknown, After: model.StatusUnknown,
				Proof: "finding " + id + " was not supplied to the re-run"})
			continue
		}
		rows = append(rows, rerunOne(ctx, f, recheck))
	}
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
	row.After, row.Proof = after, redact.String(identifierProof(f, after, proof))
	return row
}

// IdentifierStillOpen is appended to the proof of an identifier forgery that
// still reproduces: the client-traits fix is not expected to close it.
const IdentifierStillOpen = "Still exploitable: choosing an identifier is not affected by the client-traits setting. " +
	"Assign identifiers on the server and stop targeting on identifier patterns."

// identifierProof explains an identifier forgery that survives a re-check,
// so a reader who just turned off client traits knows why it is still open.
func identifierProof(f model.Finding, after model.Status, proof string) string {
	if f.Type != model.FIdentifierForgery || after != model.StatusExploitable {
		return proof
	}
	if proof == "" {
		return IdentifierStillOpen
	}
	return proof + ". " + IdentifierStillOpen
}

// AllBlocked reports whether every row ended BLOCKED (and there is at least
// one row).
func AllBlocked(rows []model.VerifyRow) bool {
	for _, r := range rows {
		if r.After != model.StatusBlocked {
			return false
		}
	}
	return len(rows) > 0
}
