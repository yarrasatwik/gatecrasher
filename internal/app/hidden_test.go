package app

import (
	"strings"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

// The audit after a "Server-side only" fix must report the same status
// verify did: the engine still proves the rollout, the client SDK cannot
// reproduce it, so the finding is HIDDEN (open), not UNKNOWN and not gone.
func TestAuditMarksEngineProvenRerollOnServerOnlyFlagHidden(t *testing.T) {
	settings := []model.EnvSettings{{Environment: "Production", ServerOnlyFlags: []string{"early_access_ai"}}}
	serverOnly := serverOnlyFlags(settings, "production")
	if !serverOnly["early_access_ai"] || len(serverOnly) != 1 {
		t.Fatalf("serverOnlyFlags = %v", serverOnly)
	}
	f := model.Finding{Type: model.FPercentageReroll, Subject: "early_access_ai", Status: model.StatusExploitable,
		DetectedBy: []model.Method{model.MethodEngine},
		Unlocked:   []model.FlagChange{{Flag: "early_access_ai", Before: "off", After: "on"}}}
	engineStatus := f.Status
	markLive(&f, liveResult{ok: false}) // the client SDK no longer serves the flag
	if f.Status != model.StatusUnknown {
		t.Fatalf("precondition: live mismatch should leave %s", f.Status)
	}
	markHidden(&f, engineStatus, serverOnly)
	if f.Status != model.StatusHidden {
		t.Fatalf("status = %s, want HIDDEN", f.Status)
	}
	notes := strings.Join(f.Notes, "\n")
	if strings.Contains(notes, liveMismatchNote) || !strings.Contains(notes, "Hidden is not fixed") {
		t.Fatalf("notes = %q", notes)
	}

	// Still served to clients and reproduced live: stays EXPLOITABLE.
	g := model.Finding{Type: model.FPercentageReroll, Status: model.StatusExploitable,
		DetectedBy: []model.Method{model.MethodEngine, model.MethodProbe},
		Unlocked:   []model.FlagChange{{Flag: "early_access_ai"}}}
	markHidden(&g, model.StatusExploitable, serverOnly)
	if g.Status != model.StatusExploitable {
		t.Fatalf("live-reproduced finding became %s", g.Status)
	}
	// Not server-only: a live mismatch stays UNKNOWN, never HIDDEN.
	h := model.Finding{Type: model.FPercentageReroll, Status: model.StatusUnknown,
		Unlocked: []model.FlagChange{{Flag: "pricing_page"}}}
	markHidden(&h, model.StatusExploitable, serverOnly)
	if h.Status != model.StatusUnknown {
		t.Fatalf("non-server-only finding became %s", h.Status)
	}
	// The engine itself was unsure: never upgraded to HIDDEN.
	u := model.Finding{Type: model.FSegmentForgeable, Status: model.StatusUnknown,
		Unlocked: []model.FlagChange{{Flag: "early_access_ai"}}}
	markHidden(&u, model.StatusUnknown, serverOnly)
	if u.Status != model.StatusUnknown {
		t.Fatalf("engine-unknown finding became %s", u.Status)
	}
}
