package verify

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

func TestRerun(t *testing.T) {
	secret := "ser." + strings.Repeat("ab", 12)
	findings := []model.Finding{
		{ID: "GC-1", Title: "forge plan", Status: model.StatusExploitable},
		{ID: "GC-2", Title: "leak", Status: model.StatusExploitable},
		{ID: "GC-3", Title: "still open", Status: model.StatusExploitable},
		{ID: "GC-9", Title: "not addressed", Status: model.StatusExploitable},
	}
	rec := &model.PlanRecord{Plan: model.Plan{FindingsAddressed: []string{"GC-1", "GC-2", "GC-3", "GC-404"}}}
	recheck := func(_ context.Context, f model.Finding) (model.Status, string, error) {
		switch f.ID {
		case "GC-1":
			return model.StatusBlocked, "POST identities -> plan unchanged " + secret, nil
		case "GC-2":
			return "", "", errors.New("connection refused " + secret)
		}
		return model.StatusExploitable, "still forgeable", nil
	}
	rows := Rerun(context.Background(), rec, findings, recheck)
	if len(rows) != 4 {
		t.Fatalf("rows = %d", len(rows))
	}
	if rows[0].Before != model.StatusExploitable || rows[0].After != model.StatusBlocked {
		t.Fatalf("row0 = %+v", rows[0])
	}
	if rows[1].After != model.StatusUnknown || !strings.Contains(rows[1].Proof, "re-check failed") {
		t.Fatalf("row1 = %+v", rows[1])
	}
	if rows[2].After != model.StatusExploitable {
		t.Fatalf("row2 = %+v", rows[2])
	}
	if rows[3].FindingID != "GC-404" || rows[3].After != model.StatusUnknown {
		t.Fatalf("row3 = %+v", rows[3])
	}
	for _, r := range rows {
		if strings.Contains(r.Proof, secret) {
			t.Fatalf("proof leaks a secret: %q", r.Proof)
		}
	}
	if AllBlocked(rows) || AllBlocked(nil) || !AllBlocked(rows[:1]) {
		t.Fatal("AllBlocked wrong")
	}
}

func TestRerunCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec := &model.PlanRecord{Plan: model.Plan{FindingsAddressed: []string{"GC-1"}}}
	rows := Rerun(ctx, rec, []model.Finding{{ID: "GC-1"}}, func(context.Context, model.Finding) (model.Status, string, error) {
		t.Fatal("recheck must not run after cancellation")
		return "", "", nil
	})
	if rows[0].After != model.StatusUnknown {
		t.Fatalf("got %+v", rows[0])
	}
}
