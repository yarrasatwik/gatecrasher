package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

func reviewReport(id string) *model.Report {
	rep := sampleReport(id)
	rep.Findings = append(rep.Findings, model.Finding{
		ID: "GC-DDDD4444", Type: model.FUnreleasedProduct, Severity: model.SevInfo, Environment: "Production",
		Title: "Unreleased product leaked through flag: partner_portal (suggested by Claude, needs review)", Subject: "partner_portal",
		Category: model.CatUnreleasedProduct, DetectedBy: []model.Method{model.MethodAI}, Status: model.StatusNeedsReview,
		Evidence: []model.Evidence{{Kind: "request", Note: "Name suggests a product that is not public yet."}},
	})
	return rep
}

func TestReviewItemsAreSeparateAndNotCounted(t *testing.T) {
	h := newHarness(t, nil)
	h.fb.reports["R1"] = reviewReport("R1")
	if got := WaysIn(h.fb.reports["R1"]); got != 2 {
		t.Fatalf("WaysIn = %d, want 2: a review item is not a way in", got)
	}
	_, page, _ := h.get("/report/R1")
	contains(t, page, "2 ways in", "Claude suggests reviewing (1)", "Not counted", "partner_portal",
		"Name suggests a product that is not public yet.", `action="/report/R1/confirm/GC-DDDD4444"`, "Confirm as a finding")
	// The suggestion is not rendered as a finding card in a severity group.
	notContains(t, page, `id="sev-info"`, "INFO (1)")
	if strings.Count(page, `name="csrf_token"`) < 2 {
		t.Fatal("the confirm form must carry the CSRF token")
	}
}

func TestConfirmFindingIsAHumanActionBehindCSRF(t *testing.T) {
	h := newHarness(t, nil)
	h.fb.reports["R1"] = reviewReport("R1")
	path := "/report/R1/confirm/GC-DDDD4444"

	if code, _, _ := h.post(path, url.Values{}, nil); code != http.StatusForbidden {
		t.Fatalf("confirm without a CSRF token = %d, want 403", code)
	}
	if code, _, _ := h.post(path, url.Values{"csrf_token": {h.token()}}, map[string]string{"Origin": "http://evil.example.com"}); code != http.StatusForbidden {
		t.Fatalf("cross-origin confirm = %d, want 403", code)
	}
	if code, _, _ := h.postScript(path, nil); code != http.StatusForbidden {
		t.Fatalf("confirm without Origin or Sec-Fetch-Site (curl) = %d, want 403", code)
	}
	if n := len(h.fb.called("confirm")); n != 0 {
		t.Fatalf("backend reached %d times by refused requests", n)
	}

	code, _, hdr := h.postCSRF(path, nil)
	if code != http.StatusSeeOther || !strings.Contains(hdr.Get("Location"), "/report/R1") {
		t.Fatalf("confirm = %d %q", code, hdr.Get("Location"))
	}
	if got := h.fb.called("confirm"); len(got) != 1 || got[0] != "confirm R1 GC-DDDD4444 web" {
		t.Fatalf("backend calls = %v", got)
	}
	_, page, _ := h.get("/report/R1")
	contains(t, page, "3 ways in", "human-review")
	notContains(t, page, "Claude suggests reviewing", "Confirm as a finding")

	// Only a NEEDS_REVIEW item can be confirmed; everything else is refused
	// before it reaches the backend.
	for p, want := range map[string]int{
		"/report/R1/confirm/GC-AAAA1111":  http.StatusConflict,
		"/report/R1/confirm/GC-NOPE":      http.StatusNotFound,
		"/report/ghost/confirm/GC-DDDD44": http.StatusNotFound,
		"/report/R1/confirm/..%2Fx":       http.StatusNotFound,
	} {
		if code, _, _ := h.postCSRF(p, nil); code != want {
			t.Errorf("POST %s = %d, want %d", p, code, want)
		}
	}
	if n := len(h.fb.called("confirm")); n != 1 {
		t.Fatalf("backend called %d times, want 1", n)
	}
}
