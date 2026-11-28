package fixes

import (
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/audit"
)

func withOSUser(t *testing.T, name string) {
	t.Helper()
	old := osUser
	osUser = func() string { return name }
	t.Cleanup(func() { osUser = old })
}

func lastEntry(t *testing.T, h *harness) (audit.Entry, map[string]any) {
	t.Helper()
	entries, err := h.log.Entries()
	if err != nil {
		t.Fatal(err)
	}
	e := entries[len(entries)-1]
	var d map[string]any
	if err := e.Decode(&d); err != nil {
		t.Fatal(err)
	}
	return e, d
}

func TestApprovalRecordsChannelOSUserAndClaimedName(t *testing.T) {
	tests := []struct {
		name, osName, by, channel string
		claimed                   bool
	}{
		{"terminal, same user", "alice", "alice", ChannelTTY, false},
		{"same user, different case", "Alice", "alice", ChannelTTY, false},
		{"windows domain account", `CORP\alice`, "alice", ChannelWeb, false},
		{"--by names someone else", "alice", "cto", ChannelTTY, true},
		{"web operator label", "alice", "web", ChannelWeb, true},
		{"os user unknown", unknownUser, "alice", ChannelCLI, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withOSUser(t, tc.osName)
			h := newHarness(t)
			recs := h.planFor(t, "", traitFinding())
			rec, err := h.store.Approve(recs[0].Plan.ID, tc.by, tc.channel, "Production", "", 0)
			if err != nil {
				t.Fatal(err)
			}
			a := rec.Approval
			if a.Channel != tc.channel || a.OSUser != tc.osName || a.By != tc.by || a.ByClaimed != tc.claimed {
				t.Fatalf("approval = %+v", a)
			}
			e, d := lastEntry(t, h)
			if e.Action != audit.ActionApprove || d["channel"] != tc.channel || d["os_user"] != tc.osName {
				t.Fatalf("audit entry = %+v %v", e, d)
			}
			if tc.claimed {
				if d["claimed_by"] != tc.by || d["by"] != nil || e.Actor != tc.osName {
					t.Fatalf("a claimed name must be marked as claimed: actor %q details %v", e.Actor, d)
				}
			} else if d["by"] != tc.by || d["claimed_by"] != nil || e.Actor != tc.by {
				t.Fatalf("a matching name must be recorded as the approver: actor %q details %v", e.Actor, d)
			}
			if ok, at, err := h.log.Verify(); !ok || err != nil {
				t.Fatalf("audit chain broken at %d: %v", at, err)
			}
		})
	}
}

func TestRefusedApprovalRecordsChannelAndOSUser(t *testing.T) {
	withOSUser(t, "alice")
	h := newHarness(t)
	recs := h.planFor(t, "", traitFinding())
	if _, err := h.store.Approve(recs[0].Plan.ID, "cto", ChannelCLI, "", "", 0); err == nil {
		t.Fatal("approval without the typed environment name was accepted")
	}
	e, d := lastEntry(t, h)
	if e.Action != audit.ActionRefuse || d["channel"] != ChannelCLI || d["os_user"] != "alice" {
		t.Fatalf("refusal entry = %+v %v", e, d)
	}
}
