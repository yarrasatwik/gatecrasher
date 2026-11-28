package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/model"
)

const (
	// ProtectedApproveDelay is how long the Approve button of a protected
	// environment stays locked after the page is rendered. The server
	// enforces it too, so a script cannot skip it.
	ProtectedApproveDelay = 3 * time.Second
	// approveFormMaxAge is how long a rendered approve form stays usable.
	approveFormMaxAge = 30 * time.Minute
	// stampField carries the signed render timestamp of an approve form.
	stampField = "rendered_at"
)

// stamp returns "<unix ms>.<hmac>": when the approve form for p was
// rendered, signed with a key only this server process has. The signature
// covers the plan ID and hash, so a timestamp cannot be backdated or moved
// to another plan.
func (s *Server) stamp(p model.Plan) string {
	ms := strconv.FormatInt(s.opts.Now().UnixMilli(), 10)
	return ms + "." + s.stampMAC(p, ms)
}

func (s *Server) stampMAC(p model.Plan, ms string) string {
	m := hmac.New(sha256.New, s.stampKey)
	m.Write([]byte(p.ID + "\n" + p.Hash + "\n" + ms))
	return hex.EncodeToString(m.Sum(nil))
}

// stampAge verifies a stamp for p and returns how long ago it was issued.
func (s *Server) stampAge(p model.Plan, stamp string) (time.Duration, bool) {
	ms, sig, ok := strings.Cut(strings.TrimSpace(stamp), ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(s.stampMAC(p, ms))) {
		return 0, false
	}
	n, err := strconv.ParseInt(ms, 10, 64)
	if err != nil {
		return 0, false
	}
	return s.opts.Now().Sub(time.UnixMilli(n)), true
}

// checkDelay refuses an approval of a protected environment that arrives
// without a valid render timestamp, sooner than ProtectedApproveDelay after
// the page was rendered, or from a page that has gone stale. It returns a
// user-facing message, or "" when the approval may proceed.
func (s *Server) checkDelay(rec *model.PlanRecord, stamp string) string {
	if !rec.Plan.Production {
		return ""
	}
	age, ok := s.stampAge(rec.Plan, stamp)
	switch {
	case !ok || age < 0:
		return "This approval did not come from a plan page this server rendered. Reload the page, review the plan, then approve."
	case age < ProtectedApproveDelay:
		return fmt.Sprintf("Protected environments have a %d-second review delay. Wait until the Approve button unlocks, then approve again.",
			int(ProtectedApproveDelay/time.Second))
	case age > approveFormMaxAge:
		return fmt.Sprintf("This page was loaded more than %d minutes ago. Review the plan again, then approve.",
			int(approveFormMaxAge/time.Minute))
	}
	return ""
}
