package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

// ContaminateConfirmation is the text a human types to accept that a plan
// touches a running experiment.
const ContaminateConfirmation = "contaminate-experiment"

// actionTimeout bounds one approve/apply/verify/rollback call. The call
// outlives the browser request so closing the tab cannot abort an apply
// half-way.
const actionTimeout = 5 * time.Minute

type diffRow struct {
	Key, Before, After string
}

type opView struct {
	Op   model.Operation
	Rows []diffRow
}

type findingRef struct {
	ID       string
	Title    string
	ReportID string
}

type planView struct {
	Rec              model.PlanRecord
	Ops              []opView
	Findings         []findingRef
	Err              string
	NeedsEnv         bool
	NeedsContaminate bool
	CanApprove       bool
	GuidanceOnly     bool
	CanReject        bool
	CanApply         bool
	CanVerify        bool
	CanRollback      bool
}

type plansView struct {
	Plans      []planView
	Reports    []ReportSummary
	Filter     string
	FilterMiss bool
	Confirm    string
}

func (s *Server) plans(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("finding")
	if filter != "" && !idPattern.MatchString(filter) {
		filter = ""
	}
	s.render(w, r, "plans", http.StatusOK, pageData{Title: "Fix plans", Active: "plans", Body: s.buildPlansView(filter, nil)})
}

func (s *Server) buildPlansView(filter string, errs map[string]string) plansView {
	reports := sortedReports(s.be.Reports())
	refs := s.findingTitles(reports)
	recs := append([]model.PlanRecord(nil), s.be.Plans()...)
	sort.SliceStable(recs, func(i, j int) bool {
		pi, pj := recs[i].State == model.PlanPending, recs[j].State == model.PlanPending
		if pi != pj {
			return pi
		}
		// Plans that change Flagsmith come before guidance, biggest first.
		ai, aj := autoOps(recs[i].Plan), autoOps(recs[j].Plan)
		if (ai > 0) != (aj > 0) {
			return ai > 0
		}
		if fi, fj := len(recs[i].Plan.FindingsAddressed), len(recs[j].Plan.FindingsAddressed); fi != fj {
			return fi > fj
		}
		return recs[i].Plan.CreatedAt.After(recs[j].Plan.CreatedAt)
	})
	v := plansView{Reports: reports, Filter: filter, Confirm: ContaminateConfirmation}
	for _, rec := range recs {
		if filter != "" && !addresses(rec.Plan, filter) {
			continue
		}
		v.Plans = append(v.Plans, newPlanView(rec, refs, errs[rec.Plan.ID]))
	}
	if filter != "" && len(v.Plans) == 0 {
		v.FilterMiss = true
		for _, rec := range recs {
			v.Plans = append(v.Plans, newPlanView(rec, refs, errs[rec.Plan.ID]))
		}
	}
	return v
}

func addresses(p model.Plan, findingID string) bool {
	for _, id := range p.FindingsAddressed {
		if id == findingID {
			return true
		}
	}
	return false
}

// findingTitles maps finding IDs to titles using the newest report that
// mentions each one.
func (s *Server) findingTitles(reports []ReportSummary) map[string]findingRef {
	out := map[string]findingRef{}
	for _, sum := range reports {
		rep, err := s.be.Report(sum.ID)
		if err != nil {
			continue
		}
		for _, f := range rep.Findings {
			if _, seen := out[f.ID]; !seen {
				out[f.ID] = findingRef{ID: f.ID, Title: f.Title, ReportID: rep.ID}
			}
		}
	}
	return out
}

// autoOps counts the operations a plan would execute in Flagsmith.
func autoOps(p model.Plan) int {
	n := 0
	for _, op := range p.Operations {
		if op.Automatic {
			n++
		}
	}
	return n
}

func newPlanView(rec model.PlanRecord, refs map[string]findingRef, errMsg string) planView {
	p := rec.Plan
	v := planView{Rec: rec, Err: errMsg,
		NeedsEnv:         p.Production,
		NeedsContaminate: p.ExperimentWarning != "",
		CanApprove:       rec.State == model.PlanPending && autoOps(p) > 0,
		GuidanceOnly:     autoOps(p) == 0,
		CanReject:        rec.State == model.PlanPending || rec.State == model.PlanApproved,
		CanApply:         rec.State == model.PlanApproved,
		CanVerify:        rec.State == model.PlanApplied || rec.State == model.PlanVerified,
		CanRollback:      rec.State == model.PlanApplied || rec.State == model.PlanVerified,
	}
	for _, op := range p.Operations {
		v.Ops = append(v.Ops, opView{Op: op, Rows: diffRows(op)})
	}
	for _, id := range p.FindingsAddressed {
		ref, ok := refs[id]
		if !ok {
			ref = findingRef{ID: id}
		}
		v.Findings = append(v.Findings, ref)
	}
	return v
}

// diffRows lines up an operation's before values against what it will write.
func diffRows(op model.Operation) []diffRow {
	keys := make([]string, 0, len(op.Body))
	for k := range op.Body {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rows := make([]diffRow, 0, len(keys))
	for _, k := range keys {
		before := "(not recorded)"
		if b, ok := op.Before[k]; ok {
			before = fmtVal(b)
		}
		rows = append(rows, diffRow{Key: k, Before: before, After: fmtVal(op.Body[k])})
	}
	return rows
}

func (s *Server) makePlans(w http.ResponseWriter, r *http.Request) {
	id := r.PostFormValue("report_id")
	if !idPattern.MatchString(id) {
		s.rerender(w, r, "", "Choose a report to build fix plans from.")
		return
	}
	ctx, cancel := actionContext(r)
	defer cancel()
	if err := s.be.MakePlans(ctx, id); err != nil {
		if errors.Is(err, ErrNotFound) {
			s.notFound(w, r, "Report")
			return
		}
		s.rerender(w, r, "", redact.String(err.Error()))
		return
	}
	http.Redirect(w, r, "/plans?ok=planned", http.StatusSeeOther)
}

// rerender shows the plans page with an error, either on one plan card
// (planID set) or as a page-level banner.
func (s *Server) rerender(w http.ResponseWriter, r *http.Request, planID, msg string) {
	p := pageData{Title: "Fix plans", Active: "plans"}
	if planID == "" {
		p.Error = msg
		p.Body = s.buildPlansView("", nil)
	} else {
		p.Body = s.buildPlansView("", map[string]string{planID: msg})
	}
	s.render(w, r, "plans", http.StatusUnprocessableEntity, p)
}

func actionContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), actionTimeout)
}

// planAction handles POST /plans/{id}/{approve|reject|apply|verify|rollback}.
func (s *Server) planAction(w http.ResponseWriter, r *http.Request) {
	id, action := r.PathValue("id"), r.PathValue("action")
	if !idPattern.MatchString(id) || !knownAction(action) {
		s.notFound(w, r, "Plan")
		return
	}
	rec, err := s.be.Plan(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			s.notFound(w, r, "Plan")
			return
		}
		s.fail(w, r, err)
		return
	}
	ctx, cancel := actionContext(r)
	defer cancel()
	msg, ok := s.dispatch(ctx, r, action, rec)
	if msg != "" {
		s.rerender(w, r, id, msg)
		return
	}
	http.Redirect(w, r, "/plans?ok="+ok+"#plan-"+id, http.StatusSeeOther)
}

func knownAction(a string) bool {
	switch a {
	case "approve", "reject", "apply", "verify", "rollback":
		return true
	}
	return false
}

// dispatch runs one action. It returns a user-facing error message, or the
// notice code on success.
func (s *Server) dispatch(ctx context.Context, r *http.Request, action string, rec *model.PlanRecord) (errMsg, ok string) {
	id := rec.Plan.ID
	var err error
	switch action {
	case "approve":
		if msg := checkApproval(rec, r.PostFormValue("typed_env"), r.PostFormValue("typed_contaminate")); msg != "" {
			return msg, ""
		}
		err = s.be.Approve(ctx, id, strings.TrimSpace(r.PostFormValue("typed_env")),
			strings.TrimSpace(r.PostFormValue("typed_contaminate")), s.opts.Operator)
		ok = "approved"
	case "reject":
		if rec.State != model.PlanPending && rec.State != model.PlanApproved {
			return stateMsg(rec, "rejected"), ""
		}
		err, ok = s.be.Reject(ctx, id, s.opts.Operator), "rejected"
	case "apply":
		if rec.State != model.PlanApproved {
			return stateMsg(rec, "applied"), ""
		}
		err, ok = s.be.Apply(ctx, id), "applied"
	case "verify":
		if rec.State != model.PlanApplied && rec.State != model.PlanVerified {
			return stateMsg(rec, "verified"), ""
		}
		err, ok = s.be.Verify(ctx, id), "verified"
	case "rollback":
		if rec.State != model.PlanApplied && rec.State != model.PlanVerified {
			return stateMsg(rec, "rolled back"), ""
		}
		err, ok = s.be.Rollback(ctx, id), "rolledback"
	}
	if err != nil {
		return redact.String(err.Error()), ""
	}
	return "", ok
}

func stateMsg(rec *model.PlanRecord, verb string) string {
	return fmt.Sprintf("This plan is %s, so it cannot be %s now.", rec.State, verb)
}

// checkApproval enforces the typed confirmations before the backend is
// called: Production needs the exact environment name, and a plan with an
// experiment warning needs the contaminate-experiment phrase.
func checkApproval(rec *model.PlanRecord, typedEnv, typedContaminate string) string {
	if rec.State != model.PlanPending {
		return stateMsg(rec, "approved")
	}
	p := rec.Plan
	if p.Production && strings.TrimSpace(typedEnv) != p.Environment {
		return fmt.Sprintf("Type the environment name %q exactly to approve a change to Production.", p.Environment)
	}
	if p.ExperimentWarning != "" && strings.TrimSpace(typedContaminate) != ContaminateConfirmation {
		return fmt.Sprintf("This plan affects a running experiment. Type %q to confirm you accept that.", ContaminateConfirmation)
	}
	return ""
}
