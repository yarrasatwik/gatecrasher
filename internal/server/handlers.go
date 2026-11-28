package server

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/model"
	"github.com/yarrasatwik/gatecrasher/internal/redact"
	"github.com/yarrasatwik/gatecrasher/internal/watch"
)

// idPattern is what report and plan IDs may look like; anything else is
// refused before it reaches the backend or a template.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

const recentReports = 8

type dashboardView struct {
	Config  SafeConfigView
	Reports []ReportSummary
	Run     runView
	Pending int
	Alerts  int
	Latest  *ReportSummary
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	reports := sortedReports(s.be.Reports())
	v := dashboardView{Config: s.be.Config(), Run: s.runSnapshot(), Pending: s.pendingPlans(), Alerts: len(s.be.Alerts())}
	if len(reports) > 0 {
		v.Latest = &reports[0]
	}
	if len(reports) > recentReports {
		reports = reports[:recentReports]
	}
	v.Reports = reports
	s.render(w, r, "dashboard", http.StatusOK, pageData{Title: "Dashboard", Active: "dashboard", Body: v})
}

func sortedReports(in []ReportSummary) []ReportSummary {
	out := append([]ReportSummary(nil), in...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

type sevGroup struct {
	Severity model.Severity
	Findings []model.Finding
}

type reportView struct {
	Report   *model.Report
	WaysIn   int
	Groups   []sevGroup
	Controls []model.Finding
	// Review holds what only the AI suggested. These are not findings: they
	// are shown apart, never counted, and a person can confirm each one.
	Review []reviewItem
	Counts []sevGroup
}

// reviewItem is one NEEDS_REVIEW suggestion with the AI's stated reason.
type reviewItem struct {
	model.Finding
	Reason string
}

func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !idPattern.MatchString(id) {
		s.notFound(w, r, "Report")
		return
	}
	rep, err := s.be.Report(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			s.notFound(w, r, "Report")
			return
		}
		s.fail(w, r, err)
		return
	}
	s.render(w, r, "report", http.StatusOK, pageData{Title: "Report " + rep.ID, Active: "dashboard", Body: buildReportView(rep)})
}

func buildReportView(rep *model.Report) reportView {
	v := reportView{Report: rep, WaysIn: WaysIn(rep)}
	bySev := map[model.Severity][]model.Finding{}
	for _, f := range rep.Findings {
		if f.Type == model.FControlOK {
			v.Controls = append(v.Controls, f)
			continue
		}
		if f.Status == model.StatusNeedsReview {
			item := reviewItem{Finding: f}
			for _, e := range f.Evidence {
				if e.Note != "" {
					item.Reason = e.Note
				}
			}
			v.Review = append(v.Review, item)
			continue
		}
		bySev[f.Severity] = append(bySev[f.Severity], f)
	}
	for sev := model.SevCritical; sev >= model.SevInfo; sev-- {
		if fs := bySev[sev]; len(fs) > 0 {
			v.Groups = append(v.Groups, sevGroup{Severity: sev, Findings: fs})
		}
	}
	return v
}

// confirmFinding handles POST /report/{id}/confirm/{finding}: a person marks
// something only the AI suggested as a real finding. Like every other
// state-changing request it has passed the CSRF and same-origin checks; the
// backend records it in the audit log.
func (s *Server) confirmFinding(w http.ResponseWriter, r *http.Request) {
	id, fid := r.PathValue("id"), r.PathValue("finding")
	if !idPattern.MatchString(id) || !idPattern.MatchString(fid) {
		s.notFound(w, r, "Report")
		return
	}
	rep, err := s.be.Report(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			s.notFound(w, r, "Report")
			return
		}
		s.fail(w, r, err)
		return
	}
	var target *model.Finding
	for i := range rep.Findings {
		if rep.Findings[i].ID == fid {
			target = &rep.Findings[i]
		}
	}
	if target == nil {
		s.notFound(w, r, "Finding")
		return
	}
	if target.Status != model.StatusNeedsReview {
		s.render(w, r, "message", http.StatusConflict, pageData{Title: "Nothing to confirm",
			Error: "Finding " + fid + " is not awaiting review."})
		return
	}
	ctx, cancel := actionContext(r)
	defer cancel()
	if err := s.be.ConfirmFinding(ctx, id, fid, s.opts.Operator); err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/report/"+id+"?ok=confirmed#f-"+fid, http.StatusSeeOther)
}

func (s *Server) watchPage(w http.ResponseWriter, r *http.Request) {
	alerts := append([]watch.Alert(nil), s.be.Alerts()...)
	sort.SliceStable(alerts, func(i, j int) bool { return alerts[i].At.After(alerts[j].At) })
	s.render(w, r, "watch", http.StatusOK, pageData{Title: "Watch", Active: "watch", Body: alerts})
}

// watchStream pushes each new alert as a server-sent "alert" event whose
// data is the rendered HTML list item.
func (s *Server) watchStream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	ch, cancel := s.be.SubscribeAlerts()
	defer cancel()
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	fmt.Fprint(w, "retry: 3000\n\n")
	fl.Flush()
	beat := time.NewTicker(15 * time.Second)
	defer beat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.base.Done():
			return
		case <-beat.C:
			fmt.Fprint(w, ": keep-alive\n\n")
		case a, open := <-ch:
			if !open {
				return
			}
			html, err := s.renderPartial("alert-item", a)
			if err != nil {
				s.log.Error("render alert", "err", redact.String(err.Error()))
				continue
			}
			fmt.Fprint(w, "event: alert\n")
			for _, line := range strings.Split(strings.TrimSpace(html), "\n") {
				fmt.Fprintf(w, "data: %s\n", line)
			}
			fmt.Fprint(w, "\n")
		}
		fl.Flush()
	}
}

type auditView struct {
	Rows  []AuditRow
	Valid bool
	N     int
}

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request) {
	rows := s.be.AuditEntries()
	valid, n := s.be.ChainValid()
	s.render(w, r, "audit", http.StatusOK, pageData{Title: "Audit log", Active: "audit",
		Body: auditView{Rows: rows, Valid: valid, N: n}})
}

// fail renders an unexpected backend error. The text is redacted.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("request failed", "path", r.URL.Path, "err", redact.String(err.Error()))
	s.render(w, r, "message", http.StatusInternalServerError, pageData{Title: "Error", Error: redact.String(err.Error())})
}
