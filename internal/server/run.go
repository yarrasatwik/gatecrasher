package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

const (
	maxProgressLines = 200
	runTimeout       = 30 * time.Minute
)

type progressLine struct {
	At    time.Time
	Stage string
	Msg   string
}

type runState struct {
	State    string // "", "running", "done", "failed"
	Lines    []progressLine
	ReportID string
	Err      string
	Started  time.Time
}

// runView is the immutable snapshot the templates render.
type runView struct {
	State    string
	Lines    []progressLine
	ReportID string
	Err      string
	Started  time.Time
	Running  bool
}

func (s *Server) runSnapshot() runView {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	return runView{State: s.run.State, Lines: append([]progressLine(nil), s.run.Lines...), ReportID: s.run.ReportID,
		Err: s.run.Err, Started: s.run.Started, Running: s.run.State == "running"}
}

// startRunHandler starts a full audit in the background (one at a time) and
// answers with the progress panel for HTMX or redirects for plain forms.
func (s *Server) startRunHandler(w http.ResponseWriter, r *http.Request) {
	s.startAudit()
	if r.Header.Get("HX-Request") == "true" {
		s.writePartial(w, "run-status", s.runSnapshot())
		return
	}
	http.Redirect(w, r, "/#run", http.StatusSeeOther)
}

func (s *Server) runStatus(w http.ResponseWriter, r *http.Request) {
	s.writePartial(w, "run-status", s.runSnapshot())
}

// startAudit launches the backend run unless one is already active.
func (s *Server) startAudit() {
	s.runMu.Lock()
	if s.run.State == "running" {
		s.runMu.Unlock()
		return
	}
	s.run = runState{State: "running", Started: time.Now()}
	s.runMu.Unlock()
	go s.runAudit()
}

func (s *Server) runAudit() {
	ctx, cancel := context.WithTimeout(s.base, runTimeout)
	defer cancel()
	var id string
	var err error
	func() {
		defer func() {
			if p := recover(); p != nil {
				err = fmt.Errorf("audit panicked: %v", p)
			}
		}()
		id, err = s.be.RunAudit(ctx, s.addProgress)
	}()
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if err != nil {
		s.run.State, s.run.Err = "failed", redact.String(err.Error())
		return
	}
	s.run.State, s.run.ReportID = "done", id
}

func (s *Server) addProgress(stage, msg string) {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	s.run.Lines = append(s.run.Lines, progressLine{At: time.Now(), Stage: redact.String(stage), Msg: redact.String(msg)})
	if n := len(s.run.Lines); n > maxProgressLines {
		s.run.Lines = append([]progressLine(nil), s.run.Lines[n-maxProgressLines:]...)
	}
}
