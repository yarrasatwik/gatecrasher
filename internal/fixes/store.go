package fixes

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/audit"
	"github.com/yarrasatwik/gatecrasher/internal/model"
)

var planIDRe = regexp.MustCompile(`^plan-[0-9a-f]{8}$`)

// ErrPlanNotFound is returned when no plan has the requested ID.
var ErrPlanNotFound = errors.New("no such plan")

// Store persists plan records as <stateDir>/plans/<id>.json (mode 0600).
// When Audit is set, the lifecycle helpers (Create, Approve, Reject) write
// to the audit log.
type Store struct {
	Audit *audit.Log

	mu  sync.Mutex
	dir string
}

// NewStore returns a store rooted at <stateDir>/plans, creating it.
func NewStore(stateDir string) (*Store, error) {
	dir := filepath.Join(stateDir, "plans")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create plan store: %w", err)
	}
	return &Store{dir: dir}, nil
}

func (s *Store) file(id string) (string, error) {
	if !planIDRe.MatchString(id) {
		return "", fmt.Errorf("invalid plan id %q (want plan-<8 hex>)", id)
	}
	return filepath.Join(s.dir, id+".json"), nil
}

// Save writes the record atomically (temp file, fsync, rename).
func (s *Store) Save(rec *model.PlanRecord) error {
	path, err := s.file(rec.Plan.ID)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("encode plan: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tmp, err := os.CreateTemp(s.dir, ".plan-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp plan file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, os.ErrPermission) {
		tmp.Close()
		return fmt.Errorf("chmod plan file: %w", err)
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return fmt.Errorf("write plan file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync plan file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("replace plan file: %w", err)
	}
	return nil
}

// Get loads one plan record.
func (s *Store) Get(id string) (*model.PlanRecord, error) {
	path, err := s.file(id)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrPlanNotFound, id)
	}
	if err != nil {
		return nil, err
	}
	var rec model.PlanRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, fmt.Errorf("decode plan %s: %w", id, err)
	}
	return &rec, nil
}

// List returns every stored plan, oldest first.
func (s *Store) List() ([]*model.PlanRecord, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var recs []*model.PlanRecord
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".json" {
			continue
		}
		rec, err := s.Get(name[:len(name)-len(".json")])
		if err != nil {
			return nil, err
		}
		recs = append(recs, rec)
	}
	sort.SliceStable(recs, func(i, j int) bool {
		if !recs[i].Plan.CreatedAt.Equal(recs[j].Plan.CreatedAt) {
			return recs[i].Plan.CreatedAt.Before(recs[j].Plan.CreatedAt)
		}
		return recs[i].Plan.ID < recs[j].Plan.ID
	})
	return recs, nil
}

// Create saves each plan as a pending record and audits it.
func (s *Store) Create(plans []model.Plan) ([]*model.PlanRecord, error) {
	recs := make([]*model.PlanRecord, 0, len(plans))
	for _, p := range plans {
		rec := &model.PlanRecord{Plan: p, State: model.PlanPending}
		if err := s.Save(rec); err != nil {
			return recs, err
		}
		if err := s.record("gatecrasher", audit.ActionPlan, p.ID, map[string]any{
			"environment": p.Environment, "target": p.TargetObject, "hash": p.Hash,
			"findings": p.FindingsAddressed, "operations": len(p.Operations),
		}); err != nil {
			return recs, err
		}
		recs = append(recs, rec)
	}
	return recs, nil
}

// Approve loads the plan, applies Approve, saves and audits it.
func (s *Store) Approve(id, by, channel, typedEnv, typedContaminate string, ttl time.Duration) (*model.PlanRecord, error) {
	rec, err := s.Get(id)
	if err != nil {
		return nil, err
	}
	if err := Approve(rec, by, channel, typedEnv, typedContaminate, ttl); err != nil {
		_ = s.record(by, audit.ActionRefuse, id, map[string]any{
			"stage": "approve", "channel": channel, "os_user": osUser(), "reason": err.Error(),
		})
		return rec, err
	}
	if err := s.Save(rec); err != nil {
		return rec, err
	}
	// The audit entry says who Gatecrasher could identify (the OS user) and
	// keeps a name it could not check apart, as "claimed_by".
	ap := rec.Approval
	details := map[string]any{
		"hash": rec.Plan.Hash, "channel": ap.Channel, "os_user": ap.OSUser, "expires_at": ap.ExpiresAt,
	}
	actor := by
	if ap.ByClaimed {
		details["claimed_by"] = by
		actor = ap.OSUser
	} else {
		details["by"] = by
	}
	return rec, s.record(actor, audit.ActionApprove, id, details)
}

// Reject loads the plan, applies Reject, saves and audits it.
func (s *Store) Reject(id, by, reason string) (*model.PlanRecord, error) {
	rec, err := s.Get(id)
	if err != nil {
		return nil, err
	}
	if err := Reject(rec, by, reason); err != nil {
		return rec, err
	}
	if err := s.Save(rec); err != nil {
		return rec, err
	}
	return rec, s.record(by, audit.ActionReject, id, map[string]any{"reason": reason})
}

func (s *Store) record(actor string, action audit.Action, planID string, details map[string]any) error {
	if s.Audit == nil {
		return nil
	}
	_, err := s.Audit.Append(actor, action, planID, details)
	return err
}
