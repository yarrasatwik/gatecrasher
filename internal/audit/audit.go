// Package audit implements the hash-chained, append-only audit log
// (spec §3.3 rule 7). Every entry carries the hash of the previous entry, so
// editing, deleting or reordering lines is detected by Verify. Truncating the
// tail cannot be detected from the file alone; callers that need that can
// anchor Head elsewhere.
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/yarrasatwik/gatecrasher/internal/redact"
)

// FileName is the audit log file name inside the state directory.
const FileName = "audit.log"

// Action names what an entry records.
type Action string

// Audit actions.
const (
	ActionPlan       Action = "plan"
	ActionApprove    Action = "approve"
	ActionReject     Action = "reject"
	ActionApply      Action = "apply"
	ActionVerify     Action = "verify"
	ActionRollback   Action = "rollback"
	ActionRefuse     Action = "refuse"
	ActionWatchAlert Action = "watch-alert"
)

// Valid reports whether a is a known action.
func (a Action) Valid() bool {
	switch a {
	case ActionPlan, ActionApprove, ActionReject, ActionApply, ActionVerify,
		ActionRollback, ActionRefuse, ActionWatchAlert:
		return true
	}
	return false
}

// Entry is one line of the log. Hash is sha256(PrevHash + canonical JSON of
// the entry with Hash empty), hex encoded.
type Entry struct {
	Seq      int             `json:"seq"`
	Time     string          `json:"time"`
	Actor    string          `json:"actor"`
	Action   Action          `json:"action"`
	PlanID   string          `json:"plan_id,omitempty"`
	Details  json.RawMessage `json:"details,omitempty"`
	PrevHash string          `json:"prev_hash"`
	Hash     string          `json:"hash"`
}

// Decode unmarshals the entry's details into v.
func (e Entry) Decode(v any) error {
	if len(e.Details) == 0 {
		return nil
	}
	return json.Unmarshal(e.Details, v)
}

// computeHash returns the chain hash of e (ignoring its current Hash).
func computeHash(e Entry) string {
	e.Hash = ""
	b, _ := json.Marshal(e)
	sum := sha256.Sum256(append([]byte(e.PrevHash), b...))
	return hex.EncodeToString(sum[:])
}

// Log is an append-only audit log file.
type Log struct {
	mu   sync.Mutex
	path string
}

// Open prepares the audit log at <stateDir>/audit.log, creating the
// directory if needed.
func Open(stateDir string) (*Log, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}
	return &Log{path: filepath.Join(stateDir, FileName)}, nil
}

// Path returns the log file path.
func (l *Log) Path() string { return l.path }

// Append adds an entry. Details are redacted (every string value) before
// they are hashed and written, and the file is fsynced.
func (l *Log) Append(actor string, action Action, planID string, details map[string]any) (Entry, error) {
	if !action.Valid() {
		return Entry{}, fmt.Errorf("unknown audit action %q", action)
	}
	raw, err := redactedJSON(details)
	if err != nil {
		return Entry{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	entries, bad, err := l.read()
	if err != nil {
		return Entry{}, err
	}
	if bad > 0 {
		return Entry{}, fmt.Errorf("audit log %s is corrupt at line %d; run verify before appending", l.path, bad)
	}
	e := Entry{
		Seq:     len(entries) + 1,
		Time:    time.Now().UTC().Format(time.RFC3339Nano),
		Actor:   redact.String(actor),
		Action:  action,
		PlanID:  planID,
		Details: raw,
	}
	if n := len(entries); n > 0 {
		e.PrevHash = entries[n-1].Hash
	}
	e.Hash = computeHash(e)
	line, err := json.Marshal(e)
	if err != nil {
		return Entry{}, err
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return Entry{}, fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return Entry{}, fmt.Errorf("write audit log: %w", err)
	}
	if err := f.Sync(); err != nil {
		return Entry{}, fmt.Errorf("sync audit log: %w", err)
	}
	return e, nil
}

// Entries returns every entry in order. It fails if a line cannot be
// parsed; use Verify to locate tampering.
func (l *Log) Entries() ([]Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	entries, bad, err := l.read()
	if err != nil {
		return nil, err
	}
	if bad > 0 {
		return nil, fmt.Errorf("audit log %s is corrupt at line %d", l.path, bad)
	}
	return entries, nil
}

// Head returns the sequence number and hash of the last entry (0, "" when
// the log is empty). Storing it elsewhere makes tail truncation detectable.
func (l *Log) Head() (int, string, error) {
	entries, err := l.Entries()
	if err != nil || len(entries) == 0 {
		return 0, "", err
	}
	last := entries[len(entries)-1]
	return last.Seq, last.Hash, nil
}

// Verify walks the chain. ok is true when every entry has the expected
// sequence number, links to its predecessor and hashes correctly. When not
// ok, brokenAt is the 1-based line of the first bad entry. err is only set
// for I/O failures.
func (l *Log) Verify() (ok bool, brokenAt int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	entries, bad, err := l.read()
	if err != nil {
		return false, 0, err
	}
	prev := ""
	for i, e := range entries {
		if e.Seq != i+1 || e.PrevHash != prev || e.Hash != computeHash(e) {
			return false, i + 1, nil
		}
		prev = e.Hash
	}
	if bad > 0 {
		return false, bad, nil
	}
	return true, 0, nil
}

// read parses the file. bad is the 1-based line of the first unparsable
// line (entries then holds everything before it); 0 means all lines parsed.
func (l *Log) read() (entries []Entry, bad int, err error) {
	f, err := os.Open(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()
	r := bufio.NewReader(f)
	for line := 1; ; line++ {
		b, rerr := r.ReadBytes('\n')
		if t := bytes.TrimSpace(b); len(t) > 0 {
			var e Entry
			if jerr := json.Unmarshal(t, &e); jerr != nil {
				return entries, line, nil
			}
			entries = append(entries, e)
		}
		if rerr == io.EOF {
			return entries, 0, nil
		}
		if rerr != nil {
			return nil, 0, fmt.Errorf("read audit log: %w", rerr)
		}
	}
}

// redactedJSON round-trips details through JSON, redacting every string,
// and returns the compact encoding (nil when there are no details).
func redactedJSON(details map[string]any) (json.RawMessage, error) {
	if len(details) == 0 {
		return nil, nil
	}
	b, err := json.Marshal(details)
	if err != nil {
		return nil, fmt.Errorf("encode audit details: %w", err)
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return json.Marshal(redactValue(v))
}

func redactValue(v any) any {
	switch t := v.(type) {
	case string:
		return redact.String(t)
	case []any:
		for i := range t {
			t[i] = redactValue(t[i])
		}
	case map[string]any:
		for k, x := range t {
			t[k] = redactValue(x)
		}
	}
	return v
}
