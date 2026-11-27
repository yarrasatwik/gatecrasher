package fixes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"
)

// AdminAPI is the slice of the Flagsmith Admin client the fix pipeline
// needs. *flagsmith.Admin satisfies it.
type AdminAPI interface {
	Do(ctx context.Context, method, path string, body, out any) error
}

// Sentinel errors. Their text is written for the human reading the CLI or
// approval card.
var (
	// ErrStalePlan means live state differs from the plan's snapshot.
	ErrStalePlan = errors.New("state changed since plan; re-plan")
	// ErrNotApproved means the plan has no approval attached.
	ErrNotApproved = errors.New("this plan has not been approved; approve it first")
	// ErrApprovalExpired means the approval is older than its TTL.
	ErrApprovalExpired = errors.New("the approval has expired; approve the plan again")
	// ErrPlanTampered means the plan no longer matches its hash or approval.
	ErrPlanTampered = errors.New("the plan was modified after it was created or approved (hash mismatch); re-plan and approve again")
	// ErrConfirmEnvironment means a Production approval lacked the typed name.
	ErrConfirmEnvironment = errors.New("this is a Production environment: type its exact name to confirm")
	// ErrConfirmContaminate means a running experiment needs typed consent.
	ErrConfirmContaminate = errors.New("the flag is under a running experiment: type " + ContaminateToken + " to confirm")
	// ErrNothingToApply means the plan only holds guidance (PR drafts, manual steps).
	ErrNothingToApply = errors.New("this plan has no automatic operations; follow its PR draft and manual steps instead")
)

// getJSON performs a GET and decodes the response into out.
func getJSON(ctx context.Context, a AdminAPI, path string, out any) error {
	return a.Do(ctx, "GET", path, nil, out)
}

// getList reads a list endpoint that is either a bare array or a paginated
// {results,next} object.
func getList[T any](ctx context.Context, a AdminAPI, path string) ([]T, error) {
	var all []T
	next := path
	for page := 0; next != "" && page < 100; page++ {
		var raw json.RawMessage
		if err := getJSON(ctx, a, next, &raw); err != nil {
			return nil, err
		}
		if strings.HasPrefix(strings.TrimSpace(string(raw)), "[") {
			var items []T
			if err := json.Unmarshal(raw, &items); err != nil {
				return nil, err
			}
			return append(all, items...), nil
		}
		var pg struct {
			Results []T     `json:"results"`
			Next    *string `json:"next"`
		}
		if err := json.Unmarshal(raw, &pg); err != nil {
			return nil, err
		}
		all = append(all, pg.Results...)
		next = ""
		if pg.Next != nil {
			next = *pg.Next
		}
	}
	return all, nil
}

// liveObject reads one object as a generic map.
func liveObject(ctx context.Context, a AdminAPI, path string) (map[string]any, error) {
	var m map[string]any
	if err := getJSON(ctx, a, path, &m); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return m, nil
}

// pick returns the named fields of m (missing fields become nil).
func pick(m map[string]any, keys []string) map[string]any {
	out := make(map[string]any, len(keys))
	for _, k := range keys {
		out[k] = m[k]
	}
	return out
}

// sortedKeys returns the keys of m in deterministic order.
func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// jsonEqual compares two decoded JSON values by their canonical encoding,
// so int/float64 representations of the same number compare equal.
func jsonEqual(a, b any) bool {
	if reflect.DeepEqual(a, b) {
		return true
	}
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(x) == string(y)
}

func envPath(key string) string { return "environments/" + url.PathEscape(key) + "/" }
