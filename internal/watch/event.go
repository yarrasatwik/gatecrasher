package watch

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Change is what a webhook event says changed. Any field may be empty
// because Flagsmith's payload shapes differ per event type.
type Change struct {
	// Kind is the webhook event_type, e.g. FLAG_UPDATED.
	Kind        string `json:"kind"`
	Environment string `json:"environment,omitempty"`
	Feature     string `json:"feature,omitempty"`
	Segment     string `json:"segment,omitempty"`
	// EventTime is the timestamp inside the payload, zero if absent.
	EventTime time.Time `json:"event_time,omitempty"`
	// ReceivedAt is when the webhook arrived.
	ReceivedAt time.Time `json:"received_at"`
}

// Object returns the feature or segment name that changed, if known.
func (c Change) Object() string {
	if c.Feature != "" {
		return c.Feature
	}
	return c.Segment
}

// key identifies changes that debounce into one re-check.
func (c Change) key() string {
	if c.Environment == "" && c.Feature == "" && c.Segment == "" {
		return c.Kind
	}
	return c.Environment + "|" + c.Feature + "|" + c.Segment
}

// parseChange extracts a Change from a webhook body. It is deliberately
// lenient: only a missing or unparseable event_type is an error.
func parseChange(body []byte, received time.Time) (Change, error) {
	var ev struct {
		EventType string         `json:"event_type"`
		Data      map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &ev); err != nil {
		return Change{}, err
	}
	if ev.EventType == "" {
		return Change{}, errors.New("missing event_type")
	}
	c := Change{Kind: ev.EventType, ReceivedAt: received}
	d := ev.Data
	c.Environment = firstString(nameAt(d, "environment"), nameAt(d, "new_state", "environment"),
		nameAt(d, "previous_state", "environment"), strAt(d, "environment_name"))
	c.Feature = firstString(nameAt(d, "new_state", "feature"), nameAt(d, "previous_state", "feature"),
		nameAt(d, "feature"), strAt(d, "feature_name"))
	c.Segment = firstString(nameAt(d, "segment"), strAt(d, "segment_name"))
	c.EventTime = firstTime(strAt(d, "timestamp"), strAt(d, "created_date"))
	if c.Feature == "" && c.Segment == "" {
		fromAuditLog(&c, d)
	}
	return c, nil
}

// fromAuditLog fills the object name from an AUDIT_LOG_CREATED payload,
// whose "log" text names the object and whose related_object_type says
// what kind it is.
func fromAuditLog(c *Change, d map[string]any) {
	name := nameFromLog(strAt(d, "log"))
	if name == "" {
		return
	}
	kind := strings.ToUpper(strAt(d, "related_object_type"))
	switch {
	case strings.Contains(kind, "SEGMENT") && !strings.Contains(kind, "FEATURE"):
		c.Segment = name
	case strings.Contains(kind, "FEATURE"):
		c.Feature = name
	}
}

// nameFromLog pulls an object name from audit text such as
// "New Flag / Remote Config created: my_feature" or "Segment 'beta' updated".
func nameFromLog(log string) string {
	for _, q := range []string{"'", "\""} {
		if i := strings.Index(log, q); i >= 0 {
			if j := strings.Index(log[i+1:], q); j > 0 {
				return log[i+1 : i+1+j]
			}
		}
	}
	if i := strings.LastIndex(log, ": "); i >= 0 {
		return strings.TrimSpace(log[i+2:])
	}
	return ""
}

// nameAt walks path through nested objects and returns the object's "name"
// or, when the value is itself a string, that string.
func nameAt(m map[string]any, path ...string) string {
	var cur any = m
	for _, p := range path {
		obj, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = obj[p]
	}
	switch v := cur.(type) {
	case string:
		return v
	case map[string]any:
		return strAt(v, "name")
	}
	return ""
}

func strAt(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func firstString(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func firstTime(vals ...string) time.Time {
	for _, v := range vals {
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			return t
		}
	}
	return time.Time{}
}
