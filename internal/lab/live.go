package lab

import (
	"context"
	"fmt"
	"time"
)

// WaitLive blocks until the live SDK API serves the seeded state in every
// environment: a transient identity with plan=gold must receive
// premium_export. Flagsmith's SDK endpoints can serve a cached environment
// for several seconds after a write; waiting here makes the very next audit
// (and engine-vs-live parity) see exactly what the environment document says.
func WaitLive(ctx context.Context, st *State, apiURL string, timeout time.Duration) (time.Duration, error) {
	a, err := newAPI(apiURL)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	deadline := start.Add(timeout)
	body := map[string]any{"identifier": "gc-probe-lab-ready", "transient": true,
		"traits": []map[string]any{{"trait_key": "plan", "trait_value": "gold", "transient": true}}}
	for {
		ready := true
		for _, env := range st.Environments {
			var res struct {
				Flags []struct {
					Feature struct {
						Name string `json:"name"`
					} `json:"feature"`
					Enabled bool `json:"enabled"`
				} `json:"flags"`
			}
			if err := a.call(ctx, clientKeyAuth(env.ClientKey), "POST", "identities/", body, &res); err != nil {
				ready = false
				break
			}
			ok := false
			for _, f := range res.Flags {
				if f.Feature.Name == "premium_export" && f.Enabled {
					ok = true
				}
			}
			ready = ready && ok
		}
		if ready {
			return time.Since(start), nil
		}
		if time.Now().After(deadline) {
			return time.Since(start), fmt.Errorf("live API still serves the previous state after %s", timeout)
		}
		select {
		case <-ctx.Done():
			return time.Since(start), ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

