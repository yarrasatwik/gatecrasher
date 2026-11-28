// Package parity cross-checks Flagsmith's offline engine against the live
// API (spec §8.7): random transient identities and trait sets are evaluated
// both ways and every flag state must agree. The run is deterministic for a
// given document and segment set, and uses transient identities only.
package parity

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"sync"

	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
	"github.com/yarrasatwik/gatecrasher/internal/mapper"
)

// workers bounds concurrent live requests.
const workers = 8

// Mismatch is one flag whose engine and live states differ.
type Mismatch struct {
	Identifier string            `json:"identifier"`
	Traits     map[string]string `json:"traits"`
	Flag       string            `json:"flag"`
	Engine     string            `json:"engine"`
	Live       string            `json:"live"`
}

// Result summarises a parity run. Checked counts identities evaluated both
// ways; Agreed those whose every flag matched; Errors those whose live call
// failed (neither agreed nor mismatched).
type Result struct {
	Checked    int        `json:"checked"`
	Agreed     int        `json:"agreed"`
	Errors     int        `json:"errors"`
	Mismatches []Mismatch `json:"mismatches,omitempty"`
}

type testCase struct {
	id     string
	traits map[string]string
}

// Live describes how the environment's public API answers, so the engine's
// result is compared with what a client can actually receive.
type Live struct {
	// IgnoresClientTraits is true when "Allow client SDKs to set user traits"
	// is off: the API then evaluates without the traits a client sends.
	IgnoresClientTraits bool
	// ServerOnly lists flags marked "Server-side only", which the API never
	// returns to client keys.
	ServerOnly map[string]bool
}

// LiveFor builds Live from the environment settings and project features.
func LiveFor(env flagsmith.Environment, features []flagsmith.Feature) Live {
	l := Live{IgnoresClientTraits: !env.AllowClientTraits, ServerOnly: map[string]bool{}}
	for _, f := range features {
		if f.IsServerKeyOnly {
			l.ServerOnly[f.Name] = true
		}
	}
	return l
}

// Run evaluates n random identities with the engine and through the live SDK
// API and compares every flag's State(). Traits are drawn from the values the
// segments' conditions mention or accept, mixed with noise, so both matching
// and non-matching inputs are covered. It stops early if ctx is cancelled,
// returning the partial result and the context error.
func Run(ctx context.Context, eng *flagsmith.Engine, sdk *flagsmith.SDK, n int, segments []flagsmith.Segment) (Result, error) {
	return RunLive(ctx, eng, sdk, n, segments, Live{})
}

// RunLive is Run for an environment whose public API answers as live says.
func RunLive(ctx context.Context, eng *flagsmith.Engine, sdk *flagsmith.SDK, n int, segments []flagsmith.Segment, live Live) (Result, error) {
	cases := generate(eng, segments, n)
	var (
		mu  sync.Mutex
		res Result
		wg  sync.WaitGroup
	)
	jobs := make(chan testCase)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for tc := range jobs {
				mism, err := check(ctx, eng, sdk, tc, live)
				mu.Lock()
				switch {
				case err != nil:
					res.Errors++
				default:
					res.Checked++
					if len(mism) == 0 {
						res.Agreed++
					}
					res.Mismatches = append(res.Mismatches, mism...)
				}
				mu.Unlock()
			}
		}()
	}
	for _, tc := range cases {
		select {
		case jobs <- tc:
			continue
		case <-ctx.Done():
		}
		break
	}
	close(jobs)
	wg.Wait()
	sort.Slice(res.Mismatches, func(i, j int) bool {
		a, b := res.Mismatches[i], res.Mismatches[j]
		if a.Identifier != b.Identifier {
			return a.Identifier < b.Identifier
		}
		return a.Flag < b.Flag
	})
	return res, ctx.Err()
}

func check(ctx context.Context, eng *flagsmith.Engine, sdk *flagsmith.SDK, tc testCase, lv Live) ([]Mismatch, error) {
	live, err := sdk.Identify(ctx, tc.id, tc.traits)
	if err != nil {
		return nil, fmt.Errorf("identify %s: %w", tc.id, err)
	}
	traits := tc.traits
	if lv.IgnoresClientTraits {
		traits = nil
	}
	want := eng.Evaluate(tc.id, traits)
	names := map[string]bool{}
	for n := range want {
		if !lv.ServerOnly[n] {
			names[n] = true
		}
	}
	for n := range live.Flags {
		names[n] = true
	}
	var out []Mismatch
	for _, name := range sortedKeys(names) {
		e, l := stateOf(want, name), stateOf(live.Flags, name)
		if e != l {
			out = append(out, Mismatch{Identifier: tc.id, Traits: tc.traits, Flag: name, Engine: e, Live: l})
		}
	}
	return out, nil
}

func stateOf(fs flagsmith.Flags, name string) string {
	f, ok := fs[name]
	if !ok {
		return "absent"
	}
	return f.State()
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// generate builds n deterministic test cases. Half start from a solver
// candidate of a random segment (so segments are actually entered), the rest
// from the trait pool; noise traits and values are mixed into both.
func generate(eng *flagsmith.Engine, segments []flagsmith.Segment, n int) []testCase {
	rng := rand.New(rand.NewSource(1))
	segs := mapper.FromAdmin(segments)
	pool := mapper.TraitPool(segs)
	keys := make([]string, 0, len(pool))
	for k := range pool {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var cands [][]mapper.Candidate
	for _, s := range segs {
		if c := mapper.Solve(s, eng.Doc.APIKey, 0); len(c) > 0 {
			cands = append(cands, c)
		}
	}
	cases := make([]testCase, 0, n)
	for i := 0; i < n; i++ {
		tc := testCase{id: fmt.Sprintf("gc-probe-parity-%d", i), traits: map[string]string{}}
		if len(cands) > 0 && rng.Intn(2) == 0 {
			c := cands[rng.Intn(len(cands))][0]
			for k, v := range c.Traits {
				tc.traits[k] = v
			}
			if c.IdentifierForged && strings.HasPrefix(c.Identifier, "gc-probe-") {
				tc.id = c.Identifier
			}
		}
		for j, extra := 0, rng.Intn(3); j < extra && len(keys) > 0; j++ {
			k := keys[rng.Intn(len(keys))]
			if vals := pool[k]; len(vals) > 0 && rng.Intn(4) != 0 {
				tc.traits[k] = vals[rng.Intn(len(vals))]
			} else {
				tc.traits[k] = fmt.Sprintf("noise-%d", rng.Intn(100))
			}
		}
		if rng.Intn(3) == 0 {
			tc.traits[fmt.Sprintf("noise_%d", rng.Intn(10))] = fmt.Sprint(rng.Intn(1000))
		}
		cases = append(cases, tc)
	}
	return cases
}
