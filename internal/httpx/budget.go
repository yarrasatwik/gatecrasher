package httpx

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
)

// ErrBudget is returned (and no request is sent) once the request budget
// attached to the context is used up.
var ErrBudget = errors.New("request budget reached")

// Budget counts the requests one run sends and, when it has a limit, refuses
// the ones past it. Every attempt that reaches the network counts, retries
// included, so "N requests" means N requests on the wire. A Budget is safe for
// concurrent use; the limit is exact because the slot is taken atomically
// before the request is sent.
type Budget struct {
	max     int64 // 0 = count only, never refuse
	used    atomic.Int64
	refused atomic.Int64
}

// NewBudget returns a budget of max requests; max <= 0 counts without a limit.
func NewBudget(max int64) *Budget {
	if max < 0 {
		max = 0
	}
	return &Budget{max: max}
}

// Max is the limit (0 = unlimited).
func (b *Budget) Max() int64 { return b.max }

// Used is the number of requests sent under this budget.
func (b *Budget) Used() int64 { return b.used.Load() }

// Refused is the number of requests that were refused for lack of budget.
func (b *Budget) Refused() int64 { return b.refused.Load() }

// Exhausted reports that a limited budget has no requests left.
func (b *Budget) Exhausted() bool { return b.max > 0 && b.used.Load() >= b.max }

// Remaining is how many requests are left; -1 means unlimited.
func (b *Budget) Remaining() int64 {
	if b.max == 0 {
		return -1
	}
	return max(0, b.max-b.used.Load())
}

// take claims one request slot.
func (b *Budget) take() bool {
	for {
		n := b.used.Load()
		if b.max > 0 && n >= b.max {
			b.refused.Add(1)
			return false
		}
		if b.used.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

type budgetKey struct{}

// WithBudget attaches b to ctx: every Client.Do under ctx counts against it.
// A nil b detaches any budget ctx already carries (the AI client uses this so
// model calls never count as Flagsmith probes).
func WithBudget(ctx context.Context, b *Budget) context.Context {
	return context.WithValue(ctx, budgetKey{}, b)
}

// BudgetFrom returns the budget attached to ctx, or nil.
func BudgetFrom(ctx context.Context) *Budget {
	b, _ := ctx.Value(budgetKey{}).(*Budget)
	return b
}

func budgetError(b *Budget) error {
	return fmt.Errorf("%w (%d of %d)", ErrBudget, b.Used(), b.Max())
}
