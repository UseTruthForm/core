package awscc

import (
	"context"
	"errors"
	"math/rand/v2"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/stackdna/core/internal/snapshot"
)

// Tuning controls how hard a capture drives the API. It never changes what
// is captured: results are put in a fixed order before they are named, so
// any setting produces the same snapshot.
type Tuning struct {
	// Parallel caps API calls in flight across all types. Cloud Control
	// throttles per account; the SDK's adaptive retry absorbs bursts, and
	// the cap keeps the burst it has to absorb bounded. 0 means 8.
	Parallel int
	// Progress, if set, is called after each selected type is read. Calls
	// are serialized, so the callback needs no locking of its own.
	Progress func(Progress)
}

// Progress reports how far a capture has got.
type Progress struct {
	Types, TotalTypes, Resources int
	Type                         string
}

// inv holds what was read, per type, and why any type was not.
type inv struct {
	ctx     context.Context
	api     CloudControl
	reg     *Registry
	account string
	sem     chan struct{}

	mu    sync.Mutex
	got   map[string][]*resource
	cov   map[string]*snapshot.Coverage
	done  map[string]chan struct{}
	cycle map[string]bool

	types, resources atomic.Int64
	// early holds resources skipped before naming: AWS-owned ones and
	// those listed but unreadable. They are recorded by identifier.
	early []snapshot.Skip
}

func (in *inv) skip(s snapshot.Skip) {
	in.mu.Lock()
	in.early = append(in.early, s)
	in.mu.Unlock()
}

// inherit gives a child the parent's reason when the parent was not
// captured. A parent that is not set up, or cannot be listed at all (a
// legacy type, an underivable parent), makes the child the same kind of gap;
// only a parent that failed makes the child fail.
func inherit(parent, reason string) string {
	why := "parent " + parent + " was not captured (" + reason + ")"
	switch {
	case strings.HasPrefix(reason, "list failed"):
		return "list failed: " + why
	case strings.HasPrefix(reason, NotSetUp), strings.HasPrefix(reason, "not available"):
		return NotSetUp + why
	}
	return NeedsInput + why
}

// Prefixes of coverage and skip reasons that the CLI groups in its summary.
const (
	NotSetUp   = "not set up in this account: "
	NeedsInput = "cannot be listed without input its schema does not declare: "
	Unreadable = "listed but could not be read: "
)

// inventory reads every wanted type, several at a time. A type listed per
// parent reads its parent first; if another worker is already reading the
// parent it waits for that result instead of reading it twice.
func inventory(ctx context.Context, api CloudControl, reg *Registry, want func(string) bool, tun Tuning) (*inv, error) {
	if tun.Parallel <= 0 {
		tun.Parallel = 8
	}
	// Without the account, resources another account owns cannot be told
	// apart from this one's, so a capture refuses to start rather than
	// quietly capturing AWS's patch baselines as the customer's.
	account, err := api.Account(ctx)
	if err != nil {
		return nil, err
	}
	in := &inv{ctx: ctx, api: api, reg: reg, account: account, sem: make(chan struct{}, tun.Parallel),
		got: map[string][]*resource{}, cov: map[string]*snapshot.Coverage{},
		done: map[string]chan struct{}{}, cycle: parentCycles(reg)}
	var wanted []string
	for _, n := range sortedKeys(reg.Types) {
		if want(n) {
			wanted = append(wanted, n)
		} else {
			in.cov[n] = &snapshot.Coverage{Resource: n, Kind: n}
		}
	}
	// Interleaved by service: in name order, eight workers hit one service's
	// types together (the DataSync family) and it throttles all of them.
	wanted = interleave(wanted)
	work := make(chan string)
	var wg sync.WaitGroup
	var progressMu sync.Mutex
	for i := 0; i < tun.Parallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := range work {
				in.read(n)
				done := in.types.Add(1)
				if tun.Progress != nil {
					progressMu.Lock()
					tun.Progress(Progress{Types: int(done), TotalTypes: len(wanted), Resources: int(in.resources.Load()), Type: n})
					progressMu.Unlock()
				}
			}
		}()
	}
	for _, n := range wanted {
		work <- n
	}
	close(work)
	wg.Wait()

	// Types that still failed only because the account was throttled get
	// one more try once the burst is over.
	// All are cleared before any is read again, so a child retried before
	// its throttled parent reads the parent afresh instead of inheriting
	// the old failure.
	var again []string
	in.mu.Lock()
	for _, n := range wanted {
		if c := in.cov[n]; c != nil && throttled(c.NotCaptured) {
			delete(in.done, n)
			again = append(again, n)
		}
	}
	in.mu.Unlock()
	for _, n := range again {
		in.read(n)
	}
	return in, nil
}

// interleave orders type names round-robin across services, keeping each
// service's own order.
func interleave(names []string) []string {
	var services []string
	by := map[string][]string{}
	for _, n := range names {
		s := part(n, 1)
		if _, ok := by[s]; !ok {
			services = append(services, s)
		}
		by[s] = append(by[s], n)
	}
	out := make([]string, 0, len(names))
	for len(out) < len(names) {
		for _, s := range services {
			if len(by[s]) > 0 {
				out = append(out, by[s][0])
				by[s] = by[s][1:]
			}
		}
	}
	return out
}

func throttled(reason string) bool {
	return strings.HasPrefix(reason, "list failed") &&
		(strings.Contains(reason, "Throttling") || strings.Contains(reason, "Rate exceeded") || strings.Contains(reason, "retry quota"))
}

// parentCycles finds types whose chain of parent types loops. Found up
// front, because with workers waiting on each other's results a cycle met
// at read time would deadlock instead of failing.
func parentCycles(reg *Registry) map[string]bool {
	out := map[string]bool{}
	for _, n := range sortedKeys(reg.Types) {
		seen := map[string]bool{n: true}
		for cur := n; ; {
			t := reg.Types[cur]
			if t == nil || len(t.ListRequires) == 0 {
				break
			}
			plan, reason := reg.Plan(t)
			if reason != "" || plan.ParentType == "" {
				break
			}
			if seen[plan.ParentType] {
				out[n] = true
				break
			}
			seen[plan.ParentType] = true
			cur = plan.ParentType
		}
	}
	return out
}

// read returns a type's resources, reading them unless another worker has
// already done so or is doing so now.
func (in *inv) read(n string) []*resource {
	in.mu.Lock()
	if ch, ok := in.done[n]; ok {
		in.mu.Unlock()
		<-ch
		in.mu.Lock()
		defer in.mu.Unlock()
		return in.got[n]
	}
	ch := make(chan struct{})
	in.done[n] = ch
	c := &snapshot.Coverage{Resource: n, Kind: n}
	in.cov[n] = c
	in.mu.Unlock()

	rs := in.readType(n, c)
	in.mu.Lock()
	if c.NotCaptured == "" {
		in.got[n] = rs
	}
	in.mu.Unlock()
	close(ch)
	return rs
}

func (in *inv) coverage(n string) *snapshot.Coverage {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.cov[n]
}

// call runs one API call inside the in-flight limit.
// call runs one API call inside the in-flight limit, and retries it while
// AWS throttles, waiting with the slot released. A full capture stalled for
// 21 minutes when the SDK retried inside the slot: 34 reads that fail with
// HTTP 500 (CodePipeline's built-in action types), each retried for minutes,
// held all eight slots and no other type progressed.
func (in *inv) call(f func() error) {
	for attempt := 0; ; attempt++ {
		in.sem <- struct{}{}
		err := f()
		<-in.sem
		if err == nil || !isThrottle(err) || attempt == throttleRetries {
			return
		}
		wait := time.Duration(1<<min(attempt, 6)) * time.Second // 1s .. 64s
		select {
		case <-in.ctx.Done():
			return
		case <-time.After(wait + time.Duration(rand.Int64N(int64(wait)))):
		}
	}
}

// throttleRetries bounds the waiting: about 10 minutes at most per call.
const throttleRetries = 12

func isThrottle(err error) bool {
	s := err.Error()
	return strings.Contains(s, "Throttling") || strings.Contains(s, "Rate exceeded") ||
		strings.Contains(s, "TooManyRequests") || strings.Contains(s, "retry quota")
}

// readType lists and reads every resource of a type. Every way it can fail
// ends in the coverage report, never in a silently smaller snapshot.
func (in *inv) readType(n string, c *snapshot.Coverage) []*resource {
	t := in.reg.Types[n]
	switch {
	case len(t.Handlers) == 0:
		c.NotCaptured = "legacy type: CloudFormation only, Cloud Control has no handlers for it"
		return nil
	case !t.Capturable():
		c.NotCaptured = "Cloud Control cannot list or read this type"
		return nil
	case in.cycle[n]:
		c.NotCaptured = "parent types form a cycle"
		return nil
	}
	plan, reason := in.reg.Plan(t)
	if reason != "" {
		c.NotCaptured = "parent not derivable from the schemas: " + reason
		return nil
	}
	models := []map[string]any{{}}
	if plan.ParentType != "" {
		models = nil
		for _, pr := range in.read(plan.ParentType) {
			m := map[string]any{}
			for param, prop := range plan.FromParent {
				if v, ok := pr.props[prop]; ok {
					m[param] = v
				}
			}
			if len(m) == len(plan.FromParent) {
				models = append(models, m)
			}
		}
		if pc := in.coverage(plan.ParentType); pc.NotCaptured != "" {
			c.NotCaptured = inherit(plan.ParentType, pc.NotCaptured)
			return nil
		}
	}
	for _, param := range sortedKeys(plan.Enums) {
		var next []map[string]any
		for _, m := range models {
			for _, v := range plan.Enums[param] {
				mm := map[string]any{param: v}
				for k, x := range m {
					mm[k] = x
				}
				next = append(next, mm)
			}
		}
		models = next
	}

	var ids []string
	seen := map[string]bool{}
	rejected := 0
models:
	for _, model := range models {
		token := ""
		for {
			var page []string
			var next string
			var err error
			in.call(func() error { page, next, err = in.api.List(in.ctx, n, model, token); return err })
			// A schema enum can hold values a region refuses: WAFv2 lists
			// Scope CLOUDFRONT only in us-east-1, and the full us-east-2
			// capture lost every WAFv2 type to it. A rejected value is
			// skipped; the type fails only if every value is rejected.
			if err != nil && len(plan.Enums) > 0 && strings.Contains(err.Error(), "InvalidRequest") && rejected+1 < len(models) {
				rejected++
				continue models
			}
			if err != nil {
				switch {
				case errors.Is(err, ErrUnsupported):
					c.NotCaptured = "not available in this account or region"
				case errors.Is(err, ErrNotSetUp):
					c.NotCaptured = NotSetUp + err.Error()
				case errors.Is(err, ErrNeedsInput):
					c.NotCaptured = NeedsInput + err.Error()
				default:
					c.NotCaptured = "list failed: " + cleanMessage(err.Error())
				}
				return nil
			}
			for _, id := range page {
				// Overlapping lists (two enum values, two parents) must not
				// yield one resource twice, which would capture it twice
				// under two names.
				if !seen[id] {
					seen[id] = true
					ids = append(ids, id)
				}
			}
			if next == "" {
				break
			}
			token = next
		}
	}

	// Reads run in parallel; results keep list order by index and are then
	// sorted by identifier, so the order never depends on timing or on the
	// order AWS happened to list them in.
	kept := ids[:0]
	for _, id := range ids {
		if why := ownedByID(n, id, in.account); why != "" {
			in.skip(snapshot.Skip{Resource: n, Name: id, Reason: why})
			continue
		}
		kept = append(kept, id)
	}
	ids = kept
	props := make([]map[string]any, len(ids))
	errs := make([]error, len(ids))
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			in.call(func() error { props[i], errs[i] = in.api.Get(in.ctx, n, id); return errs[i] })
		}()
	}
	wg.Wait()
	out := []*resource{}
	for i, id := range ids {
		switch {
		case errors.Is(errs[i], ErrNotFound):
			continue // deleted between list and read
		case errs[i] != nil:
			// One unreadable resource no longer drops its whole type (the
			// full capture lost CodePipeline's types to AWS's own built-in
			// "Source|S3|1", whose read fails). It is recorded by
			// identifier, and the capture still reports itself incomplete.
			in.skip(snapshot.Skip{Resource: n, Name: id, Reason: Unreadable + cleanMessage(errs[i].Error())})
			continue
		}
		if why := ownedByProps(t, props[i], in.account); why != "" {
			in.skip(snapshot.Skip{Resource: n, Name: id, Reason: why})
			continue
		}
		out = append(out, normalize(t, id, props[i]))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	in.resources.Add(int64(len(out)))
	return out
}
