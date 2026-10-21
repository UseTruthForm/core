package awscc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// World is a set of fake AWS accounts that share one ID space, like the real
// thing: every generated ID belongs to exactly one account.
//
// That is what makes the fake worth testing against. A restore that forgets
// to remap a reference sends the source account's vpc-... to the target, and
// a fake that accepted any string would let that pass while real AWS
// answers InvalidVpcID.NotFound. Here the target refuses it the same way.
type World struct {
	mu    sync.Mutex
	reg   *Registry
	owner map[string]string // generated value -> account
	seq   int
}

// NewWorld creates an empty world whose accounts serve the registry's types.
func NewWorld(reg *Registry) *World {
	return &World{reg: reg, owner: map[string]string{}}
}

// Fake is one account and region of a World. It is schema driven: it knows
// no AWS type, only what each type's registry schema says. It rejects
// unknown, read-only and missing required properties, generates read-only
// values on create, keeps write-only values but never returns them, filters
// parent-scoped lists, and pages lists two at a time so pagination is
// always exercised.
type Fake struct {
	w          *World
	ID, Region string
	res        map[string]map[string]map[string]any // type -> id -> props
	order      map[string][]string                  // creation order, per type
	// Unsupported types answer ErrUnsupported, as a service missing from a
	// region does.
	Unsupported map[string]bool
	// AfterCreate lets a test add what AWS does as a side effect of a
	// create, such as the root resource of a REST API. The fake itself
	// knows no AWS type. It runs without the lock held and may Seed.
	AfterCreate func(typeName string, props map[string]any)
	// Validate lets a test refuse what AWS refuses although the schema
	// allows it.
	Validate func(typeName string, desired map[string]any) error
	// ListError lets a test refuse a list for some inputs, as AWS refuses
	// WAFv2 Scope CLOUDFRONT outside us-east-1.
	ListError func(typeName string, model map[string]any) error
	// Unreadable resources are listed but fail on read, as AWS's own
	// built-ins do (CodePipeline's "Source|S3|1"). Keyed "Type|identifier".
	Unreadable map[string]bool
}

// Account returns a new empty account in the world.
func (w *World) Account(account, region string) *Fake {
	return &Fake{w: w, ID: account, Region: region,
		res: map[string]map[string]map[string]any{}, order: map[string][]string{}, Unsupported: map[string]bool{}}
}

func (f *Fake) typ(name string) (*TypeInfo, error) {
	if f.Unsupported[name] {
		return nil, fmt.Errorf("%s: %w", name, ErrUnsupported)
	}
	t := f.w.reg.Types[name]
	if t == nil {
		return nil, fmt.Errorf("%s: %w", name, ErrUnsupported)
	}
	return t, nil
}

// Create validates desired against the schema and stores it.
func (f *Fake) Create(_ context.Context, typeName string, desired map[string]any) (string, error) {
	t, err := f.typ(typeName)
	if err != nil {
		return "", err
	}
	if !t.Handlers["create"] {
		return "", fmt.Errorf("%s has no create handler", typeName)
	}
	f.w.mu.Lock()
	defer f.w.mu.Unlock()
	props := deepCopy(desired)
	for k := range props {
		if _, ok := t.Properties[k]; !ok {
			return "", fmt.Errorf("%s: extraneous key [%s] is not permitted", typeName, k)
		}
		if t.IsReadOnly(k) {
			return "", fmt.Errorf("%s: read-only property [%s] cannot be set", typeName, k)
		}
	}
	for _, r := range t.Required {
		if _, ok := props[r]; !ok {
			return "", fmt.Errorf("%s: required key [%s] not found", typeName, r)
		}
	}
	var bad error
	walkStrings(props, func(s string) string {
		if bad == nil {
			if strings.Contains(s, "{{stackdna") {
				bad = fmt.Errorf("%s: unresolved StackDNA reference %q sent to AWS", typeName, s)
			}
			for v, acct := range f.w.owner {
				if acct != f.ID && strings.Contains(s, v) {
					bad = fmt.Errorf("%s: %q refers to %s, which belongs to account %s and does not exist in %s", typeName, s, v, acct, f.ID)
				}
			}
		}
		return s
	})
	if bad != nil {
		return "", bad
	}
	if f.Validate != nil {
		if err := f.Validate(typeName, props); err != nil {
			return "", err
		}
	}
	f.generate(t, props)
	id, ok := Identifier(t, props)
	if !ok {
		return "", fmt.Errorf("%s: no primary identifier after create", typeName)
	}
	if f.res[typeName] == nil {
		f.res[typeName] = map[string]map[string]any{}
	}
	if _, dup := f.res[typeName][id]; dup {
		return "", fmt.Errorf("%s %s already exists", typeName, id)
	}
	f.res[typeName][id] = props
	f.order[typeName] = append(f.order[typeName], id)
	if f.AfterCreate != nil {
		f.w.mu.Unlock()
		f.AfterCreate(typeName, props)
		f.w.mu.Lock()
	}
	return id, nil
}

// Seed stores a resource without validation, for what AWS itself creates
// (service-linked roles) or tags (aws:cloudformation:*), which a caller of
// the API cannot.
func (f *Fake) Seed(typeName string, props map[string]any) string {
	f.w.mu.Lock()
	defer f.w.mu.Unlock()
	t := f.w.reg.Types[typeName]
	p := deepCopy(props)
	f.generate(t, p)
	id, _ := Identifier(t, p)
	if f.res[typeName] == nil {
		f.res[typeName] = map[string]map[string]any{}
	}
	f.res[typeName][id] = p
	f.order[typeName] = append(f.order[typeName], id)
	return id
}

// generate fills read-only top-level properties, and a missing user-chosen
// identifier (AWS names an unnamed bucket itself).
func (f *Fake) generate(t *TypeInfo, props map[string]any) {
	for _, p := range t.PrimaryIdentifier {
		if _, ok := props[p]; !ok && !t.IsReadOnly(p) {
			props[p] = f.newValue(t, p, props)
		}
	}
	for _, ptr := range t.ReadOnly {
		s := segments(ptr)
		if len(s) != 1 {
			continue
		}
		if ps, _ := t.Properties[s[0]].(map[string]any); ps["type"] == "string" || ps["type"] == nil {
			props[s[0]] = f.newValue(t, s[0], props)
		}
	}
	// Arns and URLs name the resource, so they are made after the IDs.
	for _, ptr := range t.ReadOnly {
		if s := segments(ptr); len(s) == 1 && (strings.HasSuffix(s[0], "Arn") || strings.HasSuffix(s[0], "Url")) {
			props[s[0]] = f.named(t, s[0], props)
		}
	}
}

func (f *Fake) newValue(t *TypeInfo, prop string, props map[string]any) string {
	f.w.seq++
	h := sha256.Sum256([]byte(fmt.Sprintf("%s/%d", f.ID, f.w.seq)))
	x := hex.EncodeToString(h[:])
	var v string
	switch {
	case t.Service() == "EC2" && strings.HasSuffix(prop, "Id"):
		v = strings.ToLower(t.Short()) + "-" + x[:17]
	case strings.HasSuffix(prop, "Id"):
		v = x[:10]
	default:
		v = strings.ToLower(prop) + "-" + x[:8]
	}
	f.w.owner[v] = f.ID
	return v
}

func (f *Fake) named(t *TypeInfo, prop string, props map[string]any) string {
	name := ""
	if id, ok := Identifier(t, props); ok {
		name = id
	}
	for _, k := range []string{t.Short() + "Name", "Name"} {
		if s, ok := props[k].(string); ok {
			name = s
		}
	}
	svc := strings.ToLower(t.Service())
	var v string
	if strings.HasSuffix(prop, "Url") {
		v = "https://" + svc + "." + f.Region + ".amazonaws.com/" + f.ID + "/" + name
	} else {
		region := f.Region
		if svc == "iam" {
			region = ""
		}
		v = "arn:aws:" + svc + ":" + region + ":" + f.ID + ":" + strings.ToLower(t.Short()) + "/" + name
	}
	f.w.owner[v] = f.ID
	return v
}

// Get returns the stored properties minus every write-only pointer.
func (f *Fake) Get(_ context.Context, typeName, id string) (map[string]any, error) {
	t, err := f.typ(typeName)
	if err != nil {
		return nil, err
	}
	f.w.mu.Lock()
	defer f.w.mu.Unlock()
	p, ok := f.res[typeName][id]
	if !ok {
		return nil, fmt.Errorf("%s %s: %w", typeName, id, ErrNotFound)
	}
	if f.Unreadable[typeName+"|"+id] {
		return nil, fmt.Errorf("%s Handler returned status FAILED: Service returned error code InternalFailure (Service: Fake, Request ID: 1234)", typeName)
	}
	out := deepCopy(p)
	for _, ptr := range t.WriteOnly {
		removePointer(out, ptr)
	}
	return out, nil
}

// Stored returns what the fake holds, write-only values included, so a test
// can prove a write-only value really arrived.
func (f *Fake) Stored(typeName, id string) map[string]any {
	f.w.mu.Lock()
	defer f.w.mu.Unlock()
	return deepCopy(f.res[typeName][id])
}

// IDs returns a type's identifiers in creation order.
func (f *Fake) IDs(typeName string) []string {
	f.w.mu.Lock()
	defer f.w.mu.Unlock()
	return append([]string(nil), f.order[typeName]...)
}

const fakePage = 2

// List pages through identifiers newest first, filtered by the model.
func (f *Fake) List(_ context.Context, typeName string, model map[string]any, token string) ([]string, string, error) {
	t, err := f.typ(typeName)
	if err != nil {
		return nil, "", err
	}
	if f.ListError != nil {
		if err := f.ListError(typeName, model); err != nil {
			return nil, "", err
		}
	}
	for _, r := range t.ListRequires {
		if _, ok := model[r]; !ok {
			return nil, "", fmt.Errorf("%s list: required key [%s] not found", typeName, r)
		}
	}
	f.w.mu.Lock()
	defer f.w.mu.Unlock()
	var ids []string
	order := f.order[typeName]
	for i := len(order) - 1; i >= 0; i-- {
		p := f.res[typeName][order[i]]
		match := true
		for k, v := range model {
			if p[k] != v {
				match = false
			}
		}
		if match {
			ids = append(ids, order[i])
		}
	}
	start := 0
	if token != "" {
		fmt.Sscanf(token, "%d", &start)
	}
	end := start + fakePage
	if end >= len(ids) {
		return ids[start:], "", nil
	}
	return ids[start:end], fmt.Sprint(end), nil
}

// Account returns the fake account's ID.
func (f *Fake) Account(context.Context) (string, error) { return f.ID, nil }

// Count returns how many resources the account holds, for tests.
func (f *Fake) Count() map[string]int {
	f.w.mu.Lock()
	defer f.w.mu.Unlock()
	out := map[string]int{}
	for t, m := range f.res {
		out[t] = len(m)
	}
	return out
}

var _ CloudControl = (*Fake)(nil)

func sortedKeys[M ~map[string]V, V any](m M) []string {
	k := make([]string, 0, len(m))
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}
