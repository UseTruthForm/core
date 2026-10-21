package awscc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"reflect"
	"sort"
	"strings"

	"github.com/stackdna/core/internal/snapshot"
)

// APIVersion is the apiVersion of every AWS object in a snapshot. The AWS
// type name is the kind, so object files are grouped per type exactly as
// Kubernetes kinds are.
const APIVersion = "aws.stackdna.org/v1"

const (
	annWriteOnly = "stackdna.org/write-only"
	refPrefix    = "{{stackdna|"
)

// Policy is the set of capture rules. Its Name is recorded in the snapshot
// and diff refuses to compare captures taken under different rules.
type Policy struct {
	// Types limits the capture to matching type names (path.Match patterns
	// such as AWS::S3::*). Empty means every type the registry can capture.
	Types []string
	// CaptureManaged also captures resources a CloudFormation stack or an
	// AWS service owns. By default they are skipped, as Flux-rendered
	// Kubernetes objects are: their owner recreates them, and restoring
	// them as well makes two owners.
	CaptureManaged bool
	// Baseline is a capture of a fresh account and region. Resources
	// identical to it (the default VPC and its subnets) are AWS's own and
	// are skipped; a modified one differs and is captured.
	Baseline       map[string]map[string]any
	BaselineDigest string
}

// WithBaseline adds a baseline snapshot to the policy. It can be called once
// per region: a cross-region restore is diffed against the target region,
// whose default subnets sit in other zones, so both regions' baselines must
// be in the policy the snapshot was captured with.
func (p Policy) WithBaseline(b snapshot.Snapshot, digest string) Policy {
	merged := map[string]map[string]any{}
	for k, v := range p.Baseline {
		merged[k] = v
	}
	for _, o := range b.Objects {
		merged[o.Key()] = o.Body
	}
	p.Baseline = merged
	if p.BaselineDigest != "" {
		digest = p.BaselineDigest + "," + digest
	}
	p.BaselineDigest = digest
	return p
}

// Name describes the policy for the snapshot manifest.
func (p Policy) Name() string {
	n := "default"
	if p.CaptureManaged {
		n += "+managed"
	}
	if len(p.Types) > 0 {
		t := append([]string(nil), p.Types...)
		sort.Strings(t)
		n += "+types:" + strings.Join(t, ",")
	}
	if p.BaselineDigest != "" {
		n += "+baseline:" + p.BaselineDigest
	}
	return n
}

func (p Policy) selected(typeName string) bool {
	if len(p.Types) == 0 {
		return true
	}
	for _, pat := range p.Types {
		if ok, _ := path.Match(pat, typeName); ok {
			return true
		}
	}
	return false
}

// resource is one live resource as read, before it becomes an object.
type resource struct {
	t     *TypeInfo
	id    string
	props map[string]any // as Get returned them
	spec  map[string]any // props minus read-only and write-only values
	stat  map[string]any // read-only values, kept for reference mapping
	base  string         // logical name chosen by the user, if any
	name  string         // final logical name
	// createdBy is the resource AWS created this one with, as a side effect
	// (a REST API's root resource). attr is the parent's property holding it.
	createdBy *resource
	createdAt string
}

func (r *resource) key() string { return APIVersion + "|" + r.t.Name + "||" + r.name }

// Capture reads every selected type and writes it as snapshot objects.
func Capture(ctx context.Context, api CloudControl, reg *Registry, region string, p Policy) (snapshot.Snapshot, error) {
	in := inventory(ctx, api, reg, p.selected)
	snap := snapshot.Snapshot{Platform: "aws", ServerVersion: "cloudcontrol/" + region, Policy: p.Name()}

	for _, r := range in.named() {
		if !p.selected(r.t.Name) {
			continue // read only because a selected type is listed per parent
		}
		obj := toObject(r)
		skip := ""
		if r.createdBy != nil {
			skip = fmt.Sprintf("created by AWS with %s/%s (its %s); restoring that recreates it", r.createdBy.t.Name, r.createdBy.name, r.createdAt)
		}
		if skip == "" && !p.CaptureManaged {
			skip = managedBy(r)
		}
		if skip == "" && p.Baseline != nil {
			if b, ok := p.Baseline[r.key()]; ok && sameSpec(obj, b) {
				skip = "identical to the account baseline (AWS creates it in every account)"
			}
		}
		cov := in.cov[r.t.Name]
		if skip != "" {
			snap.Skips = append(snap.Skips, snapshot.Skip{Resource: r.t.Name, Name: r.name, Reason: skip})
			if cov.Skipped == nil {
				cov.Skipped = map[string]int{}
			}
			cov.Skipped[skip]++
			continue
		}
		cov.Captured++
		snap.Objects = append(snap.Objects, snapshot.Object{Body: obj})
	}

	for _, n := range sortedKeys(in.cov) {
		c := in.cov[n]
		if !p.selected(n) {
			c.NotCaptured = "not selected (--types)"
		}
		snap.Coverage = append(snap.Coverage, *c)
		// Fingerprinted only for types in use: the registry has ~1,850
		// types and schema-diff is about the APIs this system depends on.
		if c.NotCaptured == "" && (c.Captured > 0 || len(c.Skipped) > 0) {
			f := reg.Types[n].Fields()
			snap.Schemas = append(snap.Schemas, snapshot.TypeSchema{APIVersion: APIVersion, Kind: n, Digest: FieldsDigest(f), Fields: f})
		}
	}
	sort.Slice(snap.Objects, func(i, j int) bool { return snap.Objects[i].Key() < snap.Objects[j].Key() })
	sort.Slice(snap.Skips, func(i, j int) bool {
		a, b := snap.Skips[i], snap.Skips[j]
		return a.Resource+"|"+a.Name < b.Resource+"|"+b.Name
	})
	return snap, nil
}

// inv holds what was read, per type, and why any type was not.
type inv struct {
	ctx  context.Context
	api  CloudControl
	reg  *Registry
	got  map[string][]*resource
	cov  map[string]*snapshot.Coverage
	busy map[string]bool
}

func inventory(ctx context.Context, api CloudControl, reg *Registry, want func(string) bool) *inv {
	in := &inv{ctx: ctx, api: api, reg: reg, got: map[string][]*resource{}, cov: map[string]*snapshot.Coverage{}, busy: map[string]bool{}}
	for _, n := range sortedKeys(reg.Types) {
		if want(n) {
			in.read(n)
		} else if in.cov[n] == nil {
			in.cov[n] = &snapshot.Coverage{Resource: n, Kind: n}
		}
	}
	return in
}

// named returns every resource read, with logical names and references
// tokenized.
func (in *inv) named() []*resource {
	var out []*resource
	for _, n := range sortedKeys(in.got) {
		out = append(out, in.got[n]...)
	}
	markCreatedBy(out)
	name(out)
	return out
}

// markCreatedBy finds resources AWS creates as a side effect of creating
// another: the other resource reports the child's generated ID as one of its
// own read-only properties. API Gateway lists a REST API's root resource "/"
// (found in the first real-account drill, 2026-10-21); the REST API reports
// it as RootResourceId. A VPC reports its default security group and network
// ACL the same way. Restoring such a child would fail (the root has no
// ParentId) or duplicate it, so it is skipped, and references to its ID are
// made through the parent's property instead.
func markCreatedBy(rs []*resource) {
	type src struct {
		r    *resource
		attr string
	}
	reported := map[string]src{}
	for _, r := range rs {
		for _, k := range sortedKeys(r.stat) {
			v, ok := r.stat[k].(string)
			if !ok || k == "identifier" || strings.Contains(k, ".") || hasString(r.t.PrimaryIdentifier, k) {
				continue
			}
			if _, taken := reported[v]; !taken {
				reported[v] = src{r, k}
			}
		}
	}
	for _, r := range rs {
		for _, p := range r.t.PrimaryIdentifier {
			v, _ := r.props[p].(string)
			if s, ok := reported[v]; ok && v != "" && r.t.IsReadOnly(p) && s.r != r {
				r.createdBy, r.createdAt = s.r, s.attr
			}
		}
	}
}

func hasString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// read lists and reads every resource of a type, listing its parents first
// when the type can only be listed per parent. Every way it can fail ends
// in the coverage report, never in a silently smaller snapshot.
func (in *inv) read(n string) []*resource {
	if rs, ok := in.got[n]; ok {
		return rs
	}
	if c := in.cov[n]; c != nil && c.NotCaptured != "" {
		return nil
	}
	c := &snapshot.Coverage{Resource: n, Kind: n}
	in.cov[n] = c
	t := in.reg.Types[n]
	switch {
	case len(t.Handlers) == 0:
		c.NotCaptured = "legacy type: CloudFormation only, Cloud Control has no handlers for it"
		return nil
	case !t.Capturable():
		c.NotCaptured = "Cloud Control cannot list or read this type"
		return nil
	}
	in.busy[n] = true
	defer delete(in.busy, n)

	plan, reason := in.reg.Plan(t)
	switch {
	case reason != "":
		c.NotCaptured = "parent not derivable from the schemas: " + reason
		return nil
	case plan.ParentType != "" && in.busy[plan.ParentType]:
		c.NotCaptured = "parent types form a cycle"
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
		if pc := in.cov[plan.ParentType]; pc.NotCaptured != "" {
			c.NotCaptured = "list failed: parent " + plan.ParentType + " could not be read (" + pc.NotCaptured + ")"
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

	out := []*resource{}
	for _, model := range models {
		token := ""
		for {
			ids, next, err := in.api.List(in.ctx, n, model, token)
			if err != nil {
				if errors.Is(err, ErrUnsupported) {
					c.NotCaptured = "not available in this account or region"
				} else {
					c.NotCaptured = "list failed: " + err.Error()
				}
				return nil
			}
			for _, id := range ids {
				props, err := in.api.Get(in.ctx, n, id)
				if errors.Is(err, ErrNotFound) {
					continue // deleted between list and read
				}
				if err != nil {
					c.NotCaptured = "list failed: read " + id + ": " + err.Error()
					return nil
				}
				out = append(out, normalize(t, id, props))
			}
			if next == "" {
				break
			}
			token = next
		}
	}
	in.got[n] = out
	return out
}

// aliases lists properties AWS returns together but refuses together on
// create, because one is another name for the other. The registry schemas
// do not declare it, so this is the one place StackDNA knows something about
// a type that its schema does not say; each entry names the failure that
// found it. The first property present is kept in spec; the others move to
// status, where they stay visible but are never sent back.
var aliases = map[string][][]string{
	// "Both AvailabilityZone and AvailabilityZoneId cannot be specified":
	// first real-account drill, us-east-2, 2026-10-21. The ID is kept
	// because zone names are shuffled per account while the ID names the
	// physical zone, so it means the same in any account; the name in spec
	// would also show as drift in every cross-account diff.
	"AWS::EC2::Subnet": {{"AvailabilityZoneId", "AvailabilityZone"}},
}

// normalize splits what AWS returned into what someone configured (spec) and
// what AWS generated (read-only values, kept in status for reference
// mapping and never sent back).
func normalize(t *TypeInfo, id string, props map[string]any) *resource {
	spec := deepCopy(props)
	stat := map[string]any{"identifier": id}
	for _, ptr := range t.ReadOnly {
		if v, ok := lookupPointer(spec, ptr); ok {
			stat[strings.Join(segments(ptr), ".")] = v
		}
		removePointer(spec, ptr)
	}
	for _, set := range aliases[t.Name] {
		kept := false
		for _, p := range set {
			if v, ok := spec[p]; ok {
				if kept {
					stat[p] = v
					delete(spec, p)
				}
				kept = true
			}
		}
	}
	// AWS does not return write-only values, but that is not trusted: a
	// value that did come back is dropped, so a snapshot can never hold one.
	for _, ptr := range t.WriteOnly {
		removePointer(spec, ptr)
	}
	sortSets(spec, map[string]any{"properties": t.Properties}, t.Definitions)
	return &resource{t: t, id: id, props: props, spec: spec, stat: stat, base: baseName(t, props)}
}

// baseName is the name a person gave the resource: its identifier when the
// user chooses it (BucketName), else its Name tag, else a Name property.
// These are the same in every account, which is what lets a snapshot taken
// in one account be compared with, and restored into, another.
func baseName(t *TypeInfo, props map[string]any) string {
	if !t.GeneratedID() {
		if id, ok := Identifier(t, props); ok {
			return id
		}
	}
	if tags, ok := props["Tags"].([]any); ok {
		for _, tg := range tags {
			if m, ok := tg.(map[string]any); ok && m["Key"] == "Name" {
				if s, ok := m["Value"].(string); ok && s != "" {
					return s
				}
			}
		}
	}
	for _, k := range []string{t.Short() + "Name", "Name"} {
		if s, ok := props[k].(string); ok && s != "" && !t.IsReadOnly(k) {
			return s
		}
	}
	return ""
}

// managedBy reports a reason to skip resources an AWS service or a
// CloudFormation stack owns. Only aws: tags and the service-role path are
// used: AWS reserves both, so a person cannot set them by hand.
func managedBy(r *resource) string {
	if tags, ok := r.props["Tags"].([]any); ok {
		for _, tg := range tags {
			m, _ := tg.(map[string]any)
			k, _ := m["Key"].(string)
			if k == "aws:cloudformation:stack-name" {
				return fmt.Sprintf("managed by CloudFormation stack %v; its template recreates it", m["Value"])
			}
			if strings.HasPrefix(k, "aws:") {
				return "created by an AWS service (tag " + k + "), which recreates it"
			}
		}
	}
	if p, _ := r.props["Path"].(string); strings.HasPrefix(p, "/aws-service-role/") {
		return "service-linked role; AWS creates it when the service is used"
	}
	return ""
}

// toObject builds the snapshot document. The write-only annotation lists
// what AWS never returns for this type, so a reader of the snapshot sees
// that Lambda code or a secret value is absent by design, not lost.
func toObject(r *resource) map[string]any {
	meta := map[string]any{"name": r.name}
	if wo := writeOnlyTops(r.t); len(wo) > 0 {
		meta["annotations"] = map[string]any{annWriteOnly: strings.Join(wo, ",")}
	}
	return map[string]any{"apiVersion": APIVersion, "kind": r.t.Name, "metadata": meta, "spec": r.spec, "status": r.stat}
}

func writeOnlyTops(t *TypeInfo) []string {
	seen := map[string]bool{}
	var out []string
	for _, ptr := range t.WriteOnly {
		if top := segments(ptr)[0]; !seen[top] {
			seen[top] = true
			out = append(out, top)
		}
	}
	sort.Strings(out)
	return out
}

func sameSpec(obj, base map[string]any) bool {
	norm := func(o map[string]any) any {
		var v any
		_ = json.Unmarshal([]byte(canon(map[string]any{"m": o["metadata"], "s": o["spec"]})), &v)
		return v
	}
	return reflect.DeepEqual(norm(obj), norm(base))
}

// sortSets puts arrays the schema marks insertionOrder:false (tags, CIDR
// lists) into a canonical order. AWS may return them in any order; without
// this the same account captures differently from one run to the next.
func sortSets(v any, s map[string]any, defs map[string]any) {
	s, _ = derefCFN(s, defs)
	switch c := v.(type) {
	case map[string]any:
		props, _ := s["properties"].(map[string]any)
		for k, x := range c {
			if ps, ok := props[k].(map[string]any); ok {
				sortSets(x, ps, defs)
			}
		}
	case []any:
		if items, ok := s["items"].(map[string]any); ok {
			for _, x := range c {
				sortSets(x, items, defs)
			}
		}
		if s["insertionOrder"] == false {
			sort.SliceStable(c, func(i, j int) bool { return canon(c[i]) < canon(c[j]) })
		}
	}
}

func canon(v any) string { b, _ := json.Marshal(v); return string(b) }

// name gives every resource a logical name that is the same in any account,
// and replaces references to other resources' generated values with tokens:
//
//	VpcId: vpc-0abc...  ->  VpcId: '{{stackdna|AWS::EC2::VPC|main|VpcId}}'
//
// Restore resolves each token to the value the target account generated.
// A resource with no user-given name is named by a hash of its tokenized
// spec, which is why naming walks the reference graph: a hash taken before
// its references were tokenized would contain account IDs and name the same
// resource differently in every account.
func name(rs []*resource) {
	owners := map[string]refTarget{}
	// Parents claim values first: a reference to the root resource's ID
	// must become the REST API's RootResourceId, which restore can resolve,
	// not a token for a resource that is never restored.
	ordered := make([]*resource, 0, len(rs))
	for _, r := range rs {
		if r.createdBy == nil {
			ordered = append(ordered, r)
		}
	}
	for _, r := range rs {
		if r.createdBy != nil {
			ordered = append(ordered, r)
		}
	}
	for _, r := range ordered {
		for _, k := range sortedKeys(r.stat) {
			if s, ok := r.stat[k].(string); ok && refable(k, s) {
				if _, taken := owners[s]; !taken {
					owners[s] = refTarget{r, k}
				}
			}
		}
	}
	values := sortedKeys(owners)
	// Longest first, so an ARN is replaced whole before an ID inside it.
	sort.SliceStable(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })

	deps := map[*resource][]*resource{}
	for _, r := range rs {
		seen := map[*resource]bool{}
		walkStrings(deepCopy(r.spec), func(s string) string {
			for _, v := range values {
				if o := owners[v].r; o != r && !seen[o] && matches(s, v) {
					seen[o] = true
					deps[r] = append(deps[r], o)
				}
			}
			return s
		})
	}

	used := map[string]bool{}
	done := map[*resource]bool{}
	for len(done) < len(rs) {
		var ready []*resource
		for _, r := range rs {
			if done[r] {
				continue
			}
			ok := true
			for _, d := range deps[r] {
				ok = ok && done[d]
			}
			if ok {
				ready = append(ready, r)
			}
		}
		if len(ready) == 0 {
			// A reference cycle. What is left keeps its literal values for
			// references not yet named; a diff across accounts shows them.
			for _, r := range rs {
				if !done[r] {
					ready = append(ready, r)
				}
			}
		}
		for _, r := range ready {
			tokenize(r, values, owners)
		}
		sort.SliceStable(ready, func(i, j int) bool {
			a, b := ready[i], ready[j]
			if a.t.Name != b.t.Name {
				return a.t.Name < b.t.Name
			}
			if a.base != b.base {
				return a.base < b.base
			}
			return specHash(a) < specHash(b)
		})
		for _, r := range ready {
			base := sanitize(r.base)
			if base == "" {
				base = "h-" + specHash(r)[:12]
			}
			n := base
			for i := 2; used[r.t.Name+"|"+n]; i++ {
				n = fmt.Sprintf("%s-%d", base, i)
			}
			used[r.t.Name+"|"+n] = true
			r.name = n
			done[r] = true
		}
	}
}

type refTarget struct {
	r    *resource
	attr string
}

// refable limits reference sources to values that identify something: the
// identifier, properties named *Id, *Arn or *Url, and ARNs. A read-only
// status word ("available") is not an identity and must never be swapped
// for a token wherever it appears.
func refable(attr, v string) bool {
	if len(v) < 4 || strings.Contains(attr, ".") {
		return false
	}
	return attr == "identifier" || strings.HasPrefix(v, "arn:") ||
		strings.HasSuffix(attr, "Id") || strings.HasSuffix(attr, "Arn") || strings.HasSuffix(attr, "Url")
}

// matches is exact for IDs and substring for ARNs and URLs, which appear
// inside policy documents and environment values.
func matches(s, v string) bool {
	if s == v {
		return true
	}
	return (strings.HasPrefix(v, "arn:") || strings.HasPrefix(v, "https://")) && strings.Contains(s, v)
}

func tokenize(r *resource, values []string, owners map[string]refTarget) {
	r.spec = walkStrings(r.spec, func(s string) string {
		for _, v := range values {
			o := owners[v]
			if o.r == r || o.r.name == "" || !matches(s, v) {
				continue
			}
			s = strings.ReplaceAll(s, v, refToken(o.r.t.Name, o.r.name, o.attr))
		}
		return s
	}).(map[string]any)
}

func refToken(kind, name, attr string) string {
	return refPrefix + kind + "|" + name + "|" + attr + "}}"
}

func specHash(r *resource) string {
	h := sha256.Sum256([]byte(r.t.Name + "\x00" + canon(r.spec)))
	return hex.EncodeToString(h[:])
}

// sanitize keeps a name usable inside a reference token.
func sanitize(s string) string {
	return strings.NewReplacer("|", "_", "{", "_", "}", "_").Replace(s)
}
