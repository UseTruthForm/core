package gcp

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usetruthform/core/internal/snapshot"
)

func iamObj(kind, name, disc, schema, coll, parent string, spec map[string]any) snapshot.Object {
	return snapshot.Object{Body: map[string]any{"apiVersion": APIVersion, "kind": kind,
		"metadata": map[string]any{"name": name, "annotations": map[string]any{
			annDiscovery: disc, annSchema: schema, annCollection: coll, annParent: parent}},
		"spec": spec}}
}

// binding is a grant as a translation writes one.
func binding(disc, coll, resource, role, member string, afterNames ...string) snapshot.Object {
	o := iamObj(BindingKind, resource+" "+role+" "+member, disc, "Policy", coll, resource,
		map[string]any{"bindings": []any{map[string]any{"role": role, "members": []any{member}}}})
	if len(afterNames) > 0 {
		o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)[annAfter] = strings.Join(afterNames, ",")
	}
	return o
}

const (
	iamProj  = "projects/" + tokProject
	iamSA    = iamProj + "/serviceAccounts/shop-orders@" + tokProject + ".iam.gserviceaccount.com"
	iamEmail = "serviceAccount:shop-orders@" + tokProject + ".iam.gserviceaccount.com"
)

// iamSnapshot is a service account and what it is granted: on a topic, a
// subscription, a secret, a repository and a bucket, whose policy calls
// are each API's own (Pub/Sub's GET :getIamPolicy, IAM's POST, Cloud
// Storage's b/{bucket}/iam with the policy as the body).
func iamSnapshot() snapshot.Snapshot {
	topic := iamProj + "/topics/orders"
	sub := iamProj + "/subscriptions/orders"
	secret := iamProj + "/secrets/api-key"
	repo := iamProj + "/locations/europe-west1/repositories/shop"
	return snapshot.Snapshot{Platform: "gcp", Objects: []snapshot.Object{
		// The bindings come first, and sort before what they wait for.
		binding("pubsub/v1", "projects.topics", topic, "roles/pubsub.publisher", iamEmail, iamSA),
		binding("pubsub/v1", "projects.subscriptions", sub, "roles/pubsub.subscriber", iamEmail, iamSA),
		binding("secretmanager/v1", "projects.secrets", secret, "roles/secretmanager.secretAccessor", iamEmail, iamSA),
		binding("artifactregistry/v1", "projects.locations.repositories", repo, "roles/artifactregistry.reader", iamEmail, iamSA),
		binding("storage/v1", "buckets", "shop-assets", "roles/storage.objectViewer", iamEmail, iamSA),
		binding("iam/v1", "projects.serviceAccounts", iamSA, "roles/iam.workloadIdentityUser",
			"serviceAccount:"+tokProject+".svc.id.goog[shop/orders]", iamProj+"/locations/europe-west1/clusters/shop"),
		iamObj("iam.googleapis.com/ServiceAccount", iamSA, "iam/v1", "ServiceAccount", "projects.serviceAccounts", iamProj, map[string]any{"name": iamSA, "displayName": "orders"}),
		iamObj("pubsub.googleapis.com/Topic", topic, "pubsub/v1", "Topic", "projects.topics", iamProj, map[string]any{"name": topic}),
		iamObj("pubsub.googleapis.com/Subscription", sub, "pubsub/v1", "Subscription", "projects.subscriptions", iamProj, map[string]any{"name": sub, "topic": topic}),
		iamObj("secretmanager.googleapis.com/Secret", secret, "secretmanager/v1", "Secret", "projects.secrets", iamProj, map[string]any{"replication": map[string]any{"automatic": map[string]any{}}}),
		iamObj("artifactregistry.googleapis.com/Repository", repo, "artifactregistry/v1", "Repository", "projects.locations.repositories", iamProj+"/locations/europe-west1", map[string]any{"name": repo, "format": "DOCKER"}),
		iamObj("storage.googleapis.com/Bucket", "shop-assets", "storage/v1", "Bucket", "buckets", "", map[string]any{"name": "shop-assets", "location": "EUROPE-WEST1"}),
		iamObj("container.googleapis.com/Cluster", iamProj+"/locations/europe-west1/clusters/shop", "container/v1", "Cluster", "projects.locations.clusters", iamProj+"/locations/europe-west1",
			map[string]any{"name": "shop", "workloadIdentityConfig": map[string]any{"workloadPool": tokProject + ".svc.id.goog"}}),
	}}
}

// noSleep makes the waits instant and records them.
func noSleep(t *testing.T) *[]time.Duration {
	var mu sync.Mutex
	waits := &[]time.Duration{}
	oldSleep, oldJitter := sleepCtx, jitter
	t.Cleanup(func() { sleepCtx, jitter = oldSleep, oldJitter })
	sleepCtx = func(_ context.Context, d time.Duration) error {
		mu.Lock()
		*waits = append(*waits, d)
		mu.Unlock()
		return nil
	}
	jitter = func() time.Duration { return 0 }
	return waits
}

func iamProject(docs *Docs) *Fake {
	f := NewWorld(docs).Project("p1", "1")
	f.EmailNames = true
	return f
}

func iamDocs() *Docs { return LoadDocs(filepath.Join("..", "translate", "testdata", "gcp")) }

func iamRestoreAll(t *testing.T, f API, docs *Docs, s snapshot.Snapshot) []snapshot.Result {
	t.Helper()
	rs := Restore(context.Background(), f, docs, s, RestoreOptions{})
	if len(rs) != len(s.Objects) {
		t.Fatalf("%d results for %d objects", len(rs), len(s.Objects))
	}
	for _, r := range rs {
		if !r.OK {
			t.Errorf("%s: %s", r.Key, r.Detail)
		}
	}
	return rs
}

// Grants are added to each resource's allow policy with that API's own
// methods, after the resource, the member's service account and the
// cluster that makes the workload identity pool exist; a second restore
// writes nothing.
func TestRestoreAddsBindings(t *testing.T) {
	docs := iamDocs()
	f := iamProject(docs)
	s := iamSnapshot()
	iamRestoreAll(t, f, docs, s)
	sa := "serviceAccount:shop-orders@p1.iam.gserviceaccount.com"
	for rel, role := range map[string]string{
		"projects/p1/topics/orders":                            "roles/pubsub.publisher",
		"projects/p1/subscriptions/orders":                     "roles/pubsub.subscriber",
		"projects/p1/secrets/api-key":                          "roles/secretmanager.secretAccessor",
		"projects/p1/locations/europe-west1/repositories/shop": "roles/artifactregistry.reader",
		"shop-assets": "roles/storage.objectViewer",
	} {
		if got := f.Policy(rel); !reflect.DeepEqual(got, map[string][]string{role: {sa}}) {
			t.Errorf("%s: %v", rel, got)
		}
	}
	if got := f.Policy("projects/p1/serviceAccounts/shop-orders@p1.iam.gserviceaccount.com"); !reflect.DeepEqual(got, map[string][]string{"roles/iam.workloadIdentityUser": {"serviceAccount:p1.svc.id.goog[shop/orders]"}}) {
		t.Errorf("the service account's policy: %v", got)
	}
	writes := f.PolicyWrites
	if writes != 6 {
		t.Errorf("%d policy writes for 6 bindings", writes)
	}
	for _, r := range Restore(context.Background(), f, docs, s, RestoreOptions{}) {
		if !r.OK || r.Detail != "already present and identical" {
			t.Errorf("again: %s: %v %s", r.Key, r.OK, r.Detail)
		}
	}
	if f.PolicyWrites != writes {
		t.Errorf("a second restore wrote %d policies", f.PolicyWrites-writes)
	}
}

// What a policy already holds stays: other members of the same role,
// other roles, and conditional bindings with their conditions. The member
// is added to the unconditional binding only, never to a conditional one
// of the same role.
func TestBindingsNeverRemove(t *testing.T) {
	docs := iamDocs()
	f := iamProject(docs)
	s := iamSnapshot()
	var first snapshot.Snapshot
	for _, o := range s.Objects {
		if o.Kind() != BindingKind {
			first.Objects = append(first.Objects, o)
		}
	}
	iamRestoreAll(t, f, docs, first)
	cond := map[string]any{"title": "office", "expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
	f.SetPolicy("projects/p1/topics/orders",
		// The conditional binding comes first: the member must not join it.
		map[string]any{"role": "roles/pubsub.publisher", "members": []any{"user:bob@example.com"}, "condition": cond},
		map[string]any{"role": "roles/pubsub.publisher", "members": []any{"user:ann@example.com"}},
		map[string]any{"role": "roles/pubsub.viewer", "members": []any{"group:ops@example.com", "deleted:serviceAccount:old@p1.iam.gserviceaccount.com?uid=123"}})
	f.SetPolicy("shop-assets", map[string]any{"role": "roles/storage.admin", "members": []any{"user:ann@example.com"}})
	f.SetPolicy("projects/p1/subscriptions/orders", map[string]any{"role": "roles/pubsub.subscriber", "members": []any{"user:bob@example.com"}, "condition": cond})
	iamRestoreAll(t, f, docs, s)
	sa := "serviceAccount:shop-orders@p1.iam.gserviceaccount.com"
	want := map[string][]string{
		"roles/pubsub.publisher":               {"user:ann@example.com", sa},
		"roles/pubsub.publisher (conditional)": {"user:bob@example.com"},
		"roles/pubsub.viewer":                  {"group:ops@example.com", "deleted:serviceAccount:old@p1.iam.gserviceaccount.com?uid=123"},
	}
	if got := f.Policy("projects/p1/topics/orders"); !reflect.DeepEqual(got, want) {
		t.Errorf("the topic's policy: %v", got)
	}
	// The condition itself survived the write.
	p, err := f.Call(context.Background(), "GET", "https://pubsub.googleapis.com/v1/projects/p1/topics/orders:getIamPolicy?options.requestedPolicyVersion=3", nil)
	if err != nil {
		t.Fatal(err)
	}
	kept := false
	for _, b := range p["bindings"].([]any) {
		if c, _ := b.(map[string]any)["condition"].(map[string]any); c != nil && c["expression"] == cond["expression"] {
			kept = true
		}
	}
	if !kept || p["version"] != 3 {
		t.Errorf("the conditional binding did not survive: %v", p)
	}
	if got := f.Policy("projects/p1/subscriptions/orders"); !reflect.DeepEqual(got, map[string][]string{"roles/pubsub.subscriber (conditional)": {"user:bob@example.com"}, "roles/pubsub.subscriber": {sa}}) {
		t.Errorf("the subscription's policy: %v", got)
	}
	if got := f.Policy("shop-assets"); !reflect.DeepEqual(got, map[string][]string{"roles/storage.admin": {"user:ann@example.com"}, "roles/storage.objectViewer": {sa}}) {
		t.Errorf("the bucket's policy: %v", got)
	}
}

// A binding is not written before what it waits for: left to key order it
// comes first, and Google refuses a member that does not exist, a resource
// that does not, and a workload identity pool no cluster has made.
func TestBindingsWaitForWhatTheyName(t *testing.T) {
	noSleep(t)
	docs := iamDocs()
	s := iamSnapshot()
	order, cyclic := restoreOrder(s.Objects)
	if len(cyclic) > 0 {
		t.Fatalf("cyclic: %v", cyclic)
	}
	at := map[string]int{}
	for i, o := range order {
		at[o.Name()] = i
	}
	for _, o := range order {
		for _, n := range after(o) {
			if at[n] > at[o.Name()] {
				t.Errorf("%s comes before %s", o.Name(), n)
			}
		}
	}
	// One at a time and alone, each is refused for what is missing.
	f := iamProject(docs)
	for _, o := range s.Objects {
		if o.Kind() != BindingKind {
			continue
		}
		r := Restore(context.Background(), f, docs, snapshot.Snapshot{Platform: "gcp", Objects: []snapshot.Object{o}}, RestoreOptions{})
		if r[0].OK {
			t.Errorf("%s was written with nothing it names in the project: %s", o.Name(), r[0].Detail)
		}
	}
	if f.PolicyWrites != 0 {
		t.Errorf("%d policies written", f.PolicyWrites)
	}
	// The pool: everything but the cluster.
	var noCluster snapshot.Snapshot
	for _, o := range s.Objects {
		if o.Kind() != "container.googleapis.com/Cluster" {
			noCluster.Objects = append(noCluster.Objects, o)
		}
	}
	for _, r := range Restore(context.Background(), f, docs, noCluster, RestoreOptions{}) {
		if strings.Contains(r.Key, "workloadIdentityUser") == r.OK {
			t.Errorf("without the cluster: %s: %v %s", r.Key, r.OK, r.Detail)
		}
	}
}

// A binding with a condition, or anything else beside role and members,
// is refused: writing it without would grant more than the snapshot says.
func TestConditionalBindingsAreRefused(t *testing.T) {
	docs := iamDocs()
	f := iamProject(docs)
	s := iamSnapshot()
	iamRestoreAll(t, f, docs, s)
	before := f.PolicyWrites
	for _, spec := range []map[string]any{
		{"bindings": []any{map[string]any{"role": "roles/pubsub.subscriber", "members": []any{"user:x@example.com"}, "condition": map[string]any{"expression": "true"}}}},
		{"bindings": []any{map[string]any{"role": "roles/pubsub.subscriber", "members": []any{}}}},
		{"bindings": []any{}},
		{"bindings": []any{map[string]any{"role": "roles/pubsub.subscriber", "members": []any{"user:x@example.com"}}}, "etag": "x"},
	} {
		o := iamObj(BindingKind, "b", "pubsub/v1", "Policy", "projects.topics", iamProj+"/topics/orders", spec)
		r := Restore(context.Background(), f, docs, snapshot.Snapshot{Platform: "gcp", Objects: []snapshot.Object{o}}, RestoreOptions{})
		if r[0].OK {
			t.Errorf("%v was restored: %s", spec, r[0].Detail)
		}
	}
	if f.PolicyWrites != before {
		t.Error("a refused binding wrote a policy")
	}
	// A type with no policy methods says so.
	o := iamObj(BindingKind, "b", "container/v1", "Policy", "projects.locations.clusters", iamProj+"/locations/europe-west1/clusters/shop",
		map[string]any{"bindings": []any{map[string]any{"role": "roles/x", "members": []any{"user:x@example.com"}}}})
	if r := Restore(context.Background(), f, docs, snapshot.Snapshot{Platform: "gcp", Objects: []snapshot.Object{o}}, RestoreOptions{}); r[0].OK || !strings.Contains(r[0].Detail, "getIamPolicy") {
		t.Errorf("a binding on a type without policies: %+v", r[0])
	}
}

// racing is an API on which someone else changes each policy between the
// restore's read and its first write, and a new service account is not
// visible to the first write that names it.
type racing struct {
	*Fake
	mu      sync.Mutex
	raced   map[string]bool
	unseen  map[string]bool
	aborted int
}

func (r *racing) Call(ctx context.Context, method, url string, body any) (map[string]any, error) {
	set := strings.HasSuffix(url, ":setIamPolicy") || (method == "PUT" && strings.HasSuffix(url, "/iam"))
	if set {
		r.mu.Lock()
		if !r.raced[url] {
			r.raced[url] = true
			r.mu.Unlock()
			rel := strings.TrimSuffix(url[strings.Index(url, "/v1/")+4:], ":setIamPolicy")
			rel = strings.TrimSuffix(strings.TrimPrefix(rel, "b/"), "/iam")
			cur := r.Fake.Policy(rel)
			var bs []map[string]any
			for role, ms := range cur {
				var l []any
				for _, m := range ms {
					l = append(l, m)
				}
				bs = append(bs, map[string]any{"role": role, "members": l})
			}
			bs = append(bs, map[string]any{"role": "roles/viewer", "members": []any{"user:late@example.com"}})
			r.Fake.SetPolicy(rel, bs...)
		} else if !r.unseen[url] {
			r.unseen[url] = true
			r.mu.Unlock()
			return nil, errors.New("POST " + url + ": HTTP 400: INVALID_ARGUMENT: Service account shop-orders@p1.iam.gserviceaccount.com does not exist.")
		} else {
			r.mu.Unlock()
		}
	}
	out, err := r.Fake.Call(ctx, method, url, body)
	if err != nil && set && conflict(err.Error()) {
		r.mu.Lock()
		r.aborted++
		r.mu.Unlock()
	}
	return out, err
}

// A policy changed by someone else between the read and the write is read
// again and written again, the whole read-modify-write, and what the other
// wrote is kept. A service account Google does not see yet is waited for.
func TestBindingsRetryTheWholeReadModifyWrite(t *testing.T) {
	waits := noSleep(t)
	docs := iamDocs()
	f := &racing{Fake: iamProject(docs), raced: map[string]bool{}, unseen: map[string]bool{}}
	s := iamSnapshot()
	iamRestoreAll(t, f, docs, s)
	if f.aborted != 6 {
		t.Errorf("%d writes lost on the etag, of 6", f.aborted)
	}
	if len(*waits) != 6 {
		t.Errorf("waited %d times for the service account", len(*waits))
	}
	got := f.Policy("projects/p1/topics/orders")
	if !reflect.DeepEqual(got["roles/viewer"], []string{"user:late@example.com"}) || len(got["roles/pubsub.publisher"]) != 1 {
		t.Errorf("the topic's policy after a race: %v", got)
	}
}

// noEtag is an API whose policies come without an etag.
type noEtag struct{ *Fake }

func (n noEtag) Call(ctx context.Context, method, url string, body any) (map[string]any, error) {
	out, err := n.Fake.Call(ctx, method, url, body)
	if strings.Contains(url, "getIamPolicy") {
		delete(out, "etag")
	}
	return out, err
}

// A policy that comes without an etag is not written: nothing would stop
// the write from undoing another's. A member named twice is added once.
func TestNoEtagNoWrite(t *testing.T) {
	docs := iamDocs()
	f := iamProject(docs)
	s := iamSnapshot()
	iamRestoreAll(t, f, docs, s)
	more := binding("pubsub/v1", "projects.topics", iamProj+"/topics/orders", "roles/pubsub.viewer", iamEmail, iamSA)
	before := f.PolicyWrites
	r := Restore(context.Background(), noEtag{f}, docs, snapshot.Snapshot{Platform: "gcp", Objects: []snapshot.Object{more}}, RestoreOptions{})
	if r[0].OK || !strings.Contains(r[0].Detail, "without an etag") || f.PolicyWrites != before {
		t.Errorf("a policy without an etag: %+v, %d writes", r[0], f.PolicyWrites-before)
	}
	// What is already there needs no write, etag or not.
	r = Restore(context.Background(), noEtag{f}, docs, snapshot.Snapshot{Platform: "gcp", Objects: []snapshot.Object{s.Objects[0]}}, RestoreOptions{})
	if !r[0].OK || r[0].Detail != "already present and identical" {
		t.Errorf("a binding already there: %+v", r[0])
	}
	added := addMembers(map[string]any{}, map[string][]string{"roles/a": {"user:x@example.com", "user:x@example.com"}})
	if len(added) != 1 {
		t.Errorf("a member named twice was added %d times", len(added))
	}
}

// A project's workload identity pool carries the project ID: a capture
// writes it as the project token, in a cluster's workloadPool and in a
// member of the pool, and leaves a longer name that ends the same alone.
func TestWorkloadPoolIsTokenized(t *testing.T) {
	for in, want := range map[string]string{
		"p1.svc.id.goog": tokProject + ".svc.id.goog",
		"serviceAccount:p1.svc.id.goog[shop/orders]":   "serviceAccount:" + tokProject + ".svc.id.goog[shop/orders]",
		"x-p1.svc.id.goog":                             "x-p1.svc.id.goog",
		"workloadIdentityPools/p1.svc.id.goog/subject": "workloadIdentityPools/" + tokProject + ".svc.id.goog/subject",
	} {
		if got := tokenizeString(in, "p1", "1"); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}
