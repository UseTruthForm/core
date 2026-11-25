package gcp

import (
	"context"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

const (
	testPolicy = "accessPolicies/4321"
	testCaller = "serviceAccount:restore@shop-ops.iam.gserviceaccount.com"
)

// perimeterSnapshot is a log metric of the project and a service perimeter
// around the project that restricts Cloud Logging, as a translation writes
// one: named in an access policy, the project by its number's token.
func perimeterSnapshot(t *testing.T, docs *Docs, ingress bool) snapshot.Snapshot {
	t.Helper()
	src := NewWorld(docs).Project(srcProject, "111111111111")
	seed(t, src, "logging", "v2", "projects.metrics", map[string]any{"name": "shop-errors", "filter": "severity>=ERROR"})
	snap, err := Capture(context.Background(), src, docs, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	status := map[string]any{"resources": []any{"projects/" + tokNumber}, "restrictedServices": []any{"logging.googleapis.com"}}
	if ingress {
		status["ingressPolicies"] = []any{map[string]any{
			"ingressFrom": map[string]any{"identities": []any{testCaller}, "sources": []any{map[string]any{"accessLevel": "*"}}},
			"ingressTo": map[string]any{"resources": []any{"*"}, "operations": []any{
				map[string]any{"serviceName": "logging.googleapis.com", "methodSelectors": []any{map[string]any{"method": "*"}}}}},
		}}
	}
	name := testPolicy + "/servicePerimeters/shop_private"
	snap.Objects = append(snap.Objects, snapshot.Object{Body: map[string]any{"apiVersion": APIVersion, "kind": "accesscontextmanager.googleapis.com/ServicePerimeter",
		"metadata": map[string]any{"name": name, "annotations": map[string]any{
			annDiscovery: "accesscontextmanager/v1", annSchema: "ServicePerimeter", annCollection: "accessPolicies.servicePerimeters", annParent: testPolicy}},
		"spec": map[string]any{"name": name, "title": "shop_private", "status": status}}})
	return snap
}

func restoreAll(t *testing.T, f *Fake, docs *Docs, snap snapshot.Snapshot, opt RestoreOptions) map[string]snapshot.Result {
	t.Helper()
	out := map[string]snapshot.Result{}
	// One at a time, so the perimeter (which sorts first) is there before
	// the metric is made: the calls that follow it are the test.
	for _, r := range restoreWith(context.Background(), f, docs, snap, opt, 1) {
		out[r.Key[strings.LastIndex(r.Key, "/")+1:]] = r
	}
	return out
}

// A service perimeter is created under its access policy, with the
// project's number in place of the token, and found again by its own name:
// no project's inventory lists it. The restore's calls that follow pass by
// its ingress rule.
func TestPerimeterRestore(t *testing.T) {
	docs := fixtures(t)
	snap := perimeterSnapshot(t, docs, true)
	w := NewWorld(docs)
	w.Parent(testPolicy)
	dst := w.Project(dstProject, "222222222222")
	dst.Caller = testCaller
	for name, r := range restoreAll(t, dst, docs, snap, RestoreOptions{}) {
		if !r.OK || !strings.HasPrefix(r.Detail, "created ") {
			t.Fatalf("%s: %v %s", name, r.OK, r.Detail)
		}
	}
	rel := testPolicy + "/servicePerimeters/shop_private"
	p, ok := w.outside[rel]
	if !ok || canon(p.data["status"].(map[string]any)["resources"]) != `["projects/222222222222"]` || p.data["name"] != rel {
		t.Fatalf("the perimeter in the policy: %v", p.data)
	}
	assets, _ := dst.Assets(context.Background())
	for _, a := range assets {
		if strings.Contains(a.Name, "servicePerimeters") {
			t.Errorf("the project's inventory lists the perimeter: %s", a.Name)
		}
	}
	for name, r := range restoreAll(t, dst, docs, snap, RestoreOptions{}) {
		if !r.OK || r.Detail != "already present and identical" {
			t.Errorf("second restore, %s: %v %s", name, r.OK, r.Detail)
		}
	}
	// A capture of the project reads what the perimeter restricts, and
	// does not hold the perimeter.
	got, err := Capture(context.Background(), dst, docs, Policy{})
	if err != nil || len(got.Objects) != 1 || len(got.Skips) != 0 {
		t.Errorf("capture behind the perimeter: %v, %d objects, skips %v", err, len(got.Objects), got.Skips)
	}

	// A perimeter that drifted is put right by --update, and only then.
	w.outside[rel].data["status"].(map[string]any)["restrictedServices"] = []any{"logging.googleapis.com", "storage.googleapis.com"}
	if r := restoreAll(t, dst, docs, snap, RestoreOptions{})["shop_private"]; r.OK || !strings.Contains(r.Detail, "already exists and differs (spec.status.restrictedServices") {
		t.Errorf("drifted, without --update: %v %s", r.OK, r.Detail)
	}
	if r := restoreAll(t, dst, docs, snap, RestoreOptions{Update: true})["shop_private"]; !r.OK || r.Detail != "updated "+rel+" (status)" {
		t.Errorf("drifted, with --update: %v %s", r.OK, r.Detail)
	}
	if got := canon(w.outside[rel].data["status"].(map[string]any)["restrictedServices"]); got != `["logging.googleapis.com"]` || dst.Updates != 1 {
		t.Errorf("after --update: %s, %d updates", got, dst.Updates)
	}

	// The same snapshot into another project of the organization finds
	// the first one's perimeter under that name and leaves it: taking it
	// over would open the first project.
	other := w.Project("shop-other-9", "333333333333")
	other.Caller = testCaller
	if r := restoreAll(t, other, docs, snap, RestoreOptions{})["shop_private"]; r.OK || !strings.Contains(r.Detail, "already exists and differs (spec.status.resources") {
		t.Errorf("another project, same perimeter name: %v %s", r.OK, r.Detail)
	}
}

// The fake closes a restricted service as VPC Service Controls does: with
// no ingress rule for the caller, the restore that made the perimeter is
// refused its next call, and so is a capture; from inside the perimeter
// both pass.
func TestPerimeterLocksOutWithoutIngress(t *testing.T) {
	docs := fixtures(t)
	snap := perimeterSnapshot(t, docs, false)
	w := NewWorld(docs)
	w.Parent(testPolicy)
	dst := w.Project(dstProject, "222222222222")
	dst.Caller = testCaller
	rs := restoreAll(t, dst, docs, snap, RestoreOptions{})
	if r := rs["shop_private"]; !r.OK {
		t.Fatalf("perimeter: %s", r.Detail)
	}
	if r := rs["shop-errors"]; r.OK || !strings.Contains(r.Detail, "prohibited by organization's policy") {
		t.Errorf("a call from outside a perimeter with no ingress rule: %v %s", r.OK, r.Detail)
	}
	// Another caller than the one a rule admits is outside too.
	admitted := perimeterSnapshot(t, docs, true)
	w2 := NewWorld(docs)
	w2.Parent(testPolicy)
	d2 := w2.Project(dstProject, "222222222222")
	d2.Caller = "user:someone@example.com"
	if r := restoreAll(t, d2, docs, admitted, RestoreOptions{})["shop-errors"]; r.OK {
		t.Errorf("a caller no rule names passed: %s", r.Detail)
	}
	dst.Inside = true
	for name, r := range restoreAll(t, dst, docs, snap, RestoreOptions{}) {
		if !r.OK {
			t.Errorf("from inside, %s: %s", name, r.Detail)
		}
	}
}

// What Access Context Manager refuses, the fake refuses, and the restore
// says so: a policy that is not there, a project named by its ID, and a
// project that is already in a perimeter.
func TestPerimeterRefusals(t *testing.T) {
	docs := fixtures(t)
	snap := perimeterSnapshot(t, docs, true)
	perimeter := func(s snapshot.Snapshot) map[string]any {
		for _, o := range s.Objects {
			if strings.Contains(o.Name(), "servicePerimeters") {
				return o.Body["spec"].(map[string]any)
			}
		}
		return nil
	}
	w := NewWorld(docs)
	dst := w.Project(dstProject, "222222222222")
	dst.Caller = testCaller
	if r := restoreAll(t, dst, docs, snap, RestoreOptions{})["shop_private"]; r.OK || !strings.Contains(r.Detail, testPolicy+" was not found") {
		t.Errorf("no such policy: %v %s", r.OK, r.Detail)
	}
	w.Parent(testPolicy)
	byID := perimeterSnapshot(t, docs, true)
	perimeter(byID)["status"].(map[string]any)["resources"] = []any{"projects/" + tokProject}
	if r := restoreAll(t, dst, docs, byID, RestoreOptions{})["shop_private"]; r.OK || !strings.Contains(r.Detail, "by its number") {
		t.Errorf("a project by its ID: %v %s", r.OK, r.Detail)
	}
	noSources := perimeterSnapshot(t, docs, true)
	delete(perimeter(noSources)["status"].(map[string]any)["ingressPolicies"].([]any)[0].(map[string]any)["ingressFrom"].(map[string]any), "sources")
	if r := restoreAll(t, dst, docs, noSources, RestoreOptions{})["shop_private"]; r.OK || !strings.Contains(r.Detail, "needs sources") {
		t.Errorf("an ingress rule without sources: %v %s", r.OK, r.Detail)
	}
	// The project is already in a perimeter of another name.
	second := perimeterSnapshot(t, docs, true)
	for _, o := range second.Objects {
		if strings.Contains(o.Name(), "servicePerimeters") {
			n := testPolicy + "/servicePerimeters/shop_second"
			o.Body["metadata"].(map[string]any)["name"] = n
			o.Body["spec"].(map[string]any)["name"], o.Body["spec"].(map[string]any)["title"] = n, "shop_second"
		}
	}
	if r := restoreAll(t, dst, docs, snap, RestoreOptions{})["shop_private"]; !r.OK {
		t.Fatalf("perimeter: %s", r.Detail)
	}
	if r := restoreAll(t, dst, docs, second, RestoreOptions{})["shop_second"]; r.OK || !strings.Contains(r.Detail, "one regular perimeter only") {
		t.Errorf("a second perimeter for the project: %v %s", r.OK, r.Detail)
	}
}

// A resource outside the project that cannot be read is not created over:
// whether it exists is not known.
func TestOutsideResourceUnreadable(t *testing.T) {
	docs := fixtures(t)
	snap := perimeterSnapshot(t, docs, true)
	w := NewWorld(docs)
	w.Parent(testPolicy)
	dst := w.Project(dstProject, "222222222222")
	api := &failingGet{Fake: dst, match: "servicePerimeters"}
	for _, r := range restoreWith(context.Background(), api, docs, snap, RestoreOptions{}, 1) {
		if strings.Contains(r.Key, "servicePerimeters") && (r.OK || !strings.Contains(r.Detail, "cannot tell whether it exists")) {
			t.Errorf("%v %s", r.OK, r.Detail)
		}
	}
	if len(w.outside) != 0 {
		t.Error("a perimeter was created without knowing whether one was there")
	}
}

type failingGet struct {
	*Fake
	match string
}

func (f *failingGet) Call(ctx context.Context, method, url string, body any) (map[string]any, error) {
	if method == "GET" && strings.Contains(url, f.match) {
		return nil, context.DeadlineExceeded
	}
	return f.Fake.Call(ctx, method, url, body)
}

// An ingress rule admits its principal for the methods it names and no
// other, from anywhere only when its source says so, and a call is named
// by its service's own method.
func TestPerimeterIngressRule(t *testing.T) {
	f := NewWorld(fixtures(t)).Project(dstProject, "222222222222")
	f.Caller = testCaller
	rule := func(from, to map[string]any) map[string]any {
		return map[string]any{"ingressFrom": from, "ingressTo": to}
	}
	from := map[string]any{"identities": []any{testCaller}, "sources": []any{map[string]any{"accessLevel": "*"}}}
	to := func(service string, methods ...string) map[string]any {
		var sel []any
		for _, m := range methods {
			sel = append(sel, map[string]any{"method": m})
		}
		return map[string]any{"resources": []any{"*"}, "operations": []any{map[string]any{"serviceName": service, "methodSelectors": sel}}}
	}
	const ps = "pubsub.googleapis.com"
	for _, c := range []struct {
		why    string
		policy map[string]any
		method string
		want   bool
	}{
		{"a method it names", rule(from, to(ps, "Publisher.CreateTopic", "Publisher.GetTopic")), "Publisher.GetTopic", true},
		{"a method it does not name", rule(from, to(ps, "Publisher.CreateTopic")), "Publisher.GetTopic", false},
		{"a call with no name of its own", rule(from, to(ps, "Publisher.CreateTopic")), "", false},
		{"every method", rule(from, to(ps, "*")), "", true},
		{"another service", rule(from, to("secretmanager.googleapis.com", "*")), "Publisher.GetTopic", false},
		{"another principal", rule(map[string]any{"identities": []any{"user:someone@example.com"}, "sources": from["sources"]}, to(ps, "*")), "", false},
		{"any identity", rule(map[string]any{"identityType": "ANY_IDENTITY", "sources": from["sources"]}, to(ps, "*")), "", true},
		{"from an access level only", rule(map[string]any{"identities": from["identities"], "sources": []any{map[string]any{"accessLevel": testPolicy + "/accessLevels/office"}}}, to(ps, "*")), "", false},
		{"another project's resources", rule(from, map[string]any{"resources": []any{"projects/999"}, "operations": to(ps, "*")["operations"]}), "", false},
	} {
		if got := f.admitted(c.policy, ps, c.method); got != c.want {
			t.Errorf("%s: admitted %v, want %v", c.why, got, c.want)
		}
	}
}
