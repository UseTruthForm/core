package gcp

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/drilltest"
	"github.com/usetruthform/core/internal/platform"
)

var _ platform.Platform = (*Adapter)(nil)

const (
	srcProject = "shop-src-1234"
	dstProject = "shop-dst-5678"
)

func fixtures(t *testing.T) *Docs {
	t.Helper()
	return LoadDocs("../../testdata/gcp/discovery")
}

func seed(t *testing.T, f *Fake, api, ver, coll string, body map[string]any) string {
	t.Helper()
	schemas := map[string]string{"projects.serviceAccounts": "ServiceAccount", "projects.roles": "Role",
		"projects.metrics": "LogMetric", "projects.notificationChannels": "NotificationChannel", "projects.alertPolicies": "AlertPolicy"}
	n, err := f.Seed(api, ver, api+".googleapis.com/"+schemas[coll], schemas[coll], coll, "projects/"+f.id, body)
	if err != nil {
		t.Fatalf("seed %s: %v", coll, err)
	}
	return n
}

// seedShop builds a small project through each type's own create method,
// referencing the server-assigned channel name as a person would.
func seedShop(t *testing.T, f *Fake) {
	seed(t, f, "iam", "v1", "projects.serviceAccounts", map[string]any{"accountId": "shop-api", "serviceAccount": map[string]any{"displayName": "Shop API"}})
	seed(t, f, "iam", "v1", "projects.roles", map[string]any{"roleId": "shopReader", "role": map[string]any{
		"title": "Shop reader", "stage": "GA", "includedPermissions": []any{"logging.logEntries.list"}}})
	seed(t, f, "logging", "v2", "projects.metrics", map[string]any{"name": "shop-errors", "filter": "severity>=ERROR", "description": "errors from the shop"})
	ch := seed(t, f, "monitoring", "v3", "projects.notificationChannels", map[string]any{
		"type": "email", "displayName": "Shop on-call", "labels": map[string]any{"email_address": "oncall@example.com"}})
	seed(t, f, "monitoring", "v3", "projects.alertPolicies", map[string]any{
		"displayName": "Shop errors", "combiner": "OR", "notificationChannels": []any{ch},
		"conditions": []any{map[string]any{"displayName": "error rate", "conditionThreshold": map[string]any{
			"filter": `metric.type="logging.googleapis.com/user/shop-errors"`, "comparison": "COMPARISON_GT", "duration": "60s"}}},
	})
	// What Google creates in every project, which must be skipped.
	seed(t, f, "iam", "v1", "projects.serviceAccounts", map[string]any{"accountId": "123456-compute@developer.gserviceaccount.com", "serviceAccount": map[string]any{"displayName": "Compute default"}})
	seed(t, f, "logging", "v2", "projects.metrics", map[string]any{"name": "_Reserved", "filter": "x"})
}

var shopKeys = []string{
	"iam.googleapis.com/ServiceAccount||projects/{{truthform|project}}/serviceAccounts/shop-api",
	"iam.googleapis.com/Role||projects/{{truthform|project}}/roles/shopReader",
	"logging.googleapis.com/LogMetric||projects/{{truthform|project}}/metrics/shop-errors",
	"monitoring.googleapis.com/NotificationChannel||projects/{{truthform|project}}/notificationChannels/~Shop on-call",
	"monitoring.googleapis.com/AlertPolicy||projects/{{truthform|project}}/alertPolicies/~Shop errors",
}

func keys() []string {
	var out []string
	for _, k := range shopKeys {
		out = append(out, APIVersion+"|"+k)
	}
	return out
}

func TestDrillOnFakeProjects(t *testing.T) {
	docs := fixtures(t)
	w := NewWorld(docs)
	src, dst := w.Project(srcProject, "111111111111"), w.Project(dstProject, "222222222222")
	// Google names an alert policy's conditions under the policy's own
	// server-assigned name, as the AlertPolicy schema describes.
	for _, f := range []*Fake{src, dst} {
		// Cloud Asset Inventory names service accounts by uniqueId, not by
		// the email IAM uses (seen in my-sandbox-project, 2026-10-21).
		f.InventoryName = func(rel string, data map[string]any) string {
			if strings.Contains(rel, "/serviceAccounts/") {
				return parentOf(rel) + "/serviceAccounts/" + fmt.Sprint(data["uniqueId"])
			}
			return ""
		}
		f.AfterCreate = func(schema string, stored map[string]any) {
			if schema != "AlertPolicy" {
				return
			}
			for i, c := range stored["conditions"].([]any) {
				c.(map[string]any)["name"] = fmt.Sprintf("%s/conditions/%d", stored["name"], 9000+i)
			}
		}
	}
	seedShop(t, src)
	a := func(f *Fake) *Adapter { return &Adapter{API: f, Docs: docs} }
	snap := drilltest.Run(t, drilltest.Spec{Source: a(src), Target: a(dst), ExpectKeys: keys()})

	// The policy must point at the channel the target created, not the
	// source's: the fake would have refused the source project's name.
	var channel, policy map[string]any
	for _, n := range dst.Names() {
		r := dst.res[n]
		switch r.asset.DiscoveryName {
		case "NotificationChannel":
			channel = r.data
		case "AlertPolicy":
			policy = r.data
		}
	}
	if got := policy["notificationChannels"].([]any)[0]; got != channel["name"] {
		t.Errorf("policy points at %v, want the target's channel %v", got, channel["name"])
	}
	for _, o := range snap.Objects {
		if s := canon(o.Body["spec"]); strings.Contains(s, srcProject) || strings.Contains(s, "111111111111") {
			t.Errorf("%s spec names the source project: %s", o.Key(), s)
		}
	}
	reasons := map[string]bool{}
	for _, s := range snap.Skips {
		reasons[s.Reason[:strings.Index(s.Reason, ": ")+2]+s.Name[strings.LastIndex(s.Name, "/")+1:]] = true
	}
	for _, want := range []string{OwnedByGoog + "123456-compute@developer.gserviceaccount.com", OwnedByGoog + "_Reserved"} {
		if !reasons[want] {
			t.Errorf("missing skip %q; have %v", want, reasons)
		}
	}

	// A second restore finds everything, including the server-named
	// channel by its logical name, and creates nothing.
	before := dst.Count()
	for _, r := range a(dst).Restore(context.Background(), snap) {
		if !r.OK || r.Detail != "already present and identical" {
			t.Errorf("second restore: %s: ok=%v %s", r.Key, r.OK, r.Detail)
		}
	}
	if dst.Count() != before {
		t.Errorf("second restore created resources: %d -> %d", before, dst.Count())
	}
}

func TestOutputOnlyAndKinds(t *testing.T) {
	docs := fixtures(t)
	d, err := docs.Doc("https://iam.googleapis.com/$discovery/rest", "v1")
	if err != nil {
		t.Fatal(err)
	}
	k, err := d.Kind("ServiceAccount", "projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com")
	if err != nil {
		t.Fatal(err)
	}
	if k.Collection != "projects.serviceAccounts" || k.Create == nil || k.Create.Request.Ref != "CreateServiceAccountRequest" {
		t.Fatalf("kind %+v", k)
	}
	spec, ro := d.normalize("ServiceAccount", map[string]any{"name": "projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com",
		"email": "sa@p.iam.gserviceaccount.com", "uniqueId": "1", "displayName": "x", "etag": "e1", "newField": true})
	for _, k := range []string{"email", "uniqueId", "etag"} {
		if _, ok := spec[k]; ok {
			t.Errorf("%s kept in spec", k)
		}
	}
	if ro["email"] == nil || spec["displayName"] != "x" || spec["newField"] != true {
		t.Errorf("spec %v ro %v", spec, ro)
	}
	if !contains(d.Fields("ServiceAccount"), "displayName") {
		t.Error("fields missing displayName")
	}
	// Monitoring's audit records are flagged nowhere but written by the
	// server; they showed as drift after a real restore.
	md, _ := docs.Doc("https://monitoring.googleapis.com/$discovery/rest", "v3")
	nspec, _ := md.normalize("NotificationChannel", map[string]any{"type": "email", "displayName": "x",
		"creationRecord": map[string]any{"mutateTime": "2026-10-21T00:00:00Z"}, "mutationRecords": []any{map[string]any{"mutatedBy": "a@b"}}})
	if _, ok := nspec["creationRecord"]; ok {
		t.Errorf("creationRecord kept: %v", nspec)
	}
	if _, ok := nspec["mutationRecords"]; ok {
		t.Errorf("mutationRecords kept: %v", nspec)
	}
	if !generatedID("projects/p/notificationChannels/1234567") || generatedID("projects/p/metrics/shop-errors") {
		t.Error("generatedID")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
