package translate

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/gcp"
	"github.com/usetruthform/core/internal/snapshot"
)

const (
	perimeterTestPolicy = "accessPolicies/4321"
	perimeterTestName   = perimeterTestPolicy + "/servicePerimeters/shop_private"
	perimeterTestWho    = "serviceAccount:restore@shop-ops.iam.gserviceaccount.com"
	perimeterBus        = "Microsoft.ServiceBus/namespaces shop/shopbus"
	perimeterKV         = "Microsoft.KeyVault/vaults shop/shopkv"
	perimeterACR        = "Microsoft.ContainerRegistry/registries shop/shopacr"
)

// perimeterMap is the private-access map for GCP with a perimeter named:
// restores run as a principal from outside, or from inside.
func perimeterMap(inside bool) Map {
	m := peMaps()["gcp"]
	m.PrivateAccess = &PrivateAccessMap{AccessPolicy: perimeterTestPolicy, Perimeter: "shop_private", RestoreIdentity: perimeterTestWho}
	if inside {
		m.PrivateAccess = &PrivateAccessMap{AccessPolicy: perimeterTestPolicy, Perimeter: "shop_private", RestoreFromInside: true}
	}
	return m
}

func perimeterOf(r Result) map[string]any {
	for _, o := range r.Snapshots["gcp"].Objects {
		if o.Kind() == gcpPerimeterKind {
			return obj(o.Body["spec"])
		}
	}
	return nil
}

func lossesAbout(e Entry, field, about string) []Loss {
	var out []Loss
	for _, l := range e.Losses {
		if l.Field == field && strings.Contains(l.Why, about) {
			out = append(out, l)
		}
	}
	return out
}

// With an access policy named, one service perimeter for the project
// restricts exactly the services whose source was private, and admits the
// restore's principal: for Pub/Sub's management methods alone, and for all
// of Secret Manager and Artifact Registry, which stays said as less
// protected. Pub/Sub is no longer less protected.
func TestPerimeterWritten(t *testing.T) {
	r := runPE(t, peFixture(), perimeterMap(false))
	want := `{"name":"` + perimeterTestName + `","status":{"ingressPolicies":[{"ingressFrom":{"identities":["` + perimeterTestWho + `"],"sources":[{"accessLevel":"*"}]},` +
		`"ingressTo":{"operations":[` +
		`{"methodSelectors":[{"method":"*"}],"serviceName":"artifactregistry.googleapis.com"},` +
		`{"methodSelectors":[{"method":"Publisher.CreateTopic"},{"method":"Publisher.GetTopic"},{"method":"Publisher.UpdateTopic"},{"method":"Subscriber.CreateSubscription"},{"method":"Subscriber.GetSubscription"},{"method":"Subscriber.UpdateSubscription"}],"serviceName":"pubsub.googleapis.com"},` +
		`{"methodSelectors":[{"method":"*"}],"serviceName":"secretmanager.googleapis.com"}],"resources":["*"]},"title":"restore and capture"}],` +
		`"resources":["projects/{{truthform|project-number}}"],"restrictedServices":["artifactregistry.googleapis.com","pubsub.googleapis.com","secretmanager.googleapis.com"]},"title":"shop_private"}`
	if got := canonJSON(perimeterOf(r)); got != want {
		t.Fatalf("perimeter:\n got %s\nwant %s", got, want)
	}
	if got, want := widening(r), []string{
		perimeterACR + " properties.networkRuleSet",
		perimeterKV + " properties.enableSoftDelete",
		perimeterKV + " properties.networkAcls",
		perimeterBus + " properties.minimumTlsVersion",
		"Microsoft.Storage/storageAccounts shop/shopfiles properties.minimumTlsVersion",
	}; !reflect.DeepEqual(got, want) {
		t.Errorf("widening: %v", got)
	}
	for src, c := range map[string][2]string{
		perimeterBus: {"properties.publicNetworkAccess", "Pub/Sub (pubsub.googleapis.com)"},
		perimeterKV:  {"properties.networkAcls", "Secret Manager (secretmanager.googleapis.com)"},
		perimeterACR: {"properties.networkRuleSet", "Artifact Registry (artifactregistry.googleapis.com)"},
	} {
		e := entry(t, r, src)
		ls := lossesAbout(e, c[0], "service perimeter shop_private restricts "+c[1]+" for the whole project")
		if len(ls) != 1 || ls[0].Widens || !strings.Contains(ls[0].Why, perimeterTestWho+" from anywhere") || !strings.Contains(ls[0].Why, "management calls too") {
			t.Errorf("%s: %+v", src, e.Losses)
		}
		if !strings.Contains(fmt.Sprint(e.Targets), gcpPerimeterKind+" "+perimeterTestName) {
			t.Errorf("%s targets: %v", src, e.Targets)
		}
		whole := lossesAbout(e, c[0], "is admitted from anywhere for all of")
		if src == perimeterBus {
			if len(whole) != 0 {
				t.Errorf("Pub/Sub's rule names methods; nothing widens: %+v", whole)
			}
			continue
		}
		if len(whole) != 1 || !whole[0].Widens || !strings.Contains(whole[0].Why, "privateAccess.restoreFromInside") {
			t.Errorf("%s: the principal's reach is not said: %+v", src, e.Losses)
		}
	}
	if l := lossesAbout(entry(t, r, perimeterKV), "properties.networkAcls", "takes no method restriction"); len(l) != 1 {
		t.Error("why Secret Manager is admitted whole is not said")
	}
	if l := lossesAbout(entry(t, r, perimeterACR), "properties.networkRuleSet", "answers with an operation"); len(l) != 1 {
		t.Error("why Artifact Registry is admitted whole is not said")
	}
	for _, s := range []string{
		"Service perimeter " + perimeterTestName + " restricts artifactregistry.googleapis.com, pubsub.googleapis.com, secretmanager.googleapis.com for the whole target project",
		"in no other perimeter", "up to 30 minutes", "A capture of the target project does not hold service perimeter shop_private",
		"new push subscription only to a Cloud Run service", "*.pkg.dev",
	} {
		if !anyRequirement(r, s) {
			t.Errorf("no requirement about %q", s)
		}
	}
	// Cloud Storage keeps its bucket's IP filter, and is not restricted.
	if object(t, r, "gcp", gcsBucket, "shopfiles-docs")["ipFilter"] == nil || strings.Contains(canonJSON(perimeterOf(r)), "storage.googleapis.com") {
		t.Error("Cloud Storage is the bucket's IP filter's, not the perimeter's")
	}
}

// Restores that run from inside the perimeter need no ingress rule, and
// then nothing of the three is less protected.
func TestPerimeterFromInside(t *testing.T) {
	r := runPE(t, peFixture(), perimeterMap(true))
	st := obj(perimeterOf(r)["status"])
	if st["ingressPolicies"] != nil || len(list(st["restrictedServices"])) != 3 {
		t.Errorf("perimeter: %v", st)
	}
	for _, w := range widening(r) {
		for _, f := range []string{"networkAcls", "networkRuleSet", "publicNetworkAccess"} {
			if strings.HasSuffix(w, f) {
				t.Errorf("less protected behind a perimeter with no ingress rule: %s", w)
			}
		}
	}
	if l := lossesAbout(entry(t, r, perimeterKV), "properties.networkAcls", "nobody outside it: restores and captures run from inside (privateAccess.restoreFromInside)"); len(l) != 1 || l[0].Widens {
		t.Errorf("vault: %+v", entry(t, r, perimeterKV).Losses)
	}
}

// A perimeter restricts a service for the whole project: a public source
// of a service that has a private one is closed with it, and says so; a
// service with no private source is left out; and with none at all no
// perimeter is written.
func TestPerimeterMixedPrivateAndPublic(t *testing.T) {
	open := func(p map[string]any) { p["publicNetworkAccess"] = "Enabled" }
	s := lockFixture(true, map[string]func(map[string]any){lockACR: open})
	s.Objects = append(s.Objects,
		az("Microsoft.KeyVault/vaults", "shop", "openkv", map[string]any{"location": "westeurope", "properties": map[string]any{
			"tenantId": "t", "sku": map[string]any{"family": "A", "name": "standard"}, "enableRbacAuthorization": true, "publicNetworkAccess": "Enabled"}}),
		az("Microsoft.KeyVault/vaults/secrets", "shop", "openkv/api-key", pr(map[string]any{"attributes": map[string]any{"enabled": true}})))
	r := runPE(t, s, perimeterMap(true))
	if got := fmt.Sprint(obj(perimeterOf(r)["status"])["restrictedServices"]); got != "[pubsub.googleapis.com secretmanager.googleapis.com]" {
		t.Errorf("restricted: %s", got)
	}
	pub := entry(t, r, "Microsoft.KeyVault/vaults shop/openkv")
	if l := lossesAbout(pub, "properties.networkAcls", "it answered the internet; service perimeter shop_private restricts Secret Manager for the whole project, because Key Vault shop/shopkv answered only privately"); len(l) != 1 || l[0].Widens {
		t.Errorf("a public vault closed with a private one: %+v", pub.Losses)
	}
	if !strings.Contains(fmt.Sprint(pub.Targets), perimeterTestName) {
		t.Errorf("targets: %v", pub.Targets)
	}
	acr := entry(t, r, perimeterACR)
	if hasLoss(acr, "properties.networkRuleSet") != nil || strings.Contains(fmt.Sprint(acr.Targets), "servicePerimeters") {
		t.Errorf("a public registry, whose service is not restricted: %+v %v", acr.Losses, acr.Targets)
	}
	// Nothing private: the map's keys write nothing.
	all := lockFixture(true, map[string]func(map[string]any){lockACR: open, lockKV: open, lockBus: open, lockSt: open})
	if p := perimeterOf(runPE(t, all, perimeterMap(true))); p != nil {
		t.Errorf("a perimeter with nothing private: %v", p)
	}
}

// Every network of the project is inside its perimeter. One that had no
// private endpoint to a service, and no peering with a network that had,
// reaches it on GCP: said as less protected. A peered one reached the
// private endpoint on Azure too.
func TestPerimeterAdmitsEveryNetwork(t *testing.T) {
	lone := az("Microsoft.Network/virtualNetworks", "net", "lone", map[string]any{"location": "westeurope", "properties": map[string]any{
		"addressSpace": map[string]any{"addressPrefixes": []any{"10.40.0.0/16"}},
		"subnets":      []any{map[string]any{"name": "only", "properties": map[string]any{"addressPrefix": "10.40.1.0/24", "defaultOutboundAccess": false}}}}})
	s := peFixture()
	s.Objects = append(s.Objects, lone)
	r := runPE(t, s, perimeterMap(true))
	for _, c := range [][2]string{{perimeterBus, "properties.publicNetworkAccess"}, {perimeterKV, "properties.networkAcls"}, {perimeterACR, "properties.networkRuleSet"}} {
		l := lossesAbout(entry(t, r, c[0]), c[1], "VPC network(s) lone had no private endpoint to it")
		if len(l) != 1 || !l[0].Widens {
			t.Errorf("%s: %+v", c[0], entry(t, r, c[0]).Losses)
		}
	}
	peer := func(remote string) map[string]any {
		return pr(map[string]any{"remoteVirtualNetwork": azRef(typVNet, "net", remote), "allowVirtualNetworkAccess": true, "peeringState": "Connected", "peeringSyncLevel": "FullyInSync"})
	}
	s.Objects = append(s.Objects, az(typVNet+"/virtualNetworkPeerings", "net", "lone/to-core", peer("core")), az(typVNet+"/virtualNetworkPeerings", "net", "core/to-lone", peer("lone")))
	for _, w := range widening(runPE(t, s, perimeterMap(true))) {
		if !strings.HasSuffix(w, "minimumTlsVersion") && !strings.HasSuffix(w, "enableSoftDelete") {
			t.Errorf("a peered network reached the private endpoint on Azure too: %s", w)
		}
	}
	// With no private endpoint in the snapshot, no network reached it.
	r = runPE(t, lockFixture(false, nil), perimeterMap(true))
	if l := lossesAbout(entry(t, r, perimeterKV), "properties.networkAcls", "VPC network(s) core had no private endpoint to it"); len(l) != 1 || !l[0].Widens {
		t.Errorf("no private endpoint: %+v", entry(t, r, perimeterKV).Losses)
	}
}

// A public range the source's firewall allowed is not admitted by the
// perimeter: narrower, named, with what admits it.
func TestPerimeterDropsAllowedRanges(t *testing.T) {
	r := runPE(t, lockFixture(true, lockFirewalls()), perimeterMap(true))
	if got := fmt.Sprint(obj(perimeterOf(r)["status"])["restrictedServices"]); got != "[artifactregistry.googleapis.com secretmanager.googleapis.com]" {
		t.Errorf("restricted: %s", got)
	}
	if strings.Contains(canonJSON(perimeterOf(r)), "203.0.113.0") || obj(perimeterOf(r)["status"])["accessLevels"] != nil {
		t.Errorf("a range is admitted: %v", perimeterOf(r))
	}
	for _, c := range [][2]string{{perimeterKV, "properties.networkAcls"}, {perimeterACR, "properties.networkRuleSet"}} {
		l := lossesAbout(entry(t, r, c[0]), c[1], "its firewall allowed 203.0.113.0/24, 198.51.100.7/32; the perimeter admits no public address range")
		if len(l) != 1 || l[0].Widens {
			t.Errorf("%s: %+v", c[0], entry(t, r, c[0]).Losses)
		}
	}
	if !anyRequirement(r, "Key Vault shop/shopkv allowed the public range(s) 203.0.113.0/24, 198.51.100.7/32 on Azure, which service perimeter shop_private refuses: to admit them, create an access level") {
		t.Errorf("requirements: %v", r.Report.Requirements)
	}
}

// The map says where the perimeter goes and how restores pass it, or
// nothing is written: a perimeter with no way in for the restore would
// lock out the restore that wrote it.
func TestPerimeterMapIsHeldToItsChoices(t *testing.T) {
	for want, pa := range map[string]PrivateAccessMap{
		"would lock out the restore that wrote it": {AccessPolicy: perimeterTestPolicy, Perimeter: "shop_private"},
		"are both set":                                            {AccessPolicy: perimeterTestPolicy, Perimeter: "shop_private", RestoreIdentity: perimeterTestWho, RestoreFromInside: true},
		"privateAccess.accessPolicy":                              {AccessPolicy: "organizations/12/accessPolicies/4321", Perimeter: "shop_private", RestoreFromInside: true},
		`privateAccess.accessPolicy: ""`:                          {Perimeter: "shop_private", RestoreFromInside: true},
		`privateAccess.perimeter: "shop-private"`:                 {AccessPolicy: perimeterTestPolicy, Perimeter: "shop-private", RestoreFromInside: true},
		`privateAccess.perimeter: ""`:                             {AccessPolicy: perimeterTestPolicy, RestoreFromInside: true},
		`privateAccess.restoreIdentity: "restore@shop.iam"`:       {AccessPolicy: perimeterTestPolicy, Perimeter: "shop_private", RestoreIdentity: "restore@shop.iam"},
		`privateAccess.restoreIdentity: "group:ops@shop.example"`: {AccessPolicy: perimeterTestPolicy, Perimeter: "shop_private", RestoreIdentity: "group:ops@shop.example"},
	} {
		m := peMaps()["gcp"]
		m.PrivateAccess = &pa
		if _, err := Translate(peFixture(), m, targets(t)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: %v, want an error about %s", pa, err, want)
		}
	}
	a := peMaps()["aws"]
	a.PrivateAccess = perimeterMap(true).PrivateAccess
	if err := a.validate(); err == nil || !strings.Contains(err.Error(), "privateAccess is for gcp") {
		t.Errorf("aws: %v", err)
	}
	for _, ok := range []string{perimeterTestWho, "user:alex@shop.example"} {
		m := perimeterMap(false)
		m.PrivateAccess.RestoreIdentity = ok
		if err := m.validate(); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
}

// The translation restores into a project behind its own perimeter, as
// the principal the map names from outside it, and again: the fake closes
// the restricted services as VPC Service Controls does, so every call a
// restore, an update and a capture make must pass the ingress rule. Any
// other principal is locked out, which is what the map's choice is for.
func TestPerimeterRestores(t *testing.T) {
	tg := targets(t)
	ctx := context.Background()
	for _, inside := range []bool{false, true} {
		gs := runPE(t, peFixture(), perimeterMap(inside)).Snapshots["gcp"]
		w := gcp.NewWorld(tg.GCP)
		w.Parent(perimeterTestPolicy)
		f := w.Project("target-project", "123456789")
		f.Caller, f.Inside = perimeterTestWho, inside
		for _, res := range gcp.Restore(ctx, f, tg.GCP, gs, gcp.RestoreOptions{}) {
			if !res.OK {
				t.Errorf("inside %v: %s: %s", inside, res.Key, res.Detail)
			}
		}
		p, err := f.Call(ctx, "GET", "https://accesscontextmanager.googleapis.com/v1/"+perimeterTestName, nil)
		if err != nil || fmt.Sprint(obj(p["status"])["resources"]) != "[projects/123456789]" {
			t.Fatalf("inside %v: the perimeter in the policy: %v %v", inside, p, err)
		}
		for _, res := range gcp.Restore(ctx, f, tg.GCP, gs, gcp.RestoreOptions{}) {
			if !res.OK || res.Detail != "already present and identical" {
				t.Errorf("inside %v, again: %s: %v %s", inside, res.Key, res.OK, res.Detail)
			}
		}
		// A capture reads everything but the perimeter, which is not the
		// project's.
		got, err := gcp.Capture(ctx, f, tg.GCP, gcp.Policy{})
		if err != nil || len(got.Skips) != 0 {
			t.Fatalf("inside %v: capture: %v, skips %v", inside, err, got.Skips)
		}
		for _, c := range snapshot.Compare(gs, got) {
			if !strings.Contains(c.Key, "servicePerimeters") {
				t.Errorf("inside %v: the restored target differs: %s %s %v", inside, c.Kind, c.Key, c.Fields)
			}
		}
		// A changed topic and subscription are updated through the rule.
		for _, o := range gs.Objects {
			if o.Kind() == psTopic || o.Kind() == psSub {
				obj(o.Body["spec"])["labels"] = map[string]any{"moved": "yes"}
			}
		}
		for _, res := range gcp.Restore(ctx, f, tg.GCP, gs, gcp.RestoreOptions{Update: true}) {
			if !res.OK {
				t.Errorf("inside %v, --update: %s: %s", inside, res.Key, res.Detail)
			}
		}
		if f.Updates == 0 {
			t.Errorf("inside %v: nothing was updated", inside)
		}
		// Anyone else, from outside, is refused all three services.
		f.Caller, f.Inside = "user:someone@shop.example", false
		refused := map[string]bool{}
		for _, res := range gcp.Restore(ctx, f, tg.GCP, gs, gcp.RestoreOptions{}) {
			if !res.OK && strings.Contains(res.Detail, "prohibited by organization's policy") {
				refused[strings.Split(strings.Split(res.Key, "|")[1], "/")[0]] = true
			}
		}
		if len(refused) != 3 || !refused["pubsub.googleapis.com"] || !refused["secretmanager.googleapis.com"] || !refused["artifactregistry.googleapis.com"] {
			t.Errorf("inside %v: another principal from outside was refused only %v", inside, refused)
		}
	}
	// Without the access policy, the perimeter is refused and says so.
	gs := runPE(t, peFixture(), perimeterMap(true)).Snapshots["gcp"]
	f := gcp.NewWorld(tg.GCP).Project("target-project", "123456789")
	for _, res := range gcp.Restore(ctx, f, tg.GCP, gs, gcp.RestoreOptions{}) {
		if strings.Contains(res.Key, "servicePerimeters") && (res.OK || !strings.Contains(res.Detail, perimeterTestPolicy+" was not found")) {
			t.Errorf("no such policy: %v %s", res.OK, res.Detail)
		}
	}
}

func TestPerimeterGolden(t *testing.T) {
	golden(t, "perimeter-gcp", runPE(t, peFixture(), perimeterMap(false)))
	golden(t, "perimeter-inside-gcp", runPE(t, peFixture(), perimeterMap(true)))
}
