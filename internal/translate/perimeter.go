package translate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// A VPC Service Controls perimeter, for the Google services that take no
// network setting of their own.
//
// Pub/Sub, Secret Manager and Artifact Registry cannot say where a request
// may come from: IAM conditions know no source network ("The access levels
// attribute is available only when you use Identity-Aware Proxy",
// https://docs.cloud.google.com/iam/docs/conditions-attribute-reference),
// and deny policies' conditions "only recognize resource tag functions"
// (https://docs.cloud.google.com/iam/docs/deny-overview). What closes them
// to the internet is a service perimeter: "Access from the internet to
// managed resources within a service perimeter is denied by default"
// (https://docs.cloud.google.com/vpc-service-controls/docs/overview). For
// each of the three: "You can configure your perimeters to protect this
// service" (https://docs.cloud.google.com/vpc-service-controls/docs/supported-products).
//
// A perimeter is not the project's. It belongs to an access policy
// (accessPolicies/<number>), the organization's or one scoped to a folder
// or project: "Scoped policies are access policies that are scoped to
// specific folders or projects", made by "an organization-level Access
// Context Manager administrator", who "assigns IAM permissions to the
// delegated administrator directly on the access policy resource"
// (https://docs.cloud.google.com/access-context-manager/docs/scoped-policies).
// Even a policy scoped to the one project is the organization's to create,
// so the map names an existing one (privateAccess.accessPolicy); making
// policies is organization administration, not translation.
//
// What the perimeter does that the Azure source did not is said, never
// left out:
//
//   - It restricts a service for the whole project. A namespace, vault or
//     registry that answered the internet is closed with the private one
//     of its service: narrower, and named on it.
//   - Every VPC network of the project is inside it (a network is added on
//     its own only "instead of adding an entire host project",
//     https://docs.cloud.google.com/vpc-service-controls/docs/vpc-perimeters-management).
//     A translated network that had no private endpoint to the service,
//     and no peering with one that had, now reaches it: less protected,
//     and named.
//   - It refuses management calls from outside too ("VPC Service Controls
//     protection applies to all administrator operations, publisher
//     operations, and subscriber operations", supported-products), the
//     restore's and a later capture's among them. The map must say how
//     those run, or nothing is written: from inside the perimeter
//     (privateAccess.restoreFromInside), or as a principal an ingress rule
//     admits from anywhere (privateAccess.restoreIdentity). The rule names
//     only the methods a restore and capture call where the service takes
//     method restrictions (Pub/Sub does,
//     https://docs.cloud.google.com/vpc-service-controls/docs/supported-method-restrictions);
//     where it takes none (Secret Manager is not in that list) or answers a
//     create with an operation whose polling is no listed method (Artifact
//     Registry), the principal is admitted for the whole API, data too,
//     which stays reported as less protected.
//   - A public address range the source's firewall allowed is not
//     admitted: that takes an access level, which is not written. Narrower,
//     and named.
//
// Cloud Storage is not restricted by it: a bucket's IP filter names the
// networks per bucket, where the perimeter would close every bucket of the
// project.

const (
	gcpPerimeterKind = "accesscontextmanager.googleapis.com/ServicePerimeter"
	gcpProjectNumber = "projects/{{truthform|project-number}}"
)

// gcpService is one Azure source written to a Google service that only a
// perimeter closes.
type gcpService struct {
	src     string // its entry's source
	field   string // where its network setting is
	what    string // "Service Bus namespace rg/shop"
	product string // "Pub/Sub"
	api     string // "pubsub.googleapis.com"
	private string // why it answered only some networks, or ""
	ranges  []string
	path    *privatePath
	// at is where its losses go among its entry's: where its network
	// setting is read, before the settings read after it.
	at int
}

// gcpManagement are the methods a restore and a capture call, for the
// services whose ingress rules take method restrictions, as the list
// names them
// (https://docs.cloud.google.com/vpc-service-controls/docs/supported-method-restrictions).
// A service that is not here is admitted whole.
var gcpManagement = map[string][]string{
	"pubsub.googleapis.com": {
		"Publisher.CreateTopic", "Publisher.GetTopic", "Publisher.UpdateTopic",
		"Subscriber.CreateSubscription", "Subscriber.GetSubscription", "Subscriber.UpdateSubscription",
	},
}

// gcpWhole says why a service's ingress rule cannot be held to management
// methods.
var gcpWhole = map[string]string{
	"secretmanager.googleapis.com":    "Secret Manager takes no method restriction in an ingress rule",
	"artifactregistry.googleapis.com": "a repository's create answers with an operation, and polling it is not a method an ingress rule can name",
}

// gcpClosedBy registers a source for the project's perimeter; the losses
// are decided once every family has written (gcpPerimeters).
func (o *out) gcpClosedBy(s gcpService) { o.gcpServices = append(o.gcpServices, s) }

// gcpPerimeters decides, once everything is written, how the sources on
// perimeter-only services are closed, and writes the perimeter when the
// map names where it goes.
func gcpPerimeters(o *out) {
	at := map[string]int{}
	for i, e := range o.entries {
		at[e.Source] = i
	}
	var uses []gcpService
	private := map[string][]gcpService{}
	for _, s := range o.gcpServices {
		if _, ok := at[s.src]; ok {
			uses = append(uses, s)
			if s.private != "" {
				private[s.api] = append(private[s.api], s)
			}
		}
	}
	added := map[string]int{}
	lose := func(s gcpService, why string, widens bool) {
		e := &o.entries[at[s.src]]
		i := min(s.at+added[s.src], len(e.Losses))
		e.Losses = append(e.Losses[:i:i], append([]Loss{{Field: s.field, Why: why, Widens: widens}}, e.Losses[i:]...)...)
		added[s.src]++
	}
	pa := o.m.PrivateAccess
	if pa == nil {
		for _, s := range uses {
			if s.private != "" {
				lose(s, s.private+"; "+gcpNoPerimeter(o, s), true)
			}
		}
		return
	}
	if len(private) == 0 {
		return
	}
	apis := sortedKeys(private)
	name := pa.AccessPolicy + "/servicePerimeters/" + pa.Perimeter
	status := map[string]any{"resources": []any{gcpProjectNumber}, "restrictedServices": anyStrings(apis)}
	who := "nobody outside it: restores and captures run from inside (privateAccess.restoreFromInside)"
	if pa.RestoreIdentity != "" {
		var ops []any
		for _, api := range apis {
			sel := []any{map[string]any{"method": "*"}}
			if ms := gcpManagement[api]; ms != nil {
				sel = nil
				for _, m := range ms {
					sel = append(sel, map[string]any{"method": m})
				}
			}
			ops = append(ops, map[string]any{"serviceName": api, "methodSelectors": sel})
		}
		status["ingressPolicies"] = []any{map[string]any{
			"title":       "restore and capture",
			"ingressFrom": map[string]any{"identities": []any{pa.RestoreIdentity}, "sources": []any{map[string]any{"accessLevel": "*"}}},
			"ingressTo":   map[string]any{"resources": []any{"*"}, "operations": ops},
		}}
		who = pa.RestoreIdentity + " from anywhere, for restores and captures (privateAccess.restoreIdentity)"
	}
	var sources []string
	for _, api := range apis {
		for _, s := range private[api] {
			sources = append(sources, s.src)
		}
	}
	sort.Strings(sources)
	target := o.add("gcp", sources[0], snapshot.Object{Body: map[string]any{"apiVersion": gcpAPIVersion, "kind": gcpPerimeterKind,
		"metadata": map[string]any{"name": name, "annotations": map[string]any{
			"truthform.org/discovery":  "accesscontextmanager/v1",
			"truthform.org/schema":     "ServicePerimeter",
			"truthform.org/collection": "accessPolicies.servicePerimeters",
			"truthform.org/parent":     pa.AccessPolicy,
		}}, "spec": map[string]any{"name": name, "title": pa.Perimeter, "status": status}}})

	nets, reach := gcpNetworks(o)
	for _, s := range uses {
		e := &o.entries[at[s.src]]
		if private[s.api] == nil {
			continue
		}
		e.Targets = append(e.Targets, target)
		if s.private == "" {
			lose(s, fmt.Sprintf("it answered the internet; service perimeter %s restricts %s for the whole project, because %s answered only privately, so it is closed to the internet with it: a perimeter cannot restrict one resource of a service", pa.Perimeter, s.product, private[s.api][0].what), false)
			continue
		}
		lose(s, fmt.Sprintf("%s; on GCP service perimeter %s restricts %s (%s) for the whole project: requests from the project's own networks pass, and %s. Every other request is refused, management calls too, which Azure's management plane answered from anywhere", s.private, pa.Perimeter, s.product, s.api, who), false)
		if pa.RestoreIdentity != "" && gcpManagement[s.api] == nil {
			lose(s, fmt.Sprintf("%s is admitted from anywhere for all of %s's API, reading and writing its data included, wherever IAM allows it: %s, so the restore's own calls cannot be admitted alone. Running restores and captures from inside the perimeter closes that (privateAccess.restoreFromInside)", pa.RestoreIdentity, s.product, gcpWhole[s.api]), true)
		}
		var had map[string]bool
		if s.path != nil {
			had = reach(sortedKeys(s.path.networks))
		}
		var extra []string
		for _, n := range nets {
			if !had[n] {
				extra = append(extra, n)
			}
		}
		if len(extra) > 0 {
			lose(s, fmt.Sprintf("VPC network(s) %s had no private endpoint to it on Azure, nor a peering with a network that had, and reach it on GCP: every network of the project is inside its perimeter", strings.Join(extra, ", ")), true)
		}
		if len(s.ranges) > 0 {
			lose(s, fmt.Sprintf("its firewall allowed %s; the perimeter admits no public address range, so requests from there are refused", strings.Join(s.ranges, ", ")), false)
			o.require(fmt.Sprintf("%s allowed the public range(s) %s on Azure, which service perimeter %s refuses: to admit them, create an access level with those ranges in %s (basic.conditions.ipSubnetworks) and add an ingress rule from it to %s", s.what, strings.Join(s.ranges, ", "), pa.Perimeter, pa.AccessPolicy, s.api))
		}
	}
	o.require(fmt.Sprintf("Service perimeter %s restricts %s for the whole target project, in access policy %s, which is the organization's: whoever restores needs accesscontextmanager.servicePerimeters.create, get and update on that policy (roles/accesscontextmanager.policyEditor), the Access Context Manager API enabled in the target project (the restore's calls are counted against it), and the project must be in the policy's scope and in no other perimeter (\"You can include your project only in one service perimeter\", https://docs.cloud.google.com/vpc-service-controls/docs/service-perimeters); where it already is in one, add these services and the ingress rule to that perimeter instead", name, strings.Join(apis, ", "), pa.AccessPolicy))
	o.require(fmt.Sprintf("Service perimeter %s takes up to 30 minutes to take effect (https://docs.cloud.google.com/vpc-service-controls/docs/create-service-perimeters), and then refuses every request to %s from outside the project's networks with \"Request is prohibited by organization's policy\": the Google Cloud console, other projects and other tooling included. Admit what must pass with ingress rules or access levels of the organization's own, and try the perimeter as a dry run first where unsure (gcloud access-context-manager perimeters dry-run create)", pa.Perimeter, strings.Join(apis, ", ")))
	o.require(fmt.Sprintf("A capture of the target project does not hold service perimeter %s: it is the access policy's, and Cloud Asset Inventory lists a project's own resources. A diff of the target against this translation reports it as missing; a restore finds it by its name", pa.Perimeter))
	for _, api := range apis {
		switch api {
		case "pubsub.googleapis.com":
			o.require("Inside a service perimeter Pub/Sub makes a new push subscription only to a Cloud Run service's default run.app URL, and a subscription must be in the same perimeter as its topic (https://docs.cloud.google.com/vpc-service-controls/docs/supported-products)")
		case "artifactregistry.googleapis.com":
			o.require("Inside a service perimeter, machines pull from Artifact Registry by pkg.dev names that resolve to private.googleapis.com or restricted.googleapis.com: \"you must configure DNS\" for *.pkg.dev (https://docs.cloud.google.com/vpc-service-controls/docs/supported-products); that zone is not written")
		}
	}
}

// gcpNetworks are the VPC networks written, and a function giving, for
// some of them, those and the networks peered with them.
func gcpNetworks(o *out) ([]string, func([]string) map[string]bool) {
	var nets []string
	peers := map[string][]string{}
	for _, x := range o.objects["gcp"] {
		if x.Kind() != gcpNetwork {
			continue
		}
		spec, _ := x.Body["spec"].(map[string]any)
		n := fmt.Sprint(spec["name"])
		nets = append(nets, n)
		for _, p := range list(spec["peerings"]) {
			u := fmt.Sprint(obj(p)["network"])
			peers[n] = append(peers[n], u[strings.LastIndex(u, "/")+1:])
		}
	}
	sort.Strings(nets)
	return nets, func(of []string) map[string]bool {
		in := map[string]bool{}
		for _, n := range of {
			in[n] = true
			for _, p := range peers[n] {
				in[p] = true
			}
		}
		return in
	}
}

// gcpNoPerimeter says why a private Azure service stays less protected
// where the map names no access policy, and what closes it.
func gcpNoPerimeter(o *out, s gcpService) string {
	o.require(fmt.Sprintf("To close %s to the internet as %s was, name an existing access policy and a perimeter in the map (privateAccess.accessPolicy: accessPolicies/<number>, privateAccess.perimeter: <name>) and how restores and captures pass it (privateAccess.restoreIdentity: serviceAccount:<email>, or privateAccess.restoreFromInside: true): a VPC Service Controls perimeter is then written that restricts %s for the whole target project. The access policy is the organization's to create (gcloud access-context-manager policies create, scoped to the project or not)", s.product, s.what, s.api))
	return fmt.Sprintf("%s answers on Google's public endpoint to whoever IAM allows: it has no network setting of its own, and the VPC Service Controls perimeter that closes it (%s, for the whole project) is written only into an access policy the map names (privateAccess.accessPolicy)", s.product, s.api)
}
