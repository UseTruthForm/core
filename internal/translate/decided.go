package translate

import (
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// Types that need no destination: resource groups, which are a grouping
// and not a resource, and what issue #32 puts out of scope at first, which
// is refused with its reason rather than left "not looked at". A refusal
// here is a decision; "not looked at" means nobody has decided yet.

const azGroup = "microsoft.resources/resourcegroups"

// outOfScope maps a type prefix (lower case) to why it is refused. The
// longest matching prefix wins.
var outOfScope = map[string]string{
	"microsoft.authorization/roleassignments": "identity is not translated: Azure RBAC and the target's IAM differ in model, and a wrong translation is a security bug (#32)",
	"microsoft.authorization/roledefinitions": "identity is not translated: Azure RBAC and the target's IAM differ in model, and a wrong translation is a security bug (#32)",
	"microsoft.authorization/roleeligibility": "identity is not translated (#32)",
	"microsoft.authorization/locks":           "locks are not translated (#32); the target's equivalent (deletion protection, organization policies) is set on its own",
	"microsoft.authorization/policy":          "Azure Policy is not translated (#32); the target's equivalent (AWS Config rules and SCPs, GCP organization policies) is set on its own",
	"microsoft.managedidentity/":              "identity is not translated (#32): an app's managed identity becomes an IAM role (AWS) or service account (GCP) through workload identity, which is a change to the app",
	"microsoft.insights/diagnosticsettings":   "diagnostic settings are not translated (#32): the target's logging (CloudTrail and CloudWatch, Cloud Logging) is set on its own",
	"microsoft.insights/":                     "monitoring is not translated (#32): the target's (CloudWatch, Cloud Monitoring) is set on its own",
	"microsoft.operationalinsights/":          "log analytics is not translated (#32): the target's (CloudWatch Logs, Cloud Logging) is set on its own",
	"microsoft.web/serverfarms":               "App Service has no peer (#32); the nearest are AWS App Runner or Elastic Beanstalk and GCP Cloud Run, and moving to one is a redeployment",
	"microsoft.web/sites":                     "App Service has no peer (#32); the nearest are AWS App Runner or Elastic Beanstalk and GCP Cloud Run, and moving to one is a redeployment",
	"microsoft.logic/":                        "Logic Apps have no peer (#32); the nearest are AWS Step Functions and GCP Workflows, and a workflow is rewritten, not translated",
	"microsoft.security/":                     "Defender for Cloud settings are not translated (#32): the target's (Security Hub, Security Command Center) is set on its own",
	"microsoft.alertsmanagement/":             "alerting is not translated (#32)",
	"microsoft.network/networkwatchers":       "Azure creates a network watcher per region by itself; the target's flow logs and diagnostics are set on its own",
	"microsoft.costmanagement/":               "cost management is not translated (#32)",
	"microsoft.consumption/":                  "budgets are not translated (#32)",
	"microsoft.resources/deployments":         "a deployment is a record of a change, not a resource",
	"microsoft.resources/deploymentscripts":   "a deployment script is a record of a change, not a resource",
	"microsoft.resources/templatespecs":       "an ARM template spec is Azure's own infrastructure as code: the translation writes the target's snapshot instead",
}

type decided struct{}

func (decided) claims(kind string) bool {
	return kind == azGroup || scopeReason(kind) != ""
}

func scopeReason(kind string) string {
	best := ""
	for p := range outOfScope {
		if strings.HasPrefix(kind, p) && len(p) > len(best) {
			best = p
		}
	}
	return outOfScope[best]
}

func (decided) translate(objs []snapshot.Object, o *out) {
	sort.Slice(objs, func(i, j int) bool { return source(objs[i]) < source(objs[j]) })
	for _, obj := range objs {
		k := strings.ToLower(obj.Kind())
		if k != azGroup {
			o.entries = append(o.entries, Entry{Source: source(obj), State: Refused, Reason: scopeReason(k)})
			continue
		}
		where := map[string]string{"aws": "the account and region hold", "gcp": "the project holds"}[o.m.To]
		e := Entry{Source: source(obj), State: Mapped, Reason: "a resource group is a grouping, not a resource: " + where + " what it held"}
		p := newProps(spec(obj), "")
		p.quiet("location", "managedBy", "properties")
		if t := stringTags(p.m["tags"]); len(t) > 0 {
			p.lose("tags", "the group's tags are not put on what it held; tags each resource carries are carried with it", false)
		}
		p.quiet("tags")
		e.Losses = p.rest()
		o.entries = append(o.entries, e)
	}
}
