package translate

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/awscc"
	"github.com/usetruthform/core/internal/gcp"
	"github.com/usetruthform/core/internal/snapshot"
)

// acrFixture is a made-up set of registries: one locked down with every
// policy on and a geo-replica, one open to anonymous pulls, one whose
// name Artifact Registry does not take, and the children a registry can
// have that do not move.
func acrFixture() snapshot.Snapshot {
	return snapshot.Snapshot{Platform: "azure", Policy: "default", Objects: []snapshot.Object{
		az("Microsoft.ContainerRegistry/registries", "rg", "shopacr", map[string]any{"location": "westeurope",
			"tags":     map[string]any{"team": "platform", "Cost Center": "42"},
			"sku":      map[string]any{"name": "Premium", "tier": "Premium"},
			"identity": map[string]any{"type": "UserAssigned", "userAssignedIdentities": map[string]any{"{{truthform|ref|Microsoft.ManagedIdentity/userAssignedIdentities|rg|acr-key|id}}": map[string]any{}}},
			"properties": map[string]any{
				"loginServer": "shopacr.azurecr.io", "adminUserEnabled": true, "publicNetworkAccess": "Enabled",
				"networkRuleSet":           map[string]any{"defaultAction": "Deny", "ipRules": []any{map[string]any{"action": "Allow", "value": "198.51.100.0/24"}}},
				"networkRuleBypassOptions": "AzureServices", "networkRuleBypassAllowedForTasks": false,
				"policies": map[string]any{
					"quarantinePolicy":                 map[string]any{"status": "enabled"},
					"trustPolicy":                      map[string]any{"type": "Notary", "status": "enabled"},
					"retentionPolicy":                  map[string]any{"days": float64(14), "status": "enabled", "lastUpdatedTime": "2026-01-01T00:00:00Z"},
					"exportPolicy":                     map[string]any{"status": "disabled"},
					"azureADAuthenticationAsArmPolicy": map[string]any{"status": "enabled"},
				},
				"encryption": map[string]any{"status": "enabled", "keyVaultProperties": map[string]any{
					"keyIdentifier": "https://shop.vault.azure.net/keys/acr", "identity": "00000000-0000-0000-0000-0000000000cc"}},
				"dataEndpointEnabled": true, "zoneRedundancy": "Enabled", "anonymousPullEnabled": false,
				"roleAssignmentMode": "LegacyRegistryPermissions", "provisioningState": "Succeeded",
			}}),
		az("Microsoft.ContainerRegistry/registries/replications", "rg", "shopacr/northeurope", map[string]any{"location": "northeurope",
			"properties": map[string]any{"regionEndpointEnabled": true, "zoneRedundancy": "Disabled"}}),
		az("Microsoft.ContainerRegistry/registries", "rg", "pubimages", map[string]any{"location": "westeurope",
			"sku": map[string]any{"name": "Basic"}, "properties": map[string]any{"adminUserEnabled": false, "anonymousPullEnabled": true,
				"publicNetworkAccess": "Enabled", "policies": map[string]any{"exportPolicy": map[string]any{"status": "enabled"}}}}),
		az("Microsoft.ContainerRegistry/registries", "rg", "9lives", map[string]any{"location": "westeurope",
			"sku": map[string]any{"name": "Standard"}, "properties": map[string]any{"publicNetworkAccess": "Enabled"}}),
		az("Microsoft.ContainerRegistry/registries/scopeMaps", "rg", "shopacr/pull-only", pr(map[string]any{"actions": []any{"repositories/app/content/read"}})),
		az("Microsoft.ContainerRegistry/registries/tokens", "rg", "shopacr/ci", pr(map[string]any{"status": "enabled"})),
		az("Microsoft.ContainerRegistry/registries/credentialSets", "rg", "shopacr/hub", pr(map[string]any{"loginServer": "docker.io"})),
		az("Microsoft.ContainerRegistry/registries/connectedRegistries", "rg", "shopacr/edge", pr(map[string]any{"mode": "ReadOnly"})),
		az("Microsoft.ContainerRegistry/registries/webhooks", "rg", "shopacr/on-push", map[string]any{"location": "westeurope", "properties": map[string]any{"actions": []any{"push"}}}),
		az("Microsoft.ContainerRegistry/registries/cacheRules", "rg", "shopacr/dockerhub", pr(map[string]any{"sourceRepository": "docker.io/library/nginx"})),
		az("Microsoft.ContainerRegistry/registries/privateEndpointConnections", "rg", "shopacr/pe-1", pr(map[string]any{})),
		az("Microsoft.ContainerRegistry/registries/tasks", "rg", "shopacr/build", pr(map[string]any{})),
		az("Microsoft.ContainerRegistry/registries/replications", "rg", "gone/eastus", map[string]any{"location": "eastus"}),
	}}
}

func acrMaps() map[string]Map {
	a := Map{To: "aws", Region: "eu-west-1"}
	a.Destinations.Registry = "ecr"
	g := Map{To: "gcp", Region: "europe-west1"}
	g.Destinations.Registry = "artifact-registry"
	return map[string]Map{"aws": a, "gcp": g}
}

const (
	acrShop = "Microsoft.ContainerRegistry/registries rg/shopacr"
	acrPub  = "Microsoft.ContainerRegistry/registries rg/pubimages"
	acrNine = "Microsoft.ContainerRegistry/registries rg/9lives"
)

func TestRegistryGolden(t *testing.T) {
	for name, m := range acrMaps() {
		r := runKV(t, acrFixture(), m)
		golden(t, "registry-"+name, r)
		seen := map[string]int{}
		for _, e := range r.Report.Entries {
			seen[e.Source]++
			// The fixture holds only settings a rule reads.
			for _, l := range e.Losses {
				if l.Unread {
					t.Errorf("%s: %s: %s is unread", name, e.Source, l.Field)
				}
			}
		}
		for _, o := range acrFixture().Objects {
			if seen[source(o)] != 1 {
				t.Errorf("%s: %s is reported %d times", name, source(o), seen[source(o)])
			}
		}
		if len(seen) != len(acrFixture().Objects) {
			t.Errorf("%s: %d entries for %d objects", name, len(seen), len(acrFixture().Objects))
		}
	}
}

func TestRegistryOnAWS(t *testing.T) {
	r := runKV(t, acrFixture(), acrMaps()["aws"])
	tm := object(t, r, "aws", awsRepoTmpl, "shopacr")
	// Its firewall allowed one range: the repositories' policy denies
	// pulls and pushes from anywhere else, and grants nothing.
	want := map[string]any{"Prefix": "shopacr", "AppliedFor": []any{"CREATE_ON_PUSH"}, "Description": "From Azure Container Registry rg/shopacr",
		"ImageTagMutability": "MUTABLE", "EncryptionConfiguration": map[string]any{"EncryptionType": "AES256"},
		"RepositoryPolicy": `{"Statement":[{"Action":["ecr:BatchGetImage","ecr:GetDownloadUrlForLayer","ecr:BatchCheckLayerAvailability","ecr:InitiateLayerUpload","ecr:UploadLayerPart","ecr:CompleteLayerUpload","ecr:PutImage"],"Condition":{"BoolIfExists":{"aws:PrincipalIsAWSService":"false"},"NotIpAddress":{"aws:SourceIp":["198.51.100.0/24"]}},"Effect":"Deny","Principal":"*","Sid":"DenyOutsidePrivateAccess"}],"Version":"2012-10-17"}`}
	if !reflect.DeepEqual(tm, want) {
		t.Errorf("template: %v", tm)
	}
	// ECR's prefixes take a leading digit; a public registry's
	// repositories get no policy.
	if p := object(t, r, "aws", awsRepoTmpl, "9lives"); p["RepositoryPolicy"] != nil {
		t.Errorf("a policy on a registry that was not private: %v", p["RepositoryPolicy"])
	}
	if p := object(t, r, "aws", awsRepoTmpl, "pubimages"); p["RepositoryPolicy"] != nil {
		t.Errorf("a policy on a public registry: %v", p["RepositoryPolicy"])
	}
	if !anyRequirement(r, "<account>.dkr.ecr.eu-west-1.amazonaws.com/shopacr/<repository>") || !anyRequirement(r, "ecr:CreateRepository") {
		t.Errorf("requirements: %v", r.Report.Requirements)
	}
	if l := hasLoss(entry(t, r, acrShop), "tags"); l == nil || l.Widens {
		t.Errorf("tags: %+v", l)
	}
	m := acrMaps()["aws"]
	m.Names = map[string]string{"rg/shopacr": "Shop_ACR"}
	if e := entry(t, runKV(t, acrFixture(), m), acrShop); e.State != Refused || !strings.Contains(e.Reason, "names (rg/shopacr)") {
		t.Errorf("a prefix ECR does not take: %s %q", e.State, e.Reason)
	}
	m.Names = map[string]string{"rg/shopacr": "teams/shop"}
	object(t, runKV(t, acrFixture(), m), "aws", awsRepoTmpl, "teams/shop")
}

func TestRegistryOnGCP(t *testing.T) {
	r := runKV(t, acrFixture(), acrMaps()["gcp"])
	repo := object(t, r, "gcp", gcpRepo, gcpProject+"/locations/europe-west1/repositories/shopacr")
	want := map[string]any{"name": gcpProject + "/locations/europe-west1/repositories/shopacr", "format": "DOCKER", "mode": "STANDARD_REPOSITORY",
		"description": "From Azure Container Registry rg/shopacr", "labels": map[string]any{"team": "platform"}}
	if !reflect.DeepEqual(repo, want) {
		t.Errorf("repository: %v", repo)
	}
	if l := hasLoss(entry(t, r, acrShop), "tags.Cost Center"); l == nil || l.Widens {
		t.Errorf("a tag no label holds: %+v", entry(t, r, acrShop).Losses)
	}
	if e := entry(t, r, acrNine); e.State != Refused || !strings.Contains(e.Reason, "names (rg/9lives)") {
		t.Errorf("9lives: %s %q", e.State, e.Reason)
	}
	if !anyRequirement(r, "europe-west1-docker.pkg.dev/<project>/shopacr/<repository>") {
		t.Errorf("requirements: %v", r.Report.Requirements)
	}
	m := acrMaps()["gcp"]
	m.Region = ""
	if e := entry(t, runKV(t, acrFixture(), m), acrShop); e.State != Refused || !strings.Contains(e.Reason, "region") {
		t.Errorf("no region: %s %q", e.State, e.Reason)
	}
}

// What made the registry more closed than the target is named as
// widening; the rest is a loss, or narrower.
func TestRegistryLosses(t *testing.T) {
	for name, m := range acrMaps() {
		r := runKV(t, acrFixture(), m)
		shop := entry(t, r, acrShop)
		var widens []string
		for _, l := range shop.Losses {
			if l.Widens {
				widens = append(widens, l.Field)
			}
		}
		// The firewall is closed on ECR by the repositories' policy; on
		// Artifact Registry nothing closes it.
		w := []string{"properties.networkRuleSet", "properties.encryption", "properties.policies.quarantinePolicy.status"}
		if name == "aws" {
			w = w[1:]
		}
		if !reflect.DeepEqual(widens, w) {
			t.Errorf("%s: shopacr widens %v, want %v", name, widens, w)
		}
		for _, f := range []string{"sku.name", "identity", "properties.adminUserEnabled", "properties.policies.trustPolicy.status",
			"properties.policies.retentionPolicy.status", "properties.policies.exportPolicy.status", "properties.dataEndpointEnabled",
			"properties.zoneRedundancy", "replications/northeurope: location"} {
			if l := hasLoss(shop, f); l == nil || l.Widens {
				t.Errorf("%s: %s: %+v", name, f, l)
			}
		}
		if l := hasLoss(shop, "properties.policies.retentionPolicy.status"); l == nil || !strings.Contains(l.Why, "14 days") {
			t.Errorf("%s: retention: %+v", name, l)
		}
		for _, f := range []string{"properties.policies.azureADAuthenticationAsArmPolicy.status", "properties.roleAssignmentMode"} {
			if l := hasLoss(shop, f); l != nil {
				t.Errorf("%s: a default is a loss: %+v", name, l)
			}
		}
		pub := entry(t, r, acrPub)
		if l := hasLoss(pub, "properties.anonymousPullEnabled"); l == nil || l.Widens {
			t.Errorf("%s: anonymous pull: %+v", name, pub.Losses)
		}
		if l := hasLoss(pub, "properties.policies.exportPolicy.status"); l != nil {
			t.Errorf("%s: export enabled is a loss: %+v", name, l)
		}
		for _, l := range pub.Losses {
			if l.Widens {
				t.Errorf("%s: pubimages widens: %+v", name, l)
			}
		}
		// Public pulls are not written: everything the target holds is
		// private.
		for _, o := range r.Snapshots[m.To].Objects {
			if s := canonJSON(o.Body); strings.Contains(s, "allUsers") || strings.Contains(s, `\"Effect\":\"Allow\"`) {
				t.Errorf("%s: %s is public: %s", name, o.Key(), s)
			}
		}
		if !anyRequirement(r, "rg/pubimages let anyone pull") || !anyRequirement(r, "rg/shopacr had its admin user on") || !anyRequirement(r, "Kubernetes image references are not rewritten") {
			t.Errorf("%s: requirements: %v", name, r.Report.Requirements)
		}
	}
	// A registry reachable from private endpoints only is private too.
	s := acrFixture()
	s.Objects[2].Body["spec"].(map[string]any)["properties"].(map[string]any)["publicNetworkAccess"] = "Disabled"
	for name, m := range acrMaps() {
		if l := hasLoss(entry(t, runKV(t, s, m), acrPub), "properties.networkRuleSet"); l == nil || !l.Widens || !strings.Contains(l.Why, "private endpoints only") {
			t.Errorf("%s: public access disabled: %+v", name, l)
		}
	}
	// The non-default identity settings are named.
	sh := s.Objects[0].Body["spec"].(map[string]any)["properties"].(map[string]any)
	sh["roleAssignmentMode"] = "AbacRepositoryPermissions"
	sh["policies"].(map[string]any)["azureADAuthenticationAsArmPolicy"] = map[string]any{"status": "disabled"}
	e := entry(t, runKV(t, s, acrMaps()["aws"]), acrShop)
	for _, f := range []string{"properties.policies.azureADAuthenticationAsArmPolicy.status", "properties.roleAssignmentMode"} {
		if l := hasLoss(e, f); l == nil || l.Widens {
			t.Errorf("%s: %+v", f, l)
		}
	}
}

func TestRegistryRefused(t *testing.T) {
	for name, m := range acrMaps() {
		r := runKV(t, acrFixture(), m)
		for src, want := range map[string]struct {
			state State
			why   string
		}{
			"Microsoft.ContainerRegistry/registries/scopeMaps rg/shopacr/pull-only":             {Refused, "identity is not translated"},
			"Microsoft.ContainerRegistry/registries/tokens rg/shopacr/ci":                       {Refused, "identity is not translated"},
			"Microsoft.ContainerRegistry/registries/credentialSets rg/shopacr/hub":              {Refused, "identity is not translated"},
			"Microsoft.ContainerRegistry/registries/connectedRegistries rg/shopacr/edge":        {Refused, "on premises"},
			"Microsoft.ContainerRegistry/registries/tasks rg/shopacr/build":                     {Refused, "ACR Tasks"},
			"Microsoft.ContainerRegistry/registries/replications rg/gone/eastus":                {Refused, "not in the snapshot"},
			"Microsoft.ContainerRegistry/registries/webhooks rg/shopacr/on-push":                {NotLooked, "EventBridge"},
			"Microsoft.ContainerRegistry/registries/cacheRules rg/shopacr/dockerhub":            {NotLooked, "pull-through"},
			"Microsoft.ContainerRegistry/registries/privateEndpointConnections rg/shopacr/pe-1": {NotLooked, "private endpoint"},
			"Microsoft.ContainerRegistry/registries/replications rg/shopacr/northeurope":        {Mapped, "read with its registry"},
		} {
			if e := entry(t, r, src); e.State != want.state || !strings.Contains(e.Reason, want.why) {
				t.Errorf("%s: %s: %s %q", name, src, e.State, e.Reason)
			}
		}
	}
	none := Map{To: "aws", Region: "eu-west-1"}
	r := runKV(t, acrFixture(), none)
	if e := entry(t, r, acrShop); e.State != Refused || !strings.Contains(e.Reason, "destinations.registry") {
		t.Errorf("no destination: %s %q", e.State, e.Reason)
	}
	if len(r.Snapshots) != 0 {
		t.Errorf("no destination wrote %d snapshots", len(r.Snapshots))
	}
	bad := map[string]Map{}
	m := acrMaps()["aws"]
	m.Destinations.Registry = "artifact-registry"
	bad["artifact-registry on aws"] = m
	m = acrMaps()["gcp"]
	m.Destinations.Registry = "ecr"
	bad["ecr on gcp"] = m
	m = acrMaps()["gcp"]
	m.Destinations.Registry = "gcr"
	bad["an unknown destination"] = m
	for name, m := range bad {
		if _, err := Translate(acrFixture(), m, targets(t)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if !acrMaps()["aws"].NeedsAWS() || acrMaps()["aws"].NeedsGCP() || !acrMaps()["gcp"].NeedsGCP() || acrMaps()["gcp"].NeedsAWS() {
		t.Error("registries do not load their target's definitions")
	}
}

func TestRegistryRestore(t *testing.T) {
	tg := targets(t)
	s := runKV(t, acrFixture(), acrMaps()["aws"]).Snapshots["aws"]
	f := awscc.NewWorld(tg.AWS).Account("111111111111", "eu-west-1")
	for _, res := range awscc.Restore(context.Background(), f, tg.AWS, s, awscc.RestoreOptions{}, awscc.Tuning{}) {
		if !res.OK {
			t.Errorf("aws %s: %s", res.Key, res.Detail)
		}
	}
	if c := f.Count(); c[awsRepoTmpl] != 3 {
		t.Errorf("aws created %v", c)
	}
	for _, res := range awscc.Restore(context.Background(), f, tg.AWS, s, awscc.RestoreOptions{}, awscc.Tuning{}) {
		if !res.OK || res.Detail != "already present and identical" {
			t.Errorf("aws again: %s: %v %s", res.Key, res.OK, res.Detail)
		}
	}
	gs := runKV(t, acrFixture(), acrMaps()["gcp"]).Snapshots["gcp"]
	gf := gcp.NewWorld(tg.GCP).Project("target-project", "123456789")
	for _, res := range gcp.Restore(context.Background(), gf, tg.GCP, gs, gcp.RestoreOptions{}) {
		if !res.OK {
			t.Errorf("gcp %s: %s", res.Key, res.Detail)
		}
	}
	got, err := gf.Call(context.Background(), "GET", "https://artifactregistry.googleapis.com/v1/projects/target-project/locations/europe-west1/repositories/shopacr", nil)
	if err != nil || got["format"] != "DOCKER" {
		t.Errorf("shopacr: %v %v", got, err)
	}
	for _, res := range gcp.Restore(context.Background(), gf, tg.GCP, gs, gcp.RestoreOptions{}) {
		if !res.OK || res.Detail != "already present and identical" {
			t.Errorf("gcp again: %s: %v %s", res.Key, res.OK, res.Detail)
		}
	}
}
