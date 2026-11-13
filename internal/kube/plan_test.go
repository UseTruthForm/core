package kube

import (
	"reflect"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

func planObject(apiVersion, kind, ns, name string, rest map[string]any) snapshot.Object {
	body := map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": map[string]any{"name": name, "namespace": ns}}
	for k, v := range rest {
		if k == "labels" || k == "annotations" {
			body["metadata"].(map[string]any)[k] = v
			continue
		}
		body[k] = v
	}
	return snapshot.Object{Body: body}
}

// The plan is what a restore of the snapshot cannot do by itself: the
// sources the capture left things to, the types with no definition, the
// Secrets nothing supplies, the store items, the hosts.
func TestRebuildPlan(t *testing.T) {
	helm := func(ns, name string) string {
		return renderedBy(map[string]any{"labels": map[string]any{"helm.toolkit.fluxcd.io/namespace": ns, "helm.toolkit.fluxcd.io/name": name}})
	}
	kustomized := func(ns, name string) string {
		return renderedBy(map[string]any{"labels": map[string]any{"kustomize.toolkit.fluxcd.io/namespace": ns, "kustomize.toolkit.fluxcd.io/name": name}})
	}
	argo := func(app string) string {
		return renderedBy(map[string]any{"labels": map[string]any{"argocd.argoproj.io/instance": app}})
	}
	s := snapshot.Snapshot{Platform: "kubernetes", Skips: []snapshot.Skip{
		{Resource: "deployments", Namespace: "ingress", Name: "proxy", Reason: helm("ingress", "proxy")},
		{Resource: "services", Namespace: "ingress", Name: "proxy", Reason: helm("ingress", "proxy")},
		{Resource: "deployments", Namespace: "vault", Name: "connect", Reason: helm("vault", "connect")},
		{Resource: "deployments", Namespace: "shop", Name: "held", Reason: helm("shop", "held")}, // its HelmRelease is in the snapshot
		// A chain: the snapshot holds the Kustomization root, which applies the
		// HelmRelease apps/web, which renders a Deployment. Both follow.
		{Resource: "helm.toolkit.fluxcd.io/v2/helmreleases", Namespace: "apps", Name: "web", Reason: kustomized("flux-system", "root")},
		{Resource: "deployments", Namespace: "apps", Name: "web", Reason: helm("apps", "web")},
		// A chain that ends outside the snapshot does not.
		{Resource: "kustomize.toolkit.fluxcd.io/v1/kustomizations", Namespace: "flux-system", Name: "tenant", Reason: kustomized("flux-system", "gone")},
		{Resource: "configmaps", Namespace: "tenant", Name: "c", Reason: kustomized("flux-system", "tenant")},
		{Resource: "deployments", Namespace: "kube-system", Name: "addon", Reason: helm("kube-system", "addon")}, // the platform's, perhaps
		{Resource: "clusterroles", Name: "addon", Reason: helm("kube-system", "addon")},                          // no namespace: says neither
		{Resource: "clusterroles", Name: "wide", Reason: helm("ops", "wide")},                                    // only that: not system-only
		// Argo CD: the root application is in the snapshot and applies shop; another API's
		// Application of the name of an Argo CD one is neither that one nor its skip.
		{Resource: "argoproj.io/v1alpha1/applications", Namespace: "argocd", Name: "shop", Reason: argo("team_root")},
		{Resource: "deployments", Namespace: "shop", Name: "argo-web", Reason: argo("shop")},
		{Resource: "app.k8s.io/v1beta1/applications", Namespace: "pay", Name: "pay", Reason: kustomized("flux-system", "root")},
		{Resource: "deployments", Namespace: "pay", Name: "pay", Reason: argo("pay")},
		{Resource: "deployments", Namespace: "bill", Name: "bill", Reason: argo("bill")},
		{Resource: "pods", Namespace: "shop", Name: "web-1", Reason: ownedReason("ReplicaSet", "web")},
		{Resource: "configmaps", Namespace: "kube-system", Name: "x", Reason: "in system namespace kube-system"},
	}, Objects: []snapshot.Object{
		planObject("apiextensions.k8s.io/v1", "CustomResourceDefinition", "", "widgets.example.com", map[string]any{"spec": map[string]any{"group": "example.com", "names": map[string]any{"kind": "Widget"}}}),
		planObject("example.com/v1", "Widget", "shop", "w", nil), // its definition is in the snapshot
		planObject("example.com/v1", "Gadget", "shop", "g", nil), // the group's other kind is not
		planObject("gateway.networking.k8s.io/v1", "Gateway", "shop", "gw", map[string]any{"spec": map[string]any{"listeners": []any{map[string]any{"hostname": "GW.example.com"}}}}),
		planObject("helm.toolkit.fluxcd.io/v2", "HelmRelease", "shop", "held", nil),
		planObject("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "flux-system", "root", nil),
		planObject("argoproj.io/v1alpha1", "Application", "team", "root", nil),
		planObject("app.k8s.io/v1beta1", "Application", "bill", "bill", nil),
		// Three items make one Secret; Merge adds to one that has to be there; a search and a generator name no key.
		planObject("external-secrets.io/v1", "ExternalSecret", "shop", "multi", map[string]any{"spec": map[string]any{
			"secretStoreRef": map[string]any{"kind": "ClusterSecretStore", "name": "kv"},
			"data": []any{
				map[string]any{"remoteRef": map[string]any{"key": "api-key"}},
				map[string]any{"remoteRef": map[string]any{"key": "k2"}},
			},
			"dataFrom": []any{map[string]any{"find": map[string]any{"name": map[string]any{"regexp": "x"}}}},
		}}),
		planObject("external-secrets.io/v1", "ExternalSecret", "shop", "adds", map[string]any{"spec": map[string]any{
			"secretStoreRef": map[string]any{"kind": "ClusterSecretStore", "name": "kv"},
			"target":         map[string]any{"name": "merged", "creationPolicy": "Merge"},
			"data":           []any{map[string]any{"remoteRef": map[string]any{"key": "k2"}}},
		}}),
		planObject("external-secrets.io/v1", "ExternalSecret", "shop", "gen", map[string]any{"spec": map[string]any{
			"dataFrom": []any{map[string]any{"sourceRef": map[string]any{"generatorRef": map[string]any{"kind": "Password", "name": "pw"}}}},
		}}),
		planObject("external-secrets.io/v1", "ClusterExternalSecret", "", "everywhere", map[string]any{"spec": map[string]any{
			"externalSecretSpec": map[string]any{"secretStoreRef": map[string]any{"name": "local"}, "data": []any{map[string]any{"remoteRef": map[string]any{"key": "shared"}}}},
		}}),
		// References a walk for secretKeyRef alone misses.
		planObject("cert-manager.io/v1", "Issuer", "shop", "acme", map[string]any{"spec": map[string]any{"acme": map[string]any{"solvers": []any{map[string]any{
			"dns01": map[string]any{"cloudflare": map[string]any{"apiTokenSecretRef": map[string]any{"name": "dns", "key": "t"}}},
		}}}}}),
		planObject("cert-manager.io/v1", "ClusterIssuer", "", "global", map[string]any{"spec": map[string]any{"ca": map[string]any{"secretRef": map[string]any{"name": "dns"}}}}), // no namespace: not resolved
		planObject("external-secrets.io/v1", "ClusterSecretStore", "", "kv", map[string]any{"spec": map[string]any{"provider": map[string]any{"azurekv": map[string]any{
			"authSecretRef": map[string]any{"clientId": map[string]any{"name": "sp", "namespace": "eso"}},
		}}}}),
		planObject("keda.sh/v1alpha1", "TriggerAuthentication", "shop", "ta", map[string]any{"spec": map[string]any{"secretTargetRef": []any{map[string]any{"parameter": "connection", "name": "bus", "key": "c"}}}}),
		planObject("v1", "ServiceAccount", "shop", "runner", map[string]any{"secrets": []any{map[string]any{"name": "bus"}}}),
		planObject("v1", "Pod", "shop", "p", map[string]any{"spec": map[string]any{"volumes": []any{map[string]any{"projected": map[string]any{"sources": []any{map[string]any{"secret": map[string]any{"name": "dns"}}}}}}}}),
		planObject("onepassword.com/v1", "OnePasswordItem", "shop", "db", map[string]any{"spec": map[string]any{"itemPath": "vaults/apps/items/base"}}),
		planObject("onepassword.com/v1", "OnePasswordItem", "shop", "mail", map[string]any{"spec": map[string]any{"itemPath": "vaults/apps/items/base"}}),
		planObject("external-secrets.io/v1", "ExternalSecret", "shop", "es", map[string]any{"spec": map[string]any{
			"secretStoreRef": map[string]any{"kind": "ClusterSecretStore", "name": "kv"},
			"target":         map[string]any{"name": "api"},
			"data":           []any{map[string]any{"secretKey": "k", "remoteRef": map[string]any{"key": "api-key"}}},
		}}),
		// No target and no store kind: the Secret has its name, the store is a SecretStore.
		planObject("external-secrets.io/v1", "ExternalSecret", "shop", "plain", map[string]any{"spec": map[string]any{
			"secretStoreRef": map[string]any{"name": "local"},
			"dataFrom":       []any{map[string]any{"extract": map[string]any{"key": "bundle"}}},
		}}),
		planObject("traefik.io/v1alpha1", "IngressRoute", "shop", "web", map[string]any{"spec": map[string]any{
			"routes": []any{
				map[string]any{"match": "Host(`shop.example.com`, `www.example.com`) && PathPrefix(`/api`)"},
				map[string]any{"match": "Host(\"Quoted.example.com\") || HostSNI(`*`) || !Host(`not.example.com`) || HostRegexp(`^.+\\.example\\.com$`)"},
			},
			"tls": map[string]any{"secretName": "wild"},
		}}),
		planObject("networking.k8s.io/v1", "Ingress", "shop", "old", map[string]any{"spec": map[string]any{
			"rules": []any{map[string]any{"host": "old.example.com"}},
			"tls":   []any{map[string]any{"hosts": []any{"old.example.com"}, "secretName": "old-tls"}},
		}}),
		planObject("apps/v1", "Deployment", "shop", "web", map[string]any{"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"imagePullSecrets": []any{map[string]any{"name": "pull"}},
			"containers": []any{map[string]any{
				"env":     []any{map[string]any{"name": "K", "valueFrom": map[string]any{"secretKeyRef": map[string]any{"name": "token", "key": "k"}}}},
				"envFrom": []any{map[string]any{"secretRef": map[string]any{"name": "db"}}},
			}},
			"volumes": []any{map[string]any{"name": "v", "secret": map[string]any{"secretName": "files"}}},
		}}}}),
		// Supplied by the store: not for a person to supply.
		planObject("v1", "Secret", "shop", "db", map[string]any{"data": map[string]any{"password": ""}}),
		planObject("v1", "Secret", "shop", "api", map[string]any{"data": map[string]any{"k": ""}}),
		planObject("v1", "Secret", "shop", "plain", map[string]any{"data": map[string]any{"k": ""}}),
		planObject("v1", "Secret", "shop", "multi", nil),
		planObject("v1", "Secret", "shop", "gen", nil),
		planObject("v1", "Secret", "any", "everywhere", nil), // a ClusterExternalSecret's, in whichever namespace
		// Merged into, so it has to be there: by hand, though an item adds to it.
		planObject("v1", "Secret", "shop", "merged", map[string]any{"data": map[string]any{"mine": ""}}),
		planObject("v1", "Secret", "shop", "dns", nil),
		planObject("v1", "Secret", "shop", "bus", nil),
		planObject("v1", "Secret", "eso", "sp", nil),
		planObject("v1", "Secret", "shop", "sp", nil),                                                      // the reference names another namespace's
		planObject("v1", "Secret", "shop", "files", map[string]any{"stringData": map[string]any{"f": ""}}), // used as a volume only
		// Supplied by nothing in the snapshot.
		planObject("v1", "Secret", "shop", "token", map[string]any{"data": map[string]any{"k": "", "a": ""}}),
		planObject("v1", "Secret", "shop", "pull", map[string]any{"type": "kubernetes.io/dockerconfigjson", "data": map[string]any{".dockerconfigjson": ""}}),
		planObject("v1", "Secret", "other", "token", map[string]any{"data": map[string]any{"k": ""}}), // another namespace's: nothing here uses it
		// The cluster's and cert-manager's to make.
		planObject("v1", "Secret", "shop", "sa", map[string]any{"type": "kubernetes.io/service-account-token"}),
		planObject("v1", "Secret", "shop", "wild", map[string]any{"type": "kubernetes.io/tls", "annotations": map[string]any{"cert-manager.io/certificate-name": "wild"}}),
		planObject("v1", "Secret", "certs", "ca", map[string]any{"labels": map[string]any{"app.kubernetes.io/managed-by": "cert-manager"}}),
	}}
	got := RebuildPlan(s)
	want := Plan{
		Sources: []PlanSource{
			{Kind: "Flux HelmRelease", Name: "ingress/proxy", Objects: 2},
			{Kind: "Flux HelmRelease", Name: "kube-system/addon", Objects: 2, SystemOnly: true},
			{Kind: "Argo CD application", Name: "bill", Objects: 1},
			{Kind: "Argo CD application", Name: "pay", Objects: 1},
			{Kind: "Flux HelmRelease", Name: "ops/wide", Objects: 1},
			{Kind: "Flux HelmRelease", Name: "vault/connect", Objects: 1},
			{Kind: "Flux Kustomization", Name: "flux-system/gone", Objects: 1},
			{Kind: "Flux Kustomization", Name: "flux-system/tenant", Objects: 1},
		},
		Follows: []PlanSource{
			{Kind: "Flux Kustomization", Name: "flux-system/root", Objects: 2},
			{Kind: "Argo CD application", Name: "shop", Objects: 1},
			{Kind: "Argo CD application", Name: "team_root", Objects: 1},
			{Kind: "Flux HelmRelease", Name: "apps/web", Objects: 1},
			{Kind: "Flux HelmRelease", Name: "shop/held", Objects: 1},
		},
		Operators: []PlanOperator{
			{Group: "app.k8s.io", Objects: map[string]int{"Application": 1}},
			{Group: "argoproj.io", Objects: map[string]int{"Application": 1}},
			{Group: "cert-manager.io", Objects: map[string]int{"ClusterIssuer": 1, "Issuer": 1}},
			{Group: "example.com", Objects: map[string]int{"Gadget": 1}},
			{Group: "external-secrets.io", Objects: map[string]int{"ClusterExternalSecret": 1, "ClusterSecretStore": 1, "ExternalSecret": 5}},
			{Group: "gateway.networking.k8s.io", Objects: map[string]int{"Gateway": 1}},
			{Group: "helm.toolkit.fluxcd.io", Objects: map[string]int{"HelmRelease": 1}},
			{Group: "keda.sh", Objects: map[string]int{"TriggerAuthentication": 1}},
			{Group: "kustomize.toolkit.fluxcd.io", Objects: map[string]int{"Kustomization": 1}},
			{Group: "onepassword.com", Objects: map[string]int{"OnePasswordItem": 2}},
			{Group: "traefik.io", Objects: map[string]int{"IngressRoute": 1}},
		},
		ByHand: []PlanSecret{
			{Namespace: "eso", Name: "sp", Keys: []string{}, UsedBy: []string{"ClusterSecretStore/kv"}},
			{Namespace: "other", Name: "token", Keys: []string{"k"}, UsedBy: []string{}},
			{Namespace: "shop", Name: "bus", Keys: []string{}, UsedBy: []string{"ServiceAccount/runner", "TriggerAuthentication/ta"}},
			{Namespace: "shop", Name: "dns", Keys: []string{}, UsedBy: []string{"Issuer/acme", "Pod/p"}},
			{Namespace: "shop", Name: "files", Keys: []string{"f"}, UsedBy: []string{"Deployment/web"}},
			{Namespace: "shop", Name: "merged", Keys: []string{"mine"}, UsedBy: []string{}},
			{Namespace: "shop", Name: "pull", Keys: []string{".dockerconfigjson"}, UsedBy: []string{"Deployment/web"}},
			{Namespace: "shop", Name: "sp", Keys: []string{}, UsedBy: []string{}},
			{Namespace: "shop", Name: "token", Keys: []string{"a", "k"}, UsedBy: []string{"Deployment/web"}},
		},
		Reissued: []string{"certs/ca", "shop/wild"},
		FromStore: []PlanStoreItem{
			{Store: "1Password", Item: "vaults/apps/items/base", Secrets: []string{"shop/db", "shop/mail"}},
			{Store: "ClusterSecretStore kv", Item: "api-key", Secrets: []string{"shop/api", "shop/multi"}},
			{Store: "ClusterSecretStore kv", Item: "k2", Secrets: []string{"shop/merged", "shop/multi"}},
			{Store: "ClusterSecretStore kv", Item: "(found by a search of the store)", Secrets: []string{"shop/multi"}},
			{Store: "SecretStore local", Item: "bundle", Secrets: []string{"shop/plain"}},
			{Store: "SecretStore local", Item: "shared", Secrets: []string{"*/everywhere"}},
			{Store: "generator in the cluster", Item: "Password pw", Secrets: []string{"shop/gen"}},
		},
		// shop/multi is made from three items and counts once.
		StoreSecrets: 8,
		Origins:      []string{}, OriginsWithheld: []string{},
		Hosts: []string{"gw.example.com", "old.example.com", "quoted.example.com", "shop.example.com", "www.example.com"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("plan:\n got %+v\nwant %+v", got, want)
	}

	// Where Flux reads from is in the snapshot only when a repository object
	// is; a chart repository is where one chart comes from, not that.
	s.Objects = append(s.Objects,
		planObject("source.toolkit.fluxcd.io/v1", "HelmRepository", "flux-system", "charts", nil),
		planObject("source.toolkit.fluxcd.io/v1", "GitRepository", "flux-system", "flux-system", nil))
	if o := RebuildPlan(s).Origins; !reflect.DeepEqual(o, []string{"GitRepository flux-system/flux-system"}) {
		t.Errorf("origins: %v", o)
	}
}

// SourceOf reads back each reason renderedBy writes today: one reworded
// there and not here would empty the plan's first step without a word. A
// source renderedBy learns later needs its case here too.
func TestSourceOfReadsEveryRenderedBy(t *testing.T) {
	for _, c := range []struct {
		md         map[string]any
		kind, name string
	}{
		{map[string]any{"labels": map[string]any{"helm.toolkit.fluxcd.io/namespace": "a", "helm.toolkit.fluxcd.io/name": "b"}}, "Flux HelmRelease", "a/b"},
		{map[string]any{"labels": map[string]any{"kustomize.toolkit.fluxcd.io/namespace": "a", "kustomize.toolkit.fluxcd.io/name": "b"}}, "Flux Kustomization", "a/b"},
		{map[string]any{"labels": map[string]any{"argocd.argoproj.io/instance": "app"}}, "Argo CD application", "app"},
		{map[string]any{"annotations": map[string]any{"argocd.argoproj.io/tracking-id": "app:apps/Deployment:ns/x"}}, "Argo CD application", "app"},
		{map[string]any{"labels": map[string]any{"crossplane.io/composite": "xr"}}, "Crossplane composite", "xr"},
	} {
		reason := renderedBy(c.md)
		kind, name, ok := SourceOf(reason)
		if !ok || kind != c.kind || name != c.name {
			t.Errorf("SourceOf(%q) = %q, %q, %v; want %q, %q", reason, kind, name, ok, c.kind, c.name)
		}
	}
	if _, _, ok := SourceOf(ownedReason("Deployment", "web")); ok {
		t.Error("an owner is not a source to install")
	}
}

// An Argo CD application outside Argo CD's namespace is named
// namespace_name by what it makes: one the snapshot's root applies
// follows, and is not installed by hand. A bare name that applications in
// two namespaces share is not taken as held.
func TestRebuildPlanArgoApplicationsByNamespace(t *testing.T) {
	argo := func(app string) string {
		return renderedBy(map[string]any{"labels": map[string]any{"argocd.argoproj.io/instance": app}})
	}
	app := func(ns, name string) snapshot.Object {
		return planObject("argoproj.io/v1alpha1", "Application", ns, name, nil)
	}
	p := RebuildPlan(snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{app("argocd", "root")}, Skips: []snapshot.Skip{
		{Resource: "argoproj.io/v1alpha1/applications", Namespace: "team", Name: "web", Reason: argo("root")},
		{Resource: "deployments", Namespace: "shop", Name: "web", Reason: argo("team_web")},
	}})
	if len(p.Sources) != 0 || len(p.Follows) != 2 {
		t.Errorf("a child application outside Argo CD's namespace: by hand %v, follow %v", p.Sources, p.Follows)
	}

	p = RebuildPlan(snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{app("team-a", "web"), app("team-b", "web")}, Skips: []snapshot.Skip{
		{Resource: "deployments", Namespace: "shop", Name: "web", Reason: argo("web")},
		{Resource: "deployments", Namespace: "shop", Name: "api", Reason: argo("team-a_web")},
	}})
	if len(p.Sources) != 1 || p.Sources[0].Name != "web" || len(p.Follows) != 1 || p.Follows[0].Name != "team-a_web" {
		t.Errorf("a bare name two applications share: by hand %v, follow %v", p.Sources, p.Follows)
	}
}

// A repository whose address was withheld is in the snapshot without
// where it reads from, and the plan says which.
func TestRebuildPlanSaysAnOriginsAddressWasWithheld(t *testing.T) {
	repo := func(name, url string) snapshot.Object {
		body := map[string]any{"apiVersion": "source.toolkit.fluxcd.io/v1", "kind": "GitRepository",
			"metadata": map[string]any{"name": name, "namespace": "flux-system"}, "spec": map[string]any{"url": url}}
		normalize("source.toolkit.fluxcd.io", "gitrepositories", body)
		return snapshot.Object{Body: body}
	}
	p := RebuildPlan(snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{
		repo("fleet", "https://ghp_tok3ntok3ntok3ntok3n@example.com/o/fleet"), repo("open", "https://example.com/o/open"),
	}})
	if len(p.Origins) != 2 || len(p.OriginsWithheld) != 1 || p.OriginsWithheld[0] != "GitRepository flux-system/fleet" {
		t.Errorf("origins %v, withheld %v", p.Origins, p.OriginsWithheld)
	}
}
