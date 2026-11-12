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
	s := snapshot.Snapshot{Platform: "kubernetes", Skips: []snapshot.Skip{
		{Resource: "deployments", Namespace: "ingress", Name: "proxy", Reason: helm("ingress", "proxy")},
		{Resource: "services", Namespace: "ingress", Name: "proxy", Reason: helm("ingress", "proxy")},
		{Resource: "deployments", Namespace: "vault", Name: "connect", Reason: helm("vault", "connect")},
		{Resource: "pods", Namespace: "shop", Name: "web-1", Reason: ownedReason("ReplicaSet", "web")},
		{Resource: "configmaps", Namespace: "kube-system", Name: "x", Reason: "in system namespace kube-system"},
	}, Objects: []snapshot.Object{
		planObject("apiextensions.k8s.io/v1", "CustomResourceDefinition", "", "widgets.example.com", map[string]any{"spec": map[string]any{"group": "example.com"}}),
		planObject("example.com/v1", "Widget", "shop", "w", nil), // its definition is in the snapshot
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
			"routes": []any{map[string]any{"match": "Host(`shop.example.com`, `www.example.com`) && PathPrefix(`/api`)"}},
			"tls":    map[string]any{"secretName": "wild"},
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
		Sources: []PlanSource{{Kind: "Flux HelmRelease", Name: "ingress/proxy", Objects: 2}, {Kind: "Flux HelmRelease", Name: "vault/connect", Objects: 1}},
		Operators: []PlanOperator{
			{Group: "external-secrets.io", Objects: map[string]int{"ExternalSecret": 2}},
			{Group: "onepassword.com", Objects: map[string]int{"OnePasswordItem": 2}},
			{Group: "traefik.io", Objects: map[string]int{"IngressRoute": 1}},
		},
		ByHand: []PlanSecret{
			{Namespace: "other", Name: "token", Keys: []string{"k"}, UsedBy: []string{}},
			{Namespace: "shop", Name: "files", Keys: []string{"f"}, UsedBy: []string{"Deployment/web"}},
			{Namespace: "shop", Name: "pull", Keys: []string{".dockerconfigjson"}, UsedBy: []string{"Deployment/web"}},
			{Namespace: "shop", Name: "token", Keys: []string{"a", "k"}, UsedBy: []string{"Deployment/web"}},
		},
		Reissued: []string{"certs/ca", "shop/wild"},
		FromStore: []PlanStoreItem{
			{Store: "1Password", Item: "vaults/apps/items/base", Secrets: []string{"shop/db", "shop/mail"}},
			{Store: "ClusterSecretStore kv", Item: "api-key", Secrets: []string{"shop/api"}},
			{Store: "SecretStore local", Item: "bundle", Secrets: []string{"shop/plain"}},
		},
		Hosts: []string{"old.example.com", "shop.example.com", "www.example.com"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("plan:\n got %+v\nwant %+v", got, want)
	}

	// Where Flux reads from is in the snapshot only when a repository object is.
	if got.OriginRecorded {
		t.Error("no repository object, and the origin is said to be recorded")
	}
	s.Objects = append(s.Objects, planObject("source.toolkit.fluxcd.io/v1", "GitRepository", "flux-system", "flux-system", nil))
	if !RebuildPlan(s).OriginRecorded {
		t.Error("a GitRepository is in the snapshot, and the origin is said to be missing")
	}
}

// SourceOf reads back every reason renderedBy writes: a reason reworded
// there and not here would empty the plan's first step without a word.
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
