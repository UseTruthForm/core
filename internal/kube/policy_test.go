package kube

import (
	"context"
	"strings"
	"testing"

	"github.com/stackdna/core/internal/snapshot"
)

func k8sObj(kind, ns, name string, md map[string]any, extra map[string]any) map[string]any {
	m := map[string]any{"name": name}
	if ns != "" {
		m["namespace"] = ns
	}
	for k, v := range md {
		m[k] = v
	}
	o := map[string]any{"apiVersion": "v1", "kind": kind, "metadata": m}
	for k, v := range extra {
		o[k] = v
	}
	return o
}

func TestSkipReason(t *testing.T) {
	owned := map[string]any{"ownerReferences": []any{map[string]any{"kind": "ReplicaSet", "name": "api-7d9", "controller": true}}}
	platform := map[string]any{"managedFields": []any{map[string]any{"manager": "kube-apiserver"}}}
	userAndPlatform := map[string]any{"managedFields": []any{map[string]any{"manager": "kube-apiserver"}, map[string]any{"manager": "kubectl-client-side-apply"}}}
	cases := []struct {
		name, group, resource string
		obj                   map[string]any
		want                  string // substring of the reason; "" means captured
	}{
		{"user configmap is captured", "", "configmaps", k8sObj("ConfigMap", "shop", "cfg", nil, nil), ""},
		{"pod owned by a replicaset", "", "pods", k8sObj("Pod", "shop", "api-7d9-x", owned, nil), "owned by ReplicaSet/api-7d9"},
		{"anything in kube-system", "", "configmaps", k8sObj("ConfigMap", "kube-system", "coredns", nil, nil), "system namespace"},
		{"default namespace object", "", "namespaces", k8sObj("Namespace", "", "default", nil, nil), "created by the cluster"},
		{"default service account", "", "serviceaccounts", k8sObj("ServiceAccount", "shop", "default", nil, nil), "every namespace"},
		{"root CA configmap", "", "configmaps", k8sObj("ConfigMap", "shop", "kube-root-ca.crt", nil, nil), "every namespace"},
		{"service account token", "", "secrets", k8sObj("Secret", "shop", "tok", nil, map[string]any{"type": "kubernetes.io/service-account-token"}), "token"},
		{"bootstrap RBAC", "rbac.authorization.k8s.io", "clusterroles", k8sObj("ClusterRole", "", "admin", map[string]any{"labels": map[string]any{"kubernetes.io/bootstrapping": "rbac-defaults"}}, nil), "default RBAC"},
		{"written only by the platform", "", "configmaps", k8sObj("ConfigMap", "shop", "x", platform, nil), "only by the platform"},
		// Regression guard: one user-side manager means a person changed it,
		// so it must be captured even though the platform also wrote fields.
		{"platform plus a user edit is captured", "", "configmaps", k8sObj("ConfigMap", "shop", "x", userAndPlatform, nil), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Policy{}.skipReason(c.group, c.resource, c.obj)
			if c.want == "" && got != "" {
				t.Fatalf("expected capture, got skip: %s", got)
			}
			if c.want != "" && !strings.Contains(got, c.want) {
				t.Fatalf("reason %q does not contain %q", got, c.want)
			}
		})
	}
}

func TestIncludeSystemStillSkipsOwnedObjects(t *testing.T) {
	owned := map[string]any{"ownerReferences": []any{map[string]any{"kind": "ReplicaSet", "name": "rs", "controller": true}}}
	p := Policy{IncludeSystem: true}
	if r := p.skipReason("", "configmaps", k8sObj("ConfigMap", "kube-system", "coredns", nil, nil)); r != "" {
		t.Fatalf("include-system must capture kube-system objects, got skip: %s", r)
	}
	if r := p.skipReason("", "pods", k8sObj("Pod", "kube-system", "p", owned, nil)); r == "" {
		t.Fatal("owned pods are recreated by their controller and must stay skipped")
	}
}

func TestNormalize(t *testing.T) {
	t.Run("service keeps headless, drops allocated IP", func(t *testing.T) {
		svc := k8sObj("Service", "shop", "api", map[string]any{"uid": "u", "resourceVersion": "9"}, map[string]any{
			"spec": map[string]any{"clusterIP": "10.96.4.2", "clusterIPs": []any{"10.96.4.2"}, "ports": []any{}}, "status": map[string]any{},
		})
		normalize("", "services", svc)
		spec := svc["spec"].(map[string]any)
		md := svc["metadata"].(map[string]any)
		if _, ok := spec["clusterIP"]; ok || md["uid"] != nil || svc["status"] != nil {
			t.Fatalf("allocated or server fields kept: %+v", svc)
		}
		headless := k8sObj("Service", "shop", "db", nil, map[string]any{"spec": map[string]any{"clusterIP": "None"}})
		normalize("", "services", headless)
		if headless["spec"].(map[string]any)["clusterIP"] != "None" {
			t.Fatal("headless clusterIP None is configuration and must be kept")
		}
	})
	t.Run("namespace drops server label and finalizer spec", func(t *testing.T) {
		ns := k8sObj("Namespace", "", "shop", map[string]any{"labels": map[string]any{"kubernetes.io/metadata.name": "shop", "team": "platform"}}, map[string]any{"spec": map[string]any{"finalizers": []any{"kubernetes"}}})
		normalize("", "namespaces", ns)
		l := ns["metadata"].(map[string]any)["labels"].(map[string]any)
		if _, ok := l["kubernetes.io/metadata.name"]; ok || l["team"] != "platform" || ns["spec"] != nil {
			t.Fatalf("namespace not normalised correctly: %+v", ns)
		}
	})
}

// Regression for the central safety rule: a secret value must never reach
// the snapshot, in data or stringData.
func TestSecretValuesAreWithheld(t *testing.T) {
	s := k8sObj("Secret", "shop", "db", nil, map[string]any{
		"type": "Opaque", "data": map[string]any{"password": "c2VjcmV0"}, "stringData": map[string]any{"user": "shop"},
	})
	keys := normalize("", "secrets", s)
	if strings.Join(keys, ",") != "password,user" {
		t.Fatalf("withheld keys = %v", keys)
	}
	if _, ok := s["stringData"]; ok {
		t.Fatal("stringData survived")
	}
	for k, v := range s["data"].(map[string]any) {
		if v != "" {
			t.Fatalf("value for %s survived: %v", k, v)
		}
	}
	ann := s["metadata"].(map[string]any)["annotations"].(map[string]any)
	if ann[WithheldAnnotation] != "password,user" {
		t.Fatalf("annotation = %v", ann[WithheldAnnotation])
	}
}

// Regression: restoring a withheld secret with no value source must refuse,
// never create the secret with empty values (which would look restored and
// break the app at runtime).
func TestRestoreRefusesWithheldSecretWithoutSource(t *testing.T) {
	s := k8sObj("Secret", "shop", "db", nil, map[string]any{"data": map[string]any{"password": ""}})
	s["metadata"].(map[string]any)["annotations"] = map[string]any{WithheldAnnotation: "password"}
	res := applyOne(context.Background(), nil, nil, snapshot.Object{Body: s}, RestoreOptions{})
	if res.OK || !strings.Contains(res.Detail, "withheld") {
		t.Fatalf("want a refusal naming the withheld values, got %+v", res)
	}
}

func TestBaselineSkipsOnlyIdenticalObjects(t *testing.T) {
	sc := k8sObj("StorageClass", "", "standard", nil, map[string]any{"provisioner": "rancher.io/local-path"})
	sc["apiVersion"] = "storage.k8s.io/v1"
	base := snapshot.Snapshot{Objects: []snapshot.Object{{Body: sc}}}
	p := Policy{}.WithBaseline(base, "sha256:test")
	same := k8sObj("StorageClass", "", "standard", nil, map[string]any{"provisioner": "rancher.io/local-path"})
	same["apiVersion"] = "storage.k8s.io/v1"
	if !p.matchesBaseline(same) {
		t.Fatal("an unchanged distribution object must match the baseline")
	}
	changed := k8sObj("StorageClass", "", "standard", nil, map[string]any{"provisioner": "example.com/other"})
	changed["apiVersion"] = "storage.k8s.io/v1"
	if p.matchesBaseline(changed) {
		t.Fatal("a distribution object someone changed must be captured, not skipped")
	}
	if !strings.Contains(p.Name(), "baseline:sha256:test") {
		t.Fatalf("policy name must record the baseline, got %s", p.Name())
	}
}

// Regression from the tilt platform cluster: 335 of 632 captured objects were
// rendered by Flux HelmReleases. Captured alongside their HelmRelease, a
// restore makes two owners fight over every field.
func TestRenderedObjectsAreSkipped(t *testing.T) {
	lbl := func(kv ...string) map[string]any {
		m := map[string]any{}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return map[string]any{"labels": m}
	}
	cases := []struct {
		name string
		md   map[string]any
		want string
	}{
		{"flux helmrelease", lbl("helm.toolkit.fluxcd.io/name", "cert-manager", "helm.toolkit.fluxcd.io/namespace", "cert-manager"), "Flux HelmRelease cert-manager/cert-manager"},
		{"flux kustomization", lbl("kustomize.toolkit.fluxcd.io/name", "apps", "kustomize.toolkit.fluxcd.io/namespace", "flux-system"), "Flux Kustomization flux-system/apps"},
		{"argo cd", lbl("argocd.argoproj.io/instance", "shop"), "Argo CD application shop"},
		{"crossplane", lbl("crossplane.io/composite", "db-x7k"), "Crossplane composite db-x7k"},
		{"plain helm cli install is kept", lbl("app.kubernetes.io/managed-by", "Helm"), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Policy{}.skipReason("apps", "deployments", k8sObj("Deployment", "shop", "api", c.md, nil))
			if c.want == "" && got != "" {
				t.Fatalf("expected capture, got skip: %s", got)
			}
			if c.want != "" && !strings.Contains(got, c.want) {
				t.Fatalf("reason %q does not contain %q", got, c.want)
			}
			if c.want != "" {
				if r := (Policy{CaptureRendered: true}).skipReason("apps", "deployments", k8sObj("Deployment", "shop", "api", c.md, nil)); r != "" {
					t.Fatalf("--capture-rendered must keep it, got skip: %s", r)
				}
			}
		})
	}
}

// A restored claim with an empty volume looks exactly like one with its data,
// so the skip reason for a dynamic PV must say the data is not captured.
func TestDynamicPVSaysDataIsNotCaptured(t *testing.T) {
	pv := k8sObj("PersistentVolume", "", "pvc-123", map[string]any{"annotations": map[string]any{"pv.kubernetes.io/provisioned-by": "rancher.io/local-path"}},
		map[string]any{"spec": map[string]any{"claimRef": map[string]any{"namespace": "shop", "name": "shop-data"}}})
	got := Policy{}.skipReason("", "persistentvolumes", pv)
	if !strings.Contains(got, "claim shop/shop-data") || !strings.Contains(got, "DATA is not captured") {
		t.Fatalf("reason %q", got)
	}
}

func TestHelmReleaseSecretIsSkipped(t *testing.T) {
	s := k8sObj("Secret", "monitoring", "sh.helm.release.v1.prometheus.v3", nil, map[string]any{"type": "helm.sh/release.v1"})
	if got := (Policy{}).skipReason("", "secrets", s); !strings.Contains(got, "Helm release history") {
		t.Fatalf("reason %q", got)
	}
}
