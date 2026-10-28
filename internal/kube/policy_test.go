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

// Regression from kind-tiltdev: three Istio leader-election ConfigMaps changed
// between two captures a minute apart, so every scheduled capture would have
// reported drift that nobody made.
func TestLeaderElectionRecordsAreSkipped(t *testing.T) {
	cm := k8sObj("ConfigMap", "istio-system", "istio-leader", map[string]any{"annotations": map[string]any{
		"control-plane.alpha.kubernetes.io/leader": `{"holderIdentity":"istiod-1","renewTime":"2026-10-21T05:00:00Z"}`,
	}}, nil)
	if got := (Policy{}).skipReason("", "configmaps", cm); !strings.Contains(got, "leader-election") {
		t.Fatalf("reason %q", got)
	}
}

// Regression from the Windows API-server drill: managers are named after the
// executable ("kube-apiserver.exe"), so the platform rule silently matched
// nothing and an auto-registered APIService plus a Service's IPAddress record
// were captured as if someone had made them.
func TestPlatformManagerOnWindowsAndDerivedAPIObjects(t *testing.T) {
	winPlatform := map[string]any{"managedFields": []any{map[string]any{"manager": "kube-apiserver.exe"}}}
	if got := (Policy{}).skipReason("", "configmaps", k8sObj("ConfigMap", "shop", "x", winPlatform, nil)); !strings.Contains(got, "only by the platform") {
		t.Fatalf("kube-apiserver.exe not recognised as the platform: %q", got)
	}
	auto := map[string]any{"labels": map[string]any{"kube-aggregator.kubernetes.io/automanaged": "true"}}
	if got := (Policy{}).skipReason("apiregistration.k8s.io", "apiservices", k8sObj("APIService", "", "v1.example.stackdna.org", auto, nil)); !strings.Contains(got, "registered automatically") {
		t.Fatalf("auto-registered APIService not skipped: %q", got)
	}
	if got := (Policy{}).typeExcluded("networking.k8s.io", "ipaddresses"); got == "" {
		t.Fatal("IPAddress records must be excluded as derived from Services")
	}
}

// A credential written as a literal env value is withheld like a Secret's
// value, wherever the pod template is; a name that only mentions one (an
// ID, a URL, a setting), a secretKeyRef and a reference to another
// variable are left as they are.
func TestCredentialEnvIsWithheld(t *testing.T) {
	env := func(pairs ...string) []any {
		var out []any
		for i := 0; i+1 < len(pairs); i += 2 {
			out = append(out, map[string]any{"name": pairs[i], "value": pairs[i+1]})
		}
		return out
	}
	dep := k8sObj("Deployment", "shop", "api", nil, map[string]any{"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
		"containers": []any{map[string]any{"name": "api", "env": append(env(
			"PAYMENT_API_KEY", "k-1", "DB_PASSWORD", "p-1", "GITHUB_TOKEN", "t-1", "CLIENT_SECRET", "s-1", "AUTH_KEY", "a-1",
			"VAULT_SECRET_ID", "item-1", "VAULT_SECRET_ID_2", "item-2", "PARTNER_API_KEY_2", "k-2", "TOKEN_URL", "https://x", "API_KEY_NAME", "n", "LOG_LEVEL", "info", "KEYS_ENABLED", "true",
			"SIGNING_KEY", "$(OTHER)", "EMPTY_SECRET", ""),
			map[string]any{"name": "REF_PASSWORD", "valueFrom": map[string]any{"secretKeyRef": map[string]any{"name": "db", "key": "password"}}})}},
		"initContainers": []any{map[string]any{"name": "migrate", "env": env("DB_PASSWORD", "p-2")}},
	}}}})
	normalize("apps", "deployments", dep)
	ann := dep["metadata"].(map[string]any)["annotations"].(map[string]any)
	want := "api/AUTH_KEY,api/CLIENT_SECRET,api/DB_PASSWORD,api/GITHUB_TOKEN,api/PARTNER_API_KEY_2,api/PAYMENT_API_KEY,migrate/DB_PASSWORD"
	if ann[WithheldEnvAnnotation] != want {
		t.Errorf("withheld %v\nwant     %v", ann[WithheldEnvAnnotation], want)
	}
	kept := map[string]string{"VAULT_SECRET_ID": "item-1", "VAULT_SECRET_ID_2": "item-2", "TOKEN_URL": "https://x", "API_KEY_NAME": "n", "LOG_LEVEL": "info", "KEYS_ENABLED": "true", "SIGNING_KEY": "$(OTHER)"}
	for _, e := range dep["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["env"].([]any) {
		m := e.(map[string]any)
		n, v := m["name"].(string), m["value"]
		switch {
		case kept[n] != "" && v != kept[n]:
			t.Errorf("%s changed to %v", n, v)
		case strings.HasSuffix(want, "api/"+n) || strings.Contains(want, "api/"+n+","):
			if v != "" {
				t.Errorf("%s survived", n)
			}
		case n == "REF_PASSWORD" && m["valueFrom"] == nil:
			t.Error("a secretKeyRef was dropped")
		}
	}
	// A CronJob's pod template is two levels further down.
	cj := k8sObj("CronJob", "shop", "nightly", nil, map[string]any{"spec": map[string]any{"jobTemplate": map[string]any{"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
		"containers": []any{map[string]any{"name": "job", "env": env("SFTP_PASSWORD", "p-3")}}}}}}}})
	normalize("batch", "cronjobs", cj)
	if got := cj["metadata"].(map[string]any)["annotations"].(map[string]any)[WithheldEnvAnnotation]; got != "job/SFTP_PASSWORD" {
		t.Errorf("cronjob withheld %v", got)
	}
}

// Restoring a workload whose credentials were withheld, with no source to
// read them from, is refused: restored empty it would look done and fail
// at run time.
func TestRestoreRefusesWithheldEnvWithoutSource(t *testing.T) {
	dep := k8sObj("Deployment", "shop", "api", map[string]any{"annotations": map[string]any{WithheldEnvAnnotation: "api/PAYMENT_API_KEY"}}, nil)
	dep["apiVersion"] = "apps/v1"
	res := applyOne(context.Background(), nil, nil, snapshot.Object{Body: dep}, RestoreOptions{})
	if res.OK || !strings.Contains(res.Detail, "api/PAYMENT_API_KEY") || !strings.Contains(res.Detail, "--secrets-from-context") {
		t.Fatalf("want a refusal naming the withheld variable, got %+v", res)
	}
}
