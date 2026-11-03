package kube

import (
	"context"
	"sort"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"

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
		// What AKS installs and upgrades itself, and what an addon manager
		// keeps as shipped; one it only created is captured, edits and all.
		{"installed by AKS", "apps", "daemonsets", k8sObj("DaemonSet", "gw", "agent", map[string]any{"labels": map[string]any{"kubernetes.azure.com/managedby": "aks"}}, nil), "upgraded by AKS"},
		// Seen on a real cluster: AKS's admission policies, some with no label at all
		// and only Eno as their field manager. Eno alone is not AKS: its SDK labels a
		// user's objects the same way.
		{"AKS policy applied by Eno, unlabelled", "admissionregistration.k8s.io", "validatingadmissionpolicies", k8sObj("ValidatingAdmissionPolicy", "", "aks-managed-x", enoApplied(nil), nil), "taken as AKS's: applied by Eno, named aks-managed-"},
		{"AKS CRD labelled by Eno", "apiextensions.k8s.io", "customresourcedefinitions", k8sObj("CustomResourceDefinition", "", "things.x.kubernetes.azure.com", enoLabel(nil), nil), "labelled managed-by Eno, in the kubernetes.azure.com group"},
		{"Eno with an AKS key", "rbac.authorization.k8s.io", "clusterroles", k8sObj("ClusterRole", "", "r", enoLabel(map[string]any{"annotations": map[string]any{"kubernetes.azure.com/x": "y"}}), nil), "with kubernetes.azure.com/x; --capture-platform keeps it"},
		{"Eno in an aks- namespace, a name users pick, is captured", "apps", "deployments", k8sObj("Deployment", "aks-store", "api", enoApplied(enoLabel(nil)), nil), ""},
		{"a user's Eno object is captured", "apps", "deployments", k8sObj("Deployment", "shop", "api", enoLabel(nil), nil), ""},
		{"a user's cluster-scoped Eno object is captured", "rbac.authorization.k8s.io", "clusterroles", k8sObj("ClusterRole", "", "shop-reader", enoApplied(enoLabel(nil)), nil), ""},
		{"an AKS-like name without Eno is captured", "admissionregistration.k8s.io", "validatingadmissionpolicies", k8sObj("ValidatingAdmissionPolicy", "", "aks-managed-x", nil, nil), ""},
		{"managed by Helm is captured", "apps", "deployments", k8sObj("Deployment", "shop", "api", map[string]any{"labels": map[string]any{"app.kubernetes.io/managed-by": "Helm"}}, nil), ""},
		{"labelled for another manager is captured", "apps", "daemonsets", k8sObj("DaemonSet", "gw", "agent", map[string]any{"labels": map[string]any{"kubernetes.azure.com/managedby": "someone"}}, nil), ""},
		{"reconciled by the addon manager", "storage.k8s.io", "storageclasses", k8sObj("StorageClass", "", "fast", map[string]any{"labels": map[string]any{"addonmanager.kubernetes.io/mode": "Reconcile"}}, nil), "addon manager"},
		{"only created by the addon manager is captured", "storage.k8s.io", "storageclasses", k8sObj("StorageClass", "", "fast", map[string]any{"labels": map[string]any{"addonmanager.kubernetes.io/mode": "EnsureExists"}}, nil), ""},
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
	aks := map[string]any{"labels": map[string]any{"kubernetes.azure.com/managedby": "aks"}}
	if r := p.skipReason("apps", "daemonsets", k8sObj("DaemonSet", "gw", "agent", aks, nil)); r != "" {
		t.Fatalf("include-system must capture what AKS installs, got skip: %s", r)
	}
	if r := p.skipReason("admissionregistration.k8s.io", "validatingadmissionpolicies", k8sObj("ValidatingAdmissionPolicy", "", "aks-managed-x", enoApplied(nil), nil)); r != "" {
		t.Fatalf("include-system must capture what Eno manages, got skip: %s", r)
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

func withheldDisplays(obj map[string]any) []string {
	md, _ := obj["metadata"].(map[string]any)
	ann, _ := md["annotations"].(map[string]any)
	v, _ := ann[WithheldEnvAnnotation].(string)
	if v == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		out = append(out, WithheldDisplay(p))
	}
	sort.Strings(out)
	return out
}

func envList(pairs ...string) []any {
	var out []any
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, map[string]any{"name": pairs[i], "value": pairs[i+1]})
	}
	return out
}

// A credential set as plain configuration is withheld like a Secret's
// value; a name that only mentions one, and a value that is not one, are
// kept (review of #41: names it missed, and names it took wrongly).
func TestCredentialEnvIsWithheld(t *testing.T) {
	withheld := []string{
		"PAYMENT_API_KEY", "DB_PASSWORD", "GITHUB_TOKEN", "CLIENT_SECRET", "AUTH_KEY", "PARTNER_API_KEY_2",
		"PGPASSWORD", "MYSQLPASSWORD", "SECRETKEY", "ADMINPASS", "GPG_PASSPHRASE", "SENTRY_DSN",
		"AWS_SECRET_ACCESS_KEY", "AZURE_CLIENT_SECRET", "JWT_SECRET", "SIGNING_KEY",
	}
	kept := []string{
		"VAULT_SECRET_ID", "VAULT_SECRET_ID_2", "TOKEN_URL", "API_KEY_NAME", "LOG_LEVEL", "KEYS_ENABLED",
		"PUBLIC_KEY", "PASSWORD_MIN_LENGTH", "TOKEN_EXPIRY_SECONDS", "KAFKA_KEY_SERIALIZER", "AWS_ACCESS_KEY_ID",
		"KEYCLOAK_URL", "MONKEY", "KEYBOARD_LAYOUT",
	}
	var pairs []string
	for _, n := range withheld {
		pairs = append(pairs, n, "v-"+n)
	}
	for _, n := range kept {
		pairs = append(pairs, n, "v-"+n)
	}
	pairs = append(pairs,
		"DATABASE_URL", "postgres://app:hunter2@db:5432/x", // a URL with a password, whatever its name
		"CACHE_URL", "redis://cache:6379", // a URL without one
		"GOOGLE_APPLICATION_CREDENTIALS", "/var/run/key.json", // a file path
		"OTHER_TOKEN", "$(TOKEN)", // a reference
		"EMPTY_SECRET", "")
	env := append(envList(pairs...), map[string]any{"name": "REF_PASSWORD", "valueFrom": map[string]any{"secretKeyRef": map[string]any{"name": "db", "key": "password"}}})
	dep := k8sObj("Deployment", "shop", "api", nil, map[string]any{"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
		"containers":     []any{map[string]any{"name": "api", "env": env}},
		"initContainers": []any{map[string]any{"name": "migrate", "env": envList("DB_PASSWORD", "p-2")}},
	}}}})
	normalize("apps", "deployments", dep)
	var want []string
	for _, n := range append(withheld, "DATABASE_URL") {
		want = append(want, "api/"+n)
	}
	want = append(want, "migrate/DB_PASSWORD")
	sort.Strings(want)
	if got := withheldDisplays(dep); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("withheld\n%v\nwant\n%v", got, want)
	}
	for _, sl := range slots(dep) {
		if strings.Contains(sl.path, "api") && sl.value != "" && strings.HasPrefix(sl.value, "v-") {
			for _, n := range withheld {
				if sl.name == n {
					t.Errorf("%s survived", n)
				}
			}
		}
	}
	if ref := dep["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["env"].([]any)[len(env)-1].(map[string]any); ref["valueFrom"] == nil {
		t.Error("a secretKeyRef was dropped")
	}
}

// Env lists are found wherever they are, not only under containers: a
// CronJob's job template, Argo's container and script, Tekton's steps, a
// HelmRelease's values; and a ConfigMap's keys (review of #41).
func TestCredentialsAreFoundWhereverTheyAre(t *testing.T) {
	for name, c := range map[string]struct {
		obj  map[string]any
		want string
	}{
		"cronjob": {k8sObj("CronJob", "shop", "nightly", nil, map[string]any{"spec": map[string]any{"jobTemplate": map[string]any{"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"containers": []any{map[string]any{"name": "job", "env": envList("SFTP_PASSWORD", "p")}}}}}}}}), "job/SFTP_PASSWORD"},
		"argo container": {k8sObj("WorkflowTemplate", "ci", "build", nil, map[string]any{"spec": map[string]any{"templates": []any{map[string]any{"name": "build",
			"container": map[string]any{"image": "x", "env": envList("REGISTRY_TOKEN", "t")}}}}}), "REGISTRY_TOKEN"},
		"tekton steps":       {k8sObj("Task", "ci", "push", nil, map[string]any{"spec": map[string]any{"steps": []any{map[string]any{"name": "push", "env": envList("NPM_TOKEN", "t")}}}}), "push/NPM_TOKEN"},
		"helmrelease values": {k8sObj("HelmRelease", "apps", "web", nil, map[string]any{"spec": map[string]any{"values": map[string]any{"env": envList("API_KEY", "k")}}}), "API_KEY"},
		"configmap":          {k8sObj("ConfigMap", "shop", "cfg", nil, map[string]any{"data": map[string]any{"DB_PASSWORD": "p", "LOG_LEVEL": "info", "DATABASE_URL": "postgres://u:p@h/db"}}), "data/DATABASE_URL,data/DB_PASSWORD"},
	} {
		t.Run(name, func(t *testing.T) {
			normalize("", "x", c.obj)
			if got := strings.Join(withheldDisplays(c.obj), ","); got != c.want {
				t.Errorf("withheld %q, want %q", got, c.want)
			}
		})
	}
}

// Two templates that each have a container "main" setting DB_PASSWORD are
// two slots, and a restore puts each value back where it came from; the
// reviewer saw either value written to both (review of #41).
func TestSlotsAreUniqueAndRestoredInPlace(t *testing.T) {
	mk := func(a, b string) map[string]any {
		return k8sObj("WorkflowTemplate", "ci", "two", nil, map[string]any{"apiVersion": "argoproj.io/v1alpha1", "spec": map[string]any{"templates": []any{
			map[string]any{"name": "one", "container": map[string]any{"name": "main", "env": envList("DB_PASSWORD", a)}},
			map[string]any{"name": "two", "container": map[string]any{"name": "main", "env": envList("DB_PASSWORD", b)}},
		}}})
	}
	live := mk("p-one", "p-two")
	snap := mk("p-one", "p-two")
	normalize("argoproj.io", "workflowtemplates", snap)
	paths := withheldEnv(snap)
	if len(paths) != 2 || paths[0] == paths[1] {
		t.Fatalf("paths %v: want two distinct slots", paths)
	}
	gvr := schema.GroupVersionResource{Group: "argoproj.io", Version: "v1alpha1", Resource: "workflowtemplates"}
	live["apiVersion"] = "argoproj.io/v1alpha1"
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{gvr: "WorkflowTemplateList"}, &unstructured.Unstructured{Object: live})
	for i := 0; i < 20; i++ { // map order varies between runs; the result must not
		body := deepCopy(snap)
		if err := fillEnv(context.Background(), &Clients{Dynamic: dyn}, &meta.RESTMapping{Resource: gvr, Scope: meta.RESTScopeNamespace}, body, paths); err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		for _, sl := range slots(body) {
			got[sl.path] = sl.value
		}
		if got[paths[0]] == got[paths[1]] || got[paths[0]] == "" {
			t.Fatalf("restored %v", got)
		}
	}
}

// An object with withheld credentials never matches the baseline: both
// sides withheld, a credential someone changed would compare equal and be
// skipped (review of #41).
func TestWithheldNeverMatchesTheBaseline(t *testing.T) {
	if !hasWithheld(func() map[string]any {
		d := k8sObj("Deployment", "kube-system", "addon", nil, map[string]any{"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"containers": []any{map[string]any{"name": "a", "env": envList("API_TOKEN", "t")}}}}}})
		normalize("apps", "deployments", d)
		return d
	}()) {
		t.Fatal("hasWithheld must see the annotation")
	}
}

// Restoring a workload whose credentials were withheld, with no source to
// read them from, is refused: restored empty it would look done and fail
// at run time.
func TestRestoreRefusesWithheldEnvWithoutSource(t *testing.T) {
	dep := k8sObj("Deployment", "shop", "api", map[string]any{"annotations": map[string]any{WithheldEnvAnnotation: "spec.template.spec.containers[api].env[PAYMENT_API_KEY]"}}, nil)
	dep["apiVersion"] = "apps/v1"
	res := applyOne(context.Background(), nil, nil, snapshot.Object{Body: dep}, RestoreOptions{})
	if res.OK || !strings.Contains(res.Detail, "api/PAYMENT_API_KEY") || !strings.Contains(res.Detail, "--secrets-from-context") {
		t.Fatalf("want a refusal naming the withheld variable, got %+v", res)
	}
}

// Kubernetes allows the same variable twice in one env list; each is its
// own slot, by index, and each value is restored to its own entry.
func TestDuplicateEnvNamesAreTwoSlots(t *testing.T) {
	dep := k8sObj("Deployment", "shop", "api", nil, map[string]any{"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
		"containers": []any{map[string]any{"name": "api", "env": envList("DB_PASSWORD", "first", "DB_PASSWORD", "second")}}}}}})
	var paths []string
	for _, sl := range slots(dep) {
		paths = append(paths, sl.path)
	}
	if len(paths) != 2 || paths[0] == paths[1] {
		t.Fatalf("paths %v: want two distinct slots", paths)
	}
}

func enoLabel(md map[string]any) map[string]any {
	if md == nil {
		md = map[string]any{}
	}
	md["labels"] = map[string]any{"app.kubernetes.io/managed-by": "Eno"}
	return md
}

func enoApplied(md map[string]any) map[string]any {
	if md == nil {
		md = map[string]any{}
	}
	md["managedFields"] = []any{map[string]any{"manager": "eno", "operation": "Apply"}}
	return md
}

// What is only taken to be AKS's can be kept, and that is recorded, so a diff
// compares like with like.
func TestCapturePlatformKeepsWhatIsOnlyTakenAsAKSs(t *testing.T) {
	obj := k8sObj("ValidatingAdmissionPolicy", "", "aks-managed-x", enoApplied(nil), nil)
	if r := (Policy{CapturePlatform: true}).skipReason("admissionregistration.k8s.io", "validatingadmissionpolicies", obj); r != "" {
		t.Errorf("--capture-platform skipped it: %s", r)
	}
	aks := k8sObj("DaemonSet", "gw", "agent", map[string]any{"labels": map[string]any{"kubernetes.azure.com/managedby": "aks"}}, nil)
	if r := (Policy{CapturePlatform: true}).skipReason("apps", "daemonsets", aks); r == "" {
		t.Error("what AKS labels as its own is a fact, not a guess, and stays skipped")
	}
	if n := (Policy{CapturePlatform: true}).Name(); n != "default+platform" {
		t.Errorf("policy name %q", n)
	}
}
