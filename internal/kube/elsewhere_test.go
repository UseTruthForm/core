package kube

import (
	"reflect"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

func keysOf(s snapshot.Snapshot) []string {
	out := []string{}
	for _, o := range s.Objects {
		out = append(out, o.Kind()+"/"+o.Namespace()+"/"+o.Name())
	}
	return out
}

// An entry leaves out what it names and nothing else, and one that names
// nothing is refused: a mistyped entry would restore what it was written
// to hold back.
func TestLeaveOut(t *testing.T) {
	s := snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{
		planObject("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "flux-system", "root", nil),
		planObject("source.toolkit.fluxcd.io/v1", "GitRepository", "flux-system", "root", nil),
		planObject("argoproj.io/v1alpha1", "Application", "argocd", "shop", nil),
		planObject("app.k8s.io/v1beta1", "Application", "argocd", "shop", nil),
		planObject("v1", "ConfigMap", "shop", "a", nil),
		planObject("v1", "ConfigMap", "pay", "a", nil),
		planObject("rbac.authorization.k8s.io/v1", "ClusterRole", "", "a", nil),
		planObject("v1", "Namespace", "", "shop", nil),
	}}
	for _, c := range []struct {
		entries []string
		gone    []string
	}{
		{[]string{"Kustomization/flux-system/root"}, []string{"Kustomization/flux-system/root"}},
		{[]string{"*/flux-system/*"}, []string{"Kustomization/flux-system/root", "GitRepository/flux-system/root"}},
		{[]string{"Application.argoproj.io/argocd/shop"}, []string{"Application/argocd/shop"}}, // one of two kinds of the name
		{[]string{"ConfigMap/*/a"}, []string{"ConfigMap/shop/a", "ConfigMap/pay/a"}},
		{[]string{"ClusterRole/a"}, []string{"ClusterRole//a"}},
		{[]string{"Namespace/shop", "ConfigMap/shop/a"}, []string{"Namespace//shop", "ConfigMap/shop/a"}},
	} {
		out, err := LeaveOut(s, c.entries)
		if err != nil {
			t.Errorf("%v: %v", c.entries, err)
			continue
		}
		gone := map[string]bool{}
		for _, k := range keysOf(s) {
			gone[k] = true
		}
		for _, k := range keysOf(out) {
			delete(gone, k)
		}
		want := map[string]bool{}
		for _, k := range c.gone {
			want[k] = true
		}
		if c.entries[0] == "Application.argoproj.io/argocd/shop" {
			// Both have the same Kind/namespace/name: told apart by what is left.
			if len(out.Objects) != len(s.Objects)-1 || out.Objects[2].APIVersion() != "app.k8s.io/v1beta1" {
				t.Errorf("%v: left %v", c.entries, keysOf(out))
			}
			continue
		}
		if !reflect.DeepEqual(gone, want) {
			t.Errorf("%v: left out %v, want %v", c.entries, gone, want)
		}
	}
	for entry, want := range map[string]string{
		"ConfigMap/shop/b":       "name nothing",
		"ConfigMap/a":            "name nothing", // Kind/name is an object with no namespace
		"ClusterRole/*/a":        "name nothing", // and a namespace, even any, is one that has one
		"configmap/shop/a":       "name nothing",
		"ConfigMap":              "is not Kind/namespace/name",
		"ConfigMap/shop/a/extra": "is not Kind/namespace/name",
		"ConfigMap//a":           "has an empty part",
	} {
		if _, err := LeaveOut(s, []string{"ConfigMap/shop/a", entry}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", entry, err, want)
		}
	}
}

// A rename points the fields that say where a Secret is read from
// elsewhere, by the longest start that fits, and touches nothing else: not
// the same text in another field, not another kind of object, not the
// name of a store object, which keeps its name. Every reference is
// reported, changed or not, and so is what a rename cannot reach.
func TestRenameStores(t *testing.T) {
	es := map[string]any{
		"secretStoreRef": map[string]any{"name": "kv-dev"}, // an object of the snapshot, which keeps its name
		"target":         map[string]any{"name": "kv-dev"}, // a Secret's name
		"data": []any{
			map[string]any{"remoteRef": map[string]any{"key": "dev-api"}, "sourceRef": map[string]any{"storeRef": map[string]any{"name": "kv-dev"}}},
			map[string]any{"remoteRef": map[string]any{"key": "plain"}},
		},
		"dataFrom": []any{map[string]any{"extract": map[string]any{"key": "dev-bundle"}}, map[string]any{"find": map[string]any{"path": "dev-app/"}}},
	}
	s := snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{
		planObject("onepassword.com/v1", "OnePasswordItem", "shop", "db", map[string]any{"spec": map[string]any{"itemPath": "vaults/apps/items/db"}}),
		planObject("onepassword.com/v1", "OnePasswordItem", "shop", "special", map[string]any{"spec": map[string]any{"itemPath": "vaults/apps/items/special"}}),
		planObject("onepassword.com/v1", "OnePasswordItem", "shop", "other", map[string]any{"spec": map[string]any{"itemPath": "vaults/shared/items/x"}}),
		planObject("apps/v1", "Deployment", "shop", "web", map[string]any{"annotations": map[string]any{onePasswordPath: "vaults/apps/items/web", "note": "vaults/apps/items/web"}}),
		planObject("external-secrets.io/v1", "ExternalSecret", "shop", "es", map[string]any{"spec": es}),
		planObject("external-secrets.io/v1", "ClusterExternalSecret", "", "ces", map[string]any{"spec": map[string]any{"externalSecretSpec": map[string]any{
			"data":     []any{map[string]any{"remoteRef": map[string]any{"key": "dev-shared"}}},
			"dataFrom": []any{map[string]any{"extract": map[string]any{"key": "dev-all"}}, map[string]any{"find": map[string]any{"name": map[string]any{"regexp": "^dev-"}}}},
		}}}),
		planObject("external-secrets.io/v1alpha1", "PushSecret", "shop", "push", map[string]any{"spec": map[string]any{"data": []any{map[string]any{"match": map[string]any{"remoteRef": map[string]any{"remoteKey": "dev-pushed"}}}}}}),
		planObject("external-secrets.io/v1", "ClusterSecretStore", "", "kv-dev", map[string]any{"spec": map[string]any{"provider": map[string]any{"azurekv": map[string]any{"vaultUrl": "https://kv-dev.vault.azure.net"}}}}),
		planObject("external-secrets.io/v1", "SecretStore", "shop", "hv", map[string]any{"spec": map[string]any{"provider": map[string]any{"vault": map[string]any{"server": "https://vault-dev:8200", "path": "dev-kv", "namespace": "dev-ns"}}}}),
		planObject("external-secrets.io/v1", "SecretStore", "shop", "gcp", map[string]any{"spec": map[string]any{"provider": map[string]any{"gcpsm": map[string]any{"projectID": "dev-project"}}}}),
		planObject("external-secrets.io/v1", "SecretStore", "shop", "op", map[string]any{"spec": map[string]any{"provider": map[string]any{"onepassword": map[string]any{"connectHost": "https://connect-dev", "vaults": map[string]any{"apps": 1}}}}}),
		planObject("external-secrets.io/v1", "SecretStore", "shop", "aws", map[string]any{"spec": map[string]any{"provider": map[string]any{"aws": map[string]any{"region": "eu-west-1"}}}}),
		planObject("secrets.hashicorp.com/v1beta1", "VaultStaticSecret", "shop", "vss", map[string]any{"spec": map[string]any{"mount": "dev-kv", "path": "shop/db", "namespace": "dev-ns"}}),
		planObject("secrets.hashicorp.com/v1beta1", "VaultPKISecret", "shop", "pki", map[string]any{"spec": map[string]any{"mount": "dev-pki", "role": "dev-role"}}), // a role is the same in each
		planObject("secrets.hashicorp.com/v1beta1", "VaultConnection", "shop", "conn", map[string]any{"spec": map[string]any{"address": "https://vault-dev:8200"}}),
		planObject("secrets.hashicorp.com/v1beta1", "VaultAuth", "shop", "auth", map[string]any{"spec": map[string]any{"mount": "dev-k8s", "namespace": "dev-ns"}}),
		planObject("spv.no/v2beta1", "AzureKeyVaultSecret", "shop", "akv", map[string]any{"spec": map[string]any{"vault": map[string]any{"name": "kv-dev", "object": map[string]any{"name": "dev-api"}}}}),
		planObject("secrets-store.csi.x-k8s.io/v1", "SecretProviderClass", "shop", "spc", map[string]any{"spec": map[string]any{"provider": "kv-dev", "parameters": map[string]any{"keyvaultName": "kv-dev", "objects": "array:\n  - objectName: dev-api"}}}),
		planObject("secrets-store.csi.x-k8s.io/v1", "SecretProviderClass", "shop", "hv", map[string]any{"spec": map[string]any{"provider": "vault", "parameters": map[string]any{"vaultAddress": "https://vault-dev:8200"}}}),
		planObject("v1", "ConfigMap", "shop", "c", map[string]any{"data": map[string]any{"vault": "kv-dev", "path": "vaults/apps/items/db"}}),
		planObject("example.com/v1", "OnePasswordItem", "shop", "lookalike", map[string]any{"spec": map[string]any{"itemPath": "vaults/apps/items/db"}}),
		planObject("example.com/v1", "SecretStore", "shop", "lookalike", map[string]any{"spec": map[string]any{"provider": map[string]any{"azurekv": map[string]any{"vaultUrl": "https://kv-dev.vault.azure.net"}}}}),
	}}
	before := deepCopy(map[string]any{"o": bodies(s)})
	names := map[string]string{
		"vaults/apps/":              "vaults/apps-test/",
		"vaults/apps/items/special": "vaults/elsewhere/items/special-test", // the longer start wins
		"kv-dev":                    "kv-test",
		"https://kv-dev.":           "https://kv-test.",
		"https://vault-dev":         "https://vault-test",
		"https://connect-dev":       "https://connect-test",
		"dev-":                      "test-",
	}
	out, rep, err := RenameStores(s, names)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, deepCopy(map[string]any{"o": bodies(s)})) {
		t.Error("the snapshot given was changed")
	}
	got := map[string]string{}
	for _, r := range rep.Changed {
		got[r.Object+" "+r.Field] = r.From + " -> " + r.To
	}
	want := map[string]string{
		"OnePasswordItem shop/db spec.itemPath":                                     "vaults/apps/items/db -> vaults/apps-test/items/db",
		"OnePasswordItem shop/special spec.itemPath":                                "vaults/apps/items/special -> vaults/elsewhere/items/special-test",
		"Deployment shop/web metadata.annotations[operator.1password.io/item-path]": "vaults/apps/items/web -> vaults/apps-test/items/web",
		"ExternalSecret shop/es spec.dataFrom[].extract.key":                        "dev-bundle -> test-bundle",
		"ExternalSecret shop/es spec.dataFrom[].find.path":                          "dev-app/ -> test-app/",
		"ClusterExternalSecret ces spec.externalSecretSpec.data[].remoteRef.key":    "dev-shared -> test-shared",
		"ClusterExternalSecret ces spec.externalSecretSpec.dataFrom[].extract.key":  "dev-all -> test-all",
		"PushSecret shop/push spec.data[].match.remoteRef.remoteKey":                "dev-pushed -> test-pushed",
		"ClusterSecretStore kv-dev spec.provider.azurekv.vaultUrl":                  "https://kv-dev.vault.azure.net -> https://kv-test.vault.azure.net",
		"SecretStore shop/hv spec.provider.vault.server":                            "https://vault-dev:8200 -> https://vault-test:8200",
		"SecretStore shop/hv spec.provider.vault.path":                              "dev-kv -> test-kv",
		"SecretStore shop/hv spec.provider.vault.namespace":                         "dev-ns -> test-ns",
		"SecretStore shop/gcp spec.provider.gcpsm.projectID":                        "dev-project -> test-project",
		"SecretStore shop/op spec.provider.onepassword.connectHost":                 "https://connect-dev -> https://connect-test",
		"VaultStaticSecret shop/vss spec.mount":                                     "dev-kv -> test-kv",
		"VaultStaticSecret shop/vss spec.namespace":                                 "dev-ns -> test-ns",
		"VaultPKISecret shop/pki spec.mount":                                        "dev-pki -> test-pki",
		"VaultConnection shop/conn spec.address":                                    "https://vault-dev:8200 -> https://vault-test:8200",
		"VaultAuth shop/auth spec.mount":                                            "dev-k8s -> test-k8s",
		"VaultAuth shop/auth spec.namespace":                                        "dev-ns -> test-ns",
		"AzureKeyVaultSecret shop/akv spec.vault.name":                              "kv-dev -> kv-test",
		"AzureKeyVaultSecret shop/akv spec.vault.object.name":                       "dev-api -> test-api",
		"SecretProviderClass shop/spc spec.parameters.keyvaultName":                 "kv-dev -> kv-test",
		"SecretProviderClass shop/hv spec.parameters.vaultAddress":                  "https://vault-dev:8200 -> https://vault-test:8200",
	}
	// Two references of one field of one object: the first of the ExternalSecret's data.
	delete(got, "ExternalSecret shop/es spec.data[].remoteRef.key")
	if !reflect.DeepEqual(got, want) {
		for k, v := range want {
			if got[k] != v {
				t.Errorf("%s: got %q, want %q", k, got[k], v)
			}
		}
		for k, v := range got {
			if want[k] == "" {
				t.Errorf("changed and should not be: %s: %s", k, v)
			}
		}
	}
	var kept []string
	for _, r := range rep.Kept {
		kept = append(kept, r.Object+" "+r.Field+" "+r.From)
	}
	wantKept := []string{
		"OnePasswordItem shop/other spec.itemPath vaults/shared/items/x",
		"ExternalSecret shop/es spec.data[].remoteRef.key plain",
		"VaultStaticSecret shop/vss spec.path shop/db",
	}
	if !reflect.DeepEqual(kept, wantKept) {
		t.Errorf("kept:\n got %q\nwant %q", kept, wantKept)
	}
	wantUnreached := []string{
		"ClusterExternalSecret ces: it finds what it reads by a pattern of names (dataFrom.find.name)",
		"SecretStore shop/op: its vaults are named as keys of spec.provider.onepassword.vaults",
		"SecretStore shop/aws: which store its provider (aws) reads is in fields this does not know",
		"SecretProviderClass shop/spc: what it reads is listed in spec.parameters.objects, a document of its provider's",
	}
	if !reflect.DeepEqual(rep.Unreached, wantUnreached) {
		t.Errorf("unreached:\n got %q\nwant %q", rep.Unreached, wantUnreached)
	}
	// What is written is what is reported, and nothing beside it.
	at := func(kind, name, field string) []string {
		for _, o := range out.Objects {
			if o.Kind() == kind && o.Name() == name && !strings.HasPrefix(o.APIVersion(), "example.com/") {
				return fields(o.Body, field)
			}
		}
		return nil
	}
	for _, c := range []struct{ kind, name, field, want string }{
		{"ExternalSecret", "es", "spec.data[].remoteRef.key", "test-api plain"},
		{"ExternalSecret", "es", "spec.secretStoreRef.name", "kv-dev"},
		{"ExternalSecret", "es", "spec.data[].sourceRef.storeRef.name", "kv-dev"},
		{"ExternalSecret", "es", "spec.target.name", "kv-dev"},
		{"ClusterSecretStore", "kv-dev", "spec.provider.azurekv.vaultUrl", "https://kv-test.vault.azure.net"},
		{"SecretProviderClass", "spc", "spec.provider", "kv-dev"}, // which driver, not which vault
		{"SecretProviderClass", "spc", "spec.parameters.objects", "array:\n  - objectName: dev-api"},
		{"VaultPKISecret", "pki", "spec.role", "dev-role"},
		{"ConfigMap", "c", "data.vault", "kv-dev"},
		{"ConfigMap", "c", "data.path", "vaults/apps/items/db"},
		{"SecretStore", "aws", "spec.provider.aws.region", "eu-west-1"},
	} {
		if got := strings.Join(at(c.kind, c.name, c.field), " "); got != c.want {
			t.Errorf("%s/%s %s: %q, want %q", c.kind, c.name, c.field, got, c.want)
		}
	}
	for _, o := range out.Objects {
		md, _ := o.Body["metadata"].(map[string]any)
		switch {
		case o.Kind() == "Deployment" && (annotation(md, onePasswordPath) != "vaults/apps-test/items/web" || annotation(md, "note") != "vaults/apps/items/web"):
			t.Errorf("the workload's annotations: %v", md["annotations"])
		case strings.HasPrefix(o.APIVersion(), "example.com/") && !reflect.DeepEqual(o.Body, s.Objects[indexOf(s, o)].Body):
			t.Errorf("another API's %s was rewritten", o.Kind())
		}
	}

	// A start a longer one always wins over still names something.
	if _, _, err := RenameStores(s, map[string]string{"vaults/apps/items/special": "a", "vaults/apps/items/specia": "b", "vaults/apps/items/db": "c", "vaults/apps/items/web": "d", "vaults/apps/": "e/"}); err != nil {
		t.Errorf("a start that a longer one wins over: %v", err)
	}
	for why, names := range map[string]map[string]string{
		"starts with: vaults/typo/": {"vaults/apps/": "x/", "vaults/typo/": "y/"},
		"an empty start":            {"": "x"},
		"is replaced by nothing":    {"vaults/apps/": ""},
		"names nothing to rename":   {},
	} {
		if _, _, err := RenameStores(s, names); err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("%v: got %v, want %q", names, err, why)
		}
	}
}

func bodies(s snapshot.Snapshot) []any {
	out := make([]any, len(s.Objects))
	for i, o := range s.Objects {
		out[i] = o.Body
	}
	return out
}

func indexOf(s snapshot.Snapshot, o snapshot.Object) int {
	for i, x := range s.Objects {
		if x.Key() == o.Key() {
			return i
		}
	}
	return 0
}
