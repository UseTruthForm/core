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
// elsewhere, by the longest start that fits, and touches nothing else:
// not the same text in another field, not another kind of object.
func TestRenameStores(t *testing.T) {
	s := snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{
		planObject("onepassword.com/v1", "OnePasswordItem", "shop", "db", map[string]any{"spec": map[string]any{"itemPath": "vaults/apps/items/db"}}),
		planObject("onepassword.com/v1", "OnePasswordItem", "shop", "special", map[string]any{"spec": map[string]any{"itemPath": "vaults/apps/items/special"}}),
		planObject("onepassword.com/v1", "OnePasswordItem", "shop", "other", map[string]any{"spec": map[string]any{"itemPath": "vaults/shared/items/x"}}),
		planObject("external-secrets.io/v1", "ExternalSecret", "shop", "es", map[string]any{"spec": map[string]any{
			"secretStoreRef": map[string]any{"name": "kv-dev"},
			"target":         map[string]any{"name": "kv-dev"}, // a Secret's name, not a reference
			"data":           []any{map[string]any{"remoteRef": map[string]any{"key": "dev-api"}}, map[string]any{"remoteRef": map[string]any{"key": "plain"}}},
			"dataFrom":       []any{map[string]any{"extract": map[string]any{"key": "dev-bundle"}}},
		}}),
		planObject("external-secrets.io/v1", "ClusterExternalSecret", "", "ces", map[string]any{"spec": map[string]any{"externalSecretSpec": map[string]any{"data": []any{map[string]any{"remoteRef": map[string]any{"key": "dev-shared"}}}}}}),
		planObject("external-secrets.io/v1", "ClusterSecretStore", "", "kv-dev", map[string]any{"spec": map[string]any{"provider": map[string]any{"azurekv": map[string]any{"vaultUrl": "https://kv-dev.vault.azure.net"}}}}),
		planObject("spv.no/v2beta1", "AzureKeyVaultSecret", "shop", "akv", map[string]any{"spec": map[string]any{"vault": map[string]any{"name": "kv-dev", "object": map[string]any{"name": "dev-api"}}}}),
		planObject("secrets-store.csi.x-k8s.io/v1", "SecretProviderClass", "shop", "spc", map[string]any{"spec": map[string]any{"provider": "kv-dev", "parameters": map[string]any{"keyvaultName": "kv-dev"}}}),
		planObject("v1", "ConfigMap", "shop", "c", map[string]any{"data": map[string]any{"vault": "kv-dev", "path": "vaults/apps/items/db"}}),
		planObject("example.com/v1", "OnePasswordItem", "shop", "lookalike", map[string]any{"spec": map[string]any{"itemPath": "vaults/apps/items/db"}}),
		planObject("example.com/v1", "SecretStore", "shop", "lookalike", map[string]any{"spec": map[string]any{"provider": map[string]any{"azurekv": map[string]any{"vaultUrl": "https://kv-dev.vault.azure.net"}}}}),
	}}
	names := map[string]string{
		"vaults/apps/":              "vaults/apps-test/",
		"vaults/apps/items/special": "vaults/elsewhere/items/special-test", // the longer start wins
		"kv-dev":                    "kv-test",
		"https://kv-dev.":           "https://kv-test.",
		"dev-":                      "test-",
	}
	out, n, err := RenameStores(s, names)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, o := range out.Objects {
		for _, f := range []string{"spec.itemPath", "spec.secretStoreRef.name", "spec.target.name", "spec.data[].remoteRef.key", "spec.dataFrom[].extract.key",
			"spec.externalSecretSpec.data[].remoteRef.key", "spec.provider.azurekv.vaultUrl", "spec.vault.name", "spec.vault.object.name", "spec.provider", "spec.parameters.keyvaultName", "data.vault", "data.path"} {
			if v := fields(o.Body, f); len(v) > 0 {
				got[o.Kind()+"/"+o.Name()+" "+f] = v
			}
		}
	}
	want := map[string][]string{
		"OnePasswordItem/db spec.itemPath":                                       {"vaults/apps-test/items/db"},
		"OnePasswordItem/special spec.itemPath":                                  {"vaults/elsewhere/items/special-test"},
		"OnePasswordItem/other spec.itemPath":                                    {"vaults/shared/items/x"},
		"SecretStore/lookalike spec.provider.azurekv.vaultUrl":                   {"https://kv-dev.vault.azure.net"},
		"OnePasswordItem/lookalike spec.itemPath":                                {"vaults/apps/items/db"},
		"ExternalSecret/es spec.secretStoreRef.name":                             {"kv-test"},
		"ExternalSecret/es spec.target.name":                                     {"kv-dev"},
		"ExternalSecret/es spec.data[].remoteRef.key":                            {"test-api", "plain"},
		"ExternalSecret/es spec.dataFrom[].extract.key":                          {"test-bundle"},
		"ClusterExternalSecret/ces spec.externalSecretSpec.data[].remoteRef.key": {"test-shared"},
		"ClusterSecretStore/kv-dev spec.provider.azurekv.vaultUrl":               {"https://kv-test.vault.azure.net"},
		"AzureKeyVaultSecret/akv spec.vault.name":                                {"kv-test"},
		"AzureKeyVaultSecret/akv spec.vault.object.name":                         {"test-api"},
		"SecretProviderClass/spc spec.provider":                                  {"kv-dev"}, // which driver, not which vault
		"SecretProviderClass/spc spec.parameters.keyvaultName":                   {"kv-test"},
		"ConfigMap/c data.vault":                                                 {"kv-dev"},
		"ConfigMap/c data.path":                                                  {"vaults/apps/items/db"},
	}
	if !reflect.DeepEqual(got, want) || n != 10 {
		t.Errorf("%d changed:\n got %q\nwant %q", n, got, want)
	}
	// The snapshot given is not written to.
	if v := fields(s.Objects[0].Body, "spec.itemPath"); v[0] != "vaults/apps/items/db" {
		t.Errorf("the snapshot given was changed: %v", v)
	}
	if _, _, err := RenameStores(s, map[string]string{"vaults/apps/": "x/", "vaults/typo/": "y/"}); err == nil || !strings.Contains(err.Error(), "starts with: vaults/typo/") {
		t.Errorf("a start that fits nothing: %v", err)
	}
	if _, _, err := RenameStores(s, map[string]string{"": "x"}); err == nil {
		t.Error("an empty start rewrote every reference")
	}
}
