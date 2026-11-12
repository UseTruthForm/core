package kube

import (
	"regexp"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// Where a Secret comes from decides what a rebuild needs for it: nothing
// (a controller makes it again), a store reachable (an operator reads it
// from there), a key (it is kept encrypted), or its value from a person.
// Each origin is claimed on evidence the snapshot holds, and a Secret with
// none is a person's to supply: a tool not known here is listed as by
// hand, never as something that looks after itself.

// storeReader is a kind of object that makes Secrets from a secret store.
// Supporting another operator is a row here and a case in the test.
type storeReader struct {
	group, kind string
	// store is what the store is, to a person; named is a field that says
	// which one.
	store, named string
	// item are the fields that together name what is read.
	item []string
	// secret is the field naming the Secret made. With none the Secret has
	// the object's name; with one that is unset, the object makes none.
	secret string
}

var storeReaders = []storeReader{
	{group: "onepassword.com", kind: "OnePasswordItem", store: "1Password", item: []string{"spec.itemPath"}},
	{group: "secrets.hashicorp.com", kind: "VaultStaticSecret", store: "Vault", item: []string{"spec.mount", "spec.path"}, secret: "spec.destination.name"},
	{group: "secrets.hashicorp.com", kind: "VaultDynamicSecret", store: "Vault", item: []string{"spec.mount", "spec.path"}, secret: "spec.destination.name"},
	{group: "secrets.hashicorp.com", kind: "VaultPKISecret", store: "Vault", item: []string{"spec.mount", "spec.role"}, secret: "spec.destination.name"},
	{group: "spv.no", kind: "AzureKeyVaultSecret", store: "Azure Key Vault", named: "spec.vault.name", item: []string{"spec.vault.object.name"}, secret: "spec.output.secret.name"},
	// What a class reads is in a document its provider defines; the vault it
	// reads from is a field for the providers that have one.
	{group: "secrets-store.csi.x-k8s.io", kind: "SecretProviderClass", store: "Secrets Store CSI driver", named: "spec.provider", item: []string{"spec.parameters.keyvaultName", "spec.parameters.vaultAddress"}, secret: "spec.secretObjects[].secretName"},
}

// reads is what a store reader makes and from what, if o is one.
func (r storeReader) reads(o snapshot.Object) (store, item string, secrets []secretKey) {
	store = r.store
	if n := first(fields(o.Body, r.named)); r.named != "" && n != "" {
		store += " " + n
	}
	var parts []string
	for _, f := range r.item {
		if v := first(fields(o.Body, f)); v != "" {
			parts = append(parts, strings.Trim(v, "/"))
		}
	}
	item = strings.Join(parts, "/")
	if r.secret == "" {
		return store, item, []secretKey{{o.Namespace(), o.Name()}}
	}
	for _, n := range fields(o.Body, r.secret) {
		secrets = append(secrets, secretKey{o.Namespace(), n})
	}
	return store, item, secrets
}

// fields are the strings at a dotted path; "[]" after a name takes every
// element of a list.
func fields(body map[string]any, path string) []string {
	if path == "" {
		return nil
	}
	at := []any{body}
	for _, name := range strings.Split(path, ".") {
		each := strings.HasSuffix(name, "[]")
		name = strings.TrimSuffix(name, "[]")
		var next []any
		for _, v := range at {
			m, _ := v.(map[string]any)
			child, ok := m[name]
			if !ok {
				continue
			}
			if each {
				next = append(next, list(child)...)
			} else {
				next = append(next, child)
			}
		}
		at = next
	}
	var out []string
	for _, v := range at {
		if s := strOf(v); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func first(l []string) string {
	if len(l) == 0 {
		return ""
	}
	return l[0]
}

const azureFiles = "the Azure Files driver"

// azureFilesSecret is the name the Azure Files driver gives the Secret it
// keeps a storage account's key in.
var azureFilesSecret = regexp.MustCompile(`^azure-storage-account-.+-secret$`)

// secretKeys are the keys of a Secret in a snapshot, sorted.
func secretKeys(o snapshot.Object) []string {
	keys := []string{}
	for _, field := range []string{"data", "stringData"} {
		m, _ := o.Body[field].(map[string]any)
		for k := range m {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// madeAgain is what makes a Secret again with nothing supplied, by what
// the Secret itself says, or "".
func madeAgain(o snapshot.Object) string {
	md, _ := o.Body["metadata"].(map[string]any)
	labels, _ := md["labels"].(map[string]any)
	keys := strings.Join(secretKeys(o), ",")
	switch {
	case annotation(md, "cert-manager.io/certificate-name") != "" || strOf(labels["app.kubernetes.io/managed-by"]) == "cert-manager":
		return "cert-manager"
	case azureFilesSecret.MatchString(o.Name()) && keys == "azurestorageaccountkey,azurestorageaccountname":
		// Made when the driver provisions a share, from the account it
		// made or was pointed at.
		return azureFiles
	case o.Name() == "kedaorg-certs" && keys == "ca.crt,ca.key,tls.crt,tls.key":
		// With its CA's key: certificates brought to KEDA have the name
		// and not that.
		return "KEDA"
	}
	return ""
}

// storeMade is the store a Secret says it was made from, when the object
// that asked for it is not in the snapshot (a GitOps source applies it).
func storeMade(o snapshot.Object) (store, item string, ok bool) {
	md, _ := o.Body["metadata"].(map[string]any)
	if p := annotation(md, "operator.1password.io/item-path"); p != "" {
		return "1Password", p, true
	}
	// External Secrets marks what it writes to as well, and that is no
	// evidence: it marks a Secret it only adds to (creationPolicy Merge),
	// which a person made, and one it owns is not in a snapshot at all.
	return "", "", false
}

// noteOf is what else the Secret itself says of a Secret a person supplies.
func noteOf(o snapshot.Object) string {
	md, _ := o.Body["metadata"].(map[string]any)
	labels, _ := md["labels"].(map[string]any)
	switch {
	case labels["sealedsecrets.bitnami.com/sealed-secrets-key"] != nil:
		return "the key Sealed Secrets opens with: without it no SealedSecret can be read"
	case strOf(labels["app.kubernetes.io/managed-by"]) == "Helm" && annotation(md, "meta.helm.sh/release-name") != "":
		return "rendered by Helm release " + annotation(md, "meta.helm.sh/release-namespace") + "/" + annotation(md, "meta.helm.sh/release-name") + ": installing it again makes this, from the values given then"
	case strOf(o.Body["type"]) == "kubernetes.io/dockerconfigjson" || strOf(o.Body["type"]) == "kubernetes.io/dockercfg":
		return "a registry login"
	case strings.Join(secretKeys(o), ",") == "tls.key":
		return "holds a private key and nothing else, as an ACME account key does; no issuer in the snapshot names it, so it is taken as yours to supply"
	}
	return ""
}

// sealedKeyPrefix is how the Sealed Secrets controller names its keys.
const sealedKeyPrefix = "sealed-secrets-key"

// SealedSecrets is PlanEncrypted.By for Sealed Secrets.
const SealedSecrets = "Sealed Secrets"

// encrypted are the ways the snapshot shows Secrets kept encrypted, and
// the keys that open them: the one thing of each that only a copy kept
// outside the cluster brings back.
func encrypted(s snapshot.Snapshot) []PlanEncrypted {
	out := []PlanEncrypted{}
	sealed, keys, unheld := 0, map[string]bool{}, map[string]bool{}
	secrets, makes := map[string]bool{}, []string{}
	for _, o := range s.Objects {
		if o.Kind() == "Secret" && o.APIVersion() == "v1" {
			secrets[o.Namespace()+"/"+o.Name()] = true
		}
	}
	for _, o := range s.Objects {
		group, _, _ := strings.Cut(o.APIVersion(), "/")
		md, _ := o.Body["metadata"].(map[string]any)
		labels, _ := md["labels"].(map[string]any)
		spec, _ := o.Body["spec"].(map[string]any)
		switch {
		case group == "bitnami.com" && o.Kind() == "SealedSecret":
			sealed++
			if secrets[o.Namespace()+"/"+o.Name()] {
				makes = append(makes, o.Namespace()+"/"+o.Name())
			}
		case o.Kind() == "Secret" && o.APIVersion() == "v1" && labels["sealedsecrets.bitnami.com/sealed-secrets-key"] != nil:
			keys[o.Namespace()+"/"+o.Name()] = true
		case group == "kustomize.toolkit.fluxcd.io" && o.Kind() == "Kustomization":
			dec, _ := spec["decryption"].(map[string]any)
			if dec == nil {
				continue
			}
			e := PlanEncrypted{By: "SOPS, read by Flux Kustomization " + o.Namespace() + "/" + o.Name(), Secrets: []string{}, Keys: []string{}, KeysNotHeld: []string{}}
			if ref, _ := dec["secretRef"].(map[string]any); strOf(ref["name"]) != "" {
				e.Keys = append(e.Keys, o.Namespace()+"/"+strOf(ref["name"]))
			}
			out = append(out, e)
		}
	}
	for _, sk := range s.Skips {
		switch {
		case strings.HasPrefix(sk.Resource, "bitnami.com/") && strings.HasSuffix(sk.Resource, "/sealedsecrets"):
			sealed++
		case strings.HasPrefix(sk.Resource, "core/") && strings.HasSuffix(sk.Resource, "/secrets") && strings.HasPrefix(sk.Name, sealedKeyPrefix):
			// The controller's namespace is often kube-system, which a
			// capture leaves out: the key is named, and not in the snapshot.
			unheld[sk.Namespace+"/"+sk.Name] = true
		}
	}
	if sealed > 0 {
		sort.Strings(makes)
		e := PlanEncrypted{By: SealedSecrets, Objects: sealed, Secrets: makes, Keys: make([]string, 0, len(keys)), KeysNotHeld: make([]string, 0, len(unheld))}
		for k := range keys {
			e.Keys = append(e.Keys, k)
		}
		for k := range unheld {
			e.KeysNotHeld = append(e.KeysNotHeld, k)
		}
		sort.Strings(e.Keys)
		sort.Strings(e.KeysNotHeld)
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].By < out[j].By })
	return out
}
