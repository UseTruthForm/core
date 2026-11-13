package kube

import (
	"fmt"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// A snapshot restored into another environment than the one it was taken
// from (a drill beside the source, a rebuild of dev as test) needs two
// things changed and nothing else: objects that must not arrive there (the
// GitOps root, which would have the new cluster sync the old one's path),
// and where its Secrets are read from (the other environment's vault).

// LeaveOut returns the snapshot without the objects the entries name, and
// those objects' keys. An entry is Kind/namespace/name, or Kind/name for
// an object with no namespace; Kind may be Kind.group where two APIs share
// one, and "*" stands for any kind, namespace or name. An entry that names
// nothing is an error: a mistyped one would otherwise restore what it was
// written to hold back.
func LeaveOut(s snapshot.Snapshot, entries []string) (snapshot.Snapshot, error) {
	type pattern struct{ kind, ns, name string }
	pats := make([]pattern, len(entries))
	for i, e := range entries {
		parts := strings.Split(e, "/")
		switch len(parts) {
		case 2:
			pats[i] = pattern{parts[0], "", parts[1]}
		case 3:
			pats[i] = pattern{parts[0], parts[1], parts[2]}
		default:
			return s, fmt.Errorf("%q is not Kind/namespace/name, or Kind/name for an object with no namespace", e)
		}
		if pats[i].kind == "" || pats[i].name == "" || (len(parts) == 3 && pats[i].ns == "") {
			return s, fmt.Errorf("%q has an empty part; \"*\" stands for any", e)
		}
	}
	is := func(pat, v string) bool { return pat == "*" || pat == v }
	matched := make([]bool, len(pats))
	out := s
	out.Objects = nil
	for _, o := range s.Objects {
		group, _, versioned := strings.Cut(o.APIVersion(), "/")
		if !versioned {
			group = ""
		}
		left := false
		for i, p := range pats {
			kind := p.kind == "*" || p.kind == o.Kind() || p.kind == o.Kind()+"."+group
			// Kind/name is an object with no namespace only: "*" for the
			// namespace is how to reach into every one.
			if kind && p.ns == o.Namespace() || kind && p.ns == "*" && o.Namespace() != "" {
				if is(p.name, o.Name()) {
					matched[i], left = true, true
				}
			}
		}
		if !left {
			out.Objects = append(out.Objects, o)
		}
	}
	var none []string
	for i, ok := range matched {
		if !ok {
			none = append(none, entries[i])
		}
	}
	if len(none) > 0 {
		return s, fmt.Errorf("these name nothing in the snapshot: %s", strings.Join(none, ", "))
	}
	return out, nil
}

// externalSecretRefs are where an ExternalSecret says what it reads. Not
// which store object it reads through (secretStoreRef, sourceRef): that
// names an object of the snapshot, which keeps its name, and which vault
// that object is is the store's own field.
var externalSecretRefs = []string{"data[].remoteRef.key", "dataFrom[].extract.key", "dataFrom[].find.path"}

// providerRefs are the fields of a SecretStore's provider that say which
// vault it is.
var providerRefs = map[string][]string{
	"azurekv":        {"vaultUrl"},
	"vault":          {"server", "path", "namespace"},
	"gcpsm":          {"projectID"},
	"onepassword":    {"connectHost"},
	"onepasswordSDK": {"vault"},
}

// whichStore are the fields that say which store is read, where the rest
// say what in it. A 1Password item's path is both: it starts with its
// vault.
var whichStore = map[string]bool{
	"spec.itemPath": true, "metadata.annotations[" + onePasswordPath + "]": true,
	"spec.provider.azurekv.vaultUrl": true, "spec.provider.vault.server": true, "spec.provider.gcpsm.projectID": true,
	"spec.provider.onepassword.connectHost": true, "spec.provider.onepasswordSDK.vault": true,
	"spec.address": true, "spec.vault.name": true,
	"spec.parameters.keyvaultName": true, "spec.parameters.vaultAddress": true,
	// What a PushSecret writes to. It is an item's name, and it is judged
	// as a store is: unchanged, the new cluster writes the source's item.
	pushSecretKey: true,
}

const pushSecretKey = "spec.data[].match.remoteRef.remoteKey"

// onePasswordPath is the annotation by which the 1Password operator is
// asked for a Secret from a workload, and marks the Secrets it made.
const onePasswordPath = "operator.1password.io/item-path"

// storeRefs are the fields of an object that say where in a secret store
// it reads or writes: what differs when the same objects are to use
// another environment's items.
func storeRefs(o snapshot.Object) []string {
	group, _, _ := strings.Cut(o.APIVersion(), "/")
	for _, r := range storeReaders {
		if r.group == group && r.kind == o.Kind() {
			if r.refs != nil {
				return r.refs
			}
			return r.item
		}
	}
	var out []string
	switch {
	case group == "secrets.hashicorp.com" && o.Kind() == "VaultConnection":
		out = []string{"spec.address"}
	case group == "secrets.hashicorp.com" && o.Kind() == "VaultAuth":
		out = []string{"spec.mount", "spec.namespace"}
	case group != "external-secrets.io":
	case o.Kind() == "ExternalSecret":
		for _, f := range externalSecretRefs {
			out = append(out, "spec."+f)
		}
	case o.Kind() == "ClusterExternalSecret":
		for _, f := range externalSecretRefs {
			out = append(out, "spec.externalSecretSpec."+f)
		}
	case o.Kind() == "PushSecret":
		// It writes to the store: unchanged, it writes to the source's.
		out = []string{pushSecretKey}
	case o.Kind() == "SecretStore" || o.Kind() == "ClusterSecretStore":
		for provider, fs := range providerRefs {
			for _, f := range fs {
				out = append(out, "spec.provider."+provider+"."+f)
			}
		}
		sort.Strings(out)
	}
	return out
}

// unreached says what of an object's use of a store a rename does not
// reach, or "": said, so that a restore does not go on reading the
// source's store without a word.
func unreached(o snapshot.Object) string {
	group, _, _ := strings.Cut(o.APIVersion(), "/")
	spec, _ := o.Body["spec"].(map[string]any)
	switch {
	case group == "secrets-store.csi.x-k8s.io" && o.Kind() == "SecretProviderClass":
		params, _ := spec["parameters"].(map[string]any)
		for _, doc := range []string{"objects", "secrets"} {
			if params[doc] != nil {
				return "what it reads is listed in spec.parameters." + doc + ", a document of its provider's"
			}
		}
	case group == "external-secrets.io" && (o.Kind() == "SecretStore" || o.Kind() == "ClusterSecretStore"):
		provider, _ := spec["provider"].(map[string]any)
		var other []string
		for name := range provider {
			if providerRefs[name] == nil {
				other = append(other, name)
			}
		}
		sort.Strings(other)
		if len(other) > 0 {
			return "which store its provider (" + strings.Join(other, ", ") + ") reads is in fields this does not know"
		}
		if op, _ := provider["onepassword"].(map[string]any); op["vaults"] != nil {
			return "its vaults are named as keys of spec.provider.onepassword.vaults"
		}
	case group == "external-secrets.io" && (o.Kind() == "ExternalSecret" || o.Kind() == "ClusterExternalSecret"):
		for _, f := range []string{"spec.dataFrom[].find.name.regexp", "spec.externalSecretSpec.dataFrom[].find.name.regexp"} {
			if len(fields(o.Body, f)) > 0 {
				return "it finds what it reads by a pattern of names (dataFrom.find.name)"
			}
		}
		for _, at := range []string{"spec.dataFrom", "spec.externalSecretSpec.dataFrom"} {
			if findsByTags(o.Body, at) {
				return "it finds what it reads by tags (dataFrom.find.tags)"
			}
		}
	}
	if group == "secrets.hashicorp.com" && strings.HasPrefix(o.Kind(), "HCP") {
		return "which HCP Vault Secrets organisation, project and app it reads is in fields this does not know"
	}
	if group == "external-secrets.io" && (o.Kind() == "ExternalSecret" || o.Kind() == "ClusterExternalSecret") {
		for _, at := range []string{"spec.dataFrom", "spec.externalSecretSpec.dataFrom"} {
			if fromGenerator(o.Body, at) {
				return "it takes what it reads from a generator (dataFrom.sourceRef.generatorRef), whose own settings say where from"
			}
		}
	}
	if asksVaultAgent(o.Body) {
		return "it asks the Vault agent for secrets by annotation (" + vaultAgentSecret + "secret-*, -template-*), which names a path in Vault"
	}
	return ""
}

// findsByTags reports a dataFrom entry, in the list at the dotted path,
// that finds by tags.
func findsByTags(body map[string]any, at string) bool {
	var v any = body
	for _, name := range strings.Split(at, ".") {
		m, _ := v.(map[string]any)
		v = m[name]
	}
	for _, e := range list(v) {
		m, _ := e.(map[string]any)
		find, _ := m["find"].(map[string]any)
		if tags, _ := find["tags"].(map[string]any); len(tags) > 0 {
			return true
		}
	}
	return false
}

// vaultAgentSecret starts the annotations by which a pod asks the Vault
// agent injector for a secret.
const vaultAgentSecret = "vault.hashicorp.com/agent-inject-"

// vaultAgentAsks are the annotations of those that name what is read: a
// secret's path, or a template that reads some.
var vaultAgentAsks = []string{vaultAgentSecret + "secret-", vaultAgentSecret + "template-"}

// fromGenerator reports a dataFrom entry, in the list at the dotted path,
// that reads from a generator.
func fromGenerator(body map[string]any, at string) bool {
	var v any = body
	for _, name := range strings.Split(at, ".") {
		m, _ := v.(map[string]any)
		v = m[name]
	}
	for _, e := range list(v) {
		m, _ := e.(map[string]any)
		ref, _ := m["sourceRef"].(map[string]any)
		if ref["generatorRef"] != nil {
			return true
		}
	}
	return false
}

// StoreKinds are the kinds of object a rename looks at for a use of a
// secret store, for a person: a store named anywhere else is not seen,
// and "nothing listed" has to be read with that.
func StoreKinds() []string {
	seen := map[string]bool{}
	out := []string{"ExternalSecret", "ClusterExternalSecret", "PushSecret", "SecretStore", "ClusterSecretStore", "VaultConnection", "VaultAuth", "HCPVaultSecretsApp", "HCPAuth"}
	for _, k := range out {
		seen[k] = true
	}
	for _, r := range storeReaders {
		if !seen[r.kind] {
			seen[r.kind] = true
			out = append(out, r.kind)
		}
	}
	sort.Strings(out)
	return out
}

// asksVaultAgent reports such an annotation on the object or on a pod
// template anywhere in it.
func asksVaultAgent(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		if ann, _ := x["annotations"].(map[string]any); ann != nil {
			for k := range ann {
				for _, asks := range vaultAgentAsks {
					if strings.HasPrefix(k, asks) {
						return true
					}
				}
			}
		}
		for _, c := range x {
			if asksVaultAgent(c) {
				return true
			}
		}
	case []any:
		for _, c := range x {
			if asksVaultAgent(c) {
				return true
			}
		}
	}
	return false
}

// StoreRef is one reference to a secret store: the object and field that
// hold it, what it was, and what it is after a rename (the same, if no
// start fitted it).
type StoreRef struct {
	Object, Field, From, To string
}

// RenameReport is what a rename did and did not do.
type RenameReport struct {
	// Changed are the references that point elsewhere now. Kept are those
	// a start names and leaves as they are: said to be the same in both
	// environments. Of those no start fits, Unnamed say which store (a
	// vault's address, a 1Password item's path): they read where the
	// source reads, and nobody said they should. Within are the rest,
	// which name an item in a store and read from whichever store their
	// store object says.
	Changed, Kept, Unnamed, Within []StoreRef
	// Unreached are objects that use a store in a way a rename does not
	// reach, each with why.
	Unreached []string
}

// RenameStores rewrites where the snapshot's objects read their Secrets
// from. names maps the start of a reference to what replaces it ("vaults/
// apps/" to "vaults/apps-test/"; a whole reference is its own start), and
// the longest start that fits a reference is the one applied; a start replaced by itself
// says a reference is the same in both environments. Only the
// fields that name a store or an item in it are touched. A start that
// fits no reference is an error. The report says every reference changed,
// every one left as it was, and what a rename cannot reach: a restore
// into another environment that still reads the first one's secrets is
// the thing to rule out, and it is ruled out by reading that list.
func RenameStores(s snapshot.Snapshot, names map[string]string) (snapshot.Snapshot, RenameReport, error) {
	var rep RenameReport
	if len(names) == 0 {
		return s, rep, fmt.Errorf("it names nothing to rename")
	}
	starts := make([]string, 0, len(names))
	for k, v := range names {
		if k == "" {
			return s, rep, fmt.Errorf("an empty start would rewrite every reference")
		}
		if v == "" {
			return s, rep, fmt.Errorf("%q is replaced by nothing; give what replaces it", k)
		}
		starts = append(starts, k)
	}
	// Longest first; among equals, in order, so that the result is one.
	sort.Slice(starts, func(i, j int) bool {
		if len(starts[i]) != len(starts[j]) {
			return len(starts[i]) > len(starts[j])
		}
		return starts[i] < starts[j]
	})
	fits, loose := map[string]bool{}, map[string]bool{}
	out := s
	out.Objects = make([]snapshot.Object, len(s.Objects))
	for i, o := range s.Objects {
		out.Objects[i] = o
		who := o.Kind() + " " + o.Name()
		if o.Namespace() != "" {
			who = o.Kind() + " " + o.Namespace() + "/" + o.Name()
		}
		if why := unreached(o); why != "" {
			rep.Unreached = append(rep.Unreached, who+": "+why)
		}
		body := deepCopy(o.Body)
		n := 0
		rename := func(field string) func(string) string {
			return func(v string) string {
				to, applied := v, false
				for _, st := range starts {
					if !strings.HasPrefix(v, st) {
						continue
					}
					// Every start that fits names something, though the
					// longest alone is applied.
					fits[st] = true
					if names[st] == st && v != st && !strings.HasSuffix(st, "/") {
						// "v: v" would say every reference that starts with
						// a v is the same in both: it says so of a whole
						// reference, or of everything under a path.
						loose[st] = true
						continue
					}
					if !applied {
						to, applied = names[st]+strings.TrimPrefix(v, st), true
					}
				}
				ref := StoreRef{Object: who, Field: field, From: v, To: to}
				switch {
				case !applied && whichStore[field]:
					rep.Unnamed = append(rep.Unnamed, ref)
				case !applied:
					rep.Within = append(rep.Within, ref)
				case to == v:
					rep.Kept = append(rep.Kept, ref)
				default:
					rep.Changed = append(rep.Changed, ref)
				}
				return to
			}
		}
		for _, path := range storeRefs(o) {
			n += setFields(body, path, rename(path))
		}
		// On any object: a workload asks the 1Password operator for a
		// Secret by this annotation, and a Secret it made carries it.
		if md, _ := body["metadata"].(map[string]any); md != nil {
			if ann, _ := md["annotations"].(map[string]any); ann != nil {
				if v, ok := ann[onePasswordPath].(string); ok && v != "" {
					if to := rename("metadata.annotations[" + onePasswordPath + "]")(v); to != v {
						ann[onePasswordPath] = to
						n++
					}
				}
			}
		}
		if n > 0 {
			out.Objects[i].Body = body
		}
	}
	// The Vault Secrets Operator's objects read through a VaultConnection,
	// or, with none, through the one its own installation sets: that one
	// is no object of the snapshot, and no start can name it.
	vso, connection := 0, false
	for _, o := range s.Objects {
		if group, _, _ := strings.Cut(o.APIVersion(), "/"); group == "secrets.hashicorp.com" {
			switch o.Kind() {
			case "VaultConnection":
				connection = true
			case "VaultStaticSecret", "VaultDynamicSecret", "VaultPKISecret", "VaultAuth":
				vso++
			}
		}
	}
	if vso > 0 && !connection {
		rep.Unreached = append(rep.Unreached, fmt.Sprintf("%d Vault Secrets Operator objects: no VaultConnection is in the snapshot, so they read the Vault the operator's own installation names", vso))
	}
	var none []string
	for _, st := range starts {
		if !fits[st] {
			none = append(none, st)
		}
	}
	sort.Strings(none)
	var wide []string
	for st := range loose {
		wide = append(wide, st)
	}
	sort.Strings(wide)
	if len(wide) > 0 {
		return s, RenameReport{}, fmt.Errorf("a start replaced by itself says a reference is the same in both environments, and has to be a whole reference or end with a slash: %s", strings.Join(wide, ", "))
	}
	if len(none) > 0 {
		return s, RenameReport{}, fmt.Errorf("no store reference in the snapshot starts with: %s", strings.Join(none, ", "))
	}
	return out, rep, nil
}

// setFields passes each string at a dotted path (as fields reads them) to
// f and stores what it returns, and counts those that changed.
func setFields(body map[string]any, path string, f func(string) string) int {
	names := strings.Split(path, ".")
	var walk func(v any, rest []string) int
	walk = func(v any, rest []string) int {
		m, _ := v.(map[string]any)
		if m == nil {
			return 0
		}
		name := strings.TrimSuffix(rest[0], "[]")
		child, ok := m[name]
		if !ok {
			return 0
		}
		if strings.HasSuffix(rest[0], "[]") {
			n := 0
			l := list(child)
			for i, el := range l {
				if len(rest) == 1 {
					if sv, ok := el.(string); ok {
						if nv := f(sv); nv != sv {
							l[i] = nv
							n++
						}
					}
					continue
				}
				n += walk(el, rest[1:])
			}
			return n
		}
		if len(rest) > 1 {
			return walk(child, rest[1:])
		}
		if sv, ok := child.(string); ok {
			if nv := f(sv); nv != sv {
				m[name] = nv
				return 1
			}
		}
		return 0
	}
	return walk(body, names)
}
