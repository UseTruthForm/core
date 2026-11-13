package kube

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// What is withheld from an object that is not a Secret: a credential set
// as plain configuration. Each candidate is a slot, found by where it is
// and never by what it holds, so that a restore finds the same slots in a
// snapshot whose values are gone; whether a slot is withheld is then
// decided by its rule, from its name and its value.
//
// Two things pull against each other here. A credential kept is a leak.
// A value withheld that was no credential makes the object one a restore
// refuses without the cluster it came from, which a rebuild after a loss
// does not have. So the rules for free-form values (Helm values) withhold
// on a name that says a credential, and keep what only names a thing: a
// Secret's name, a key in it, a toleration's key.

// --- URLs ---

var (
	// urlRE is a URL's scheme and what follows up to a space or a quote.
	urlRE = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*)://([^\s"'<>]+)`)
	// urlQueryRE is a credential given as a query parameter.
	urlQueryRE = regexp.MustCompile(`(?i)[?&](access_token|token|api_?key|password|passwd|secret|sig|signature)=[^&\s"'#]+`)
	// bearerRE is the value of an Authorization header.
	bearerRE = regexp.MustCompile(`(?i)^\s*(bearer|basic|token)\s+\S{8,}\s*$`)
	// tokenPrefixRE are how well-known tokens start.
	tokenPrefixRE = regexp.MustCompile(`^(gh[pousr]_|github_pat_|glpat-|xox[abps]-|pat-)`)
	digitsRE      = regexp.MustCompile(`^[0-9]+$`)
)

// tokenShaped reports a name in a URL that reads as a token and not as an
// account: long with letters and digits, or starting as a known token
// does. "git", "deploy" and an organisation's name are accounts.
func tokenShaped(name string) bool {
	if tokenPrefixRE.MatchString(name) {
		return true
	}
	return len(name) >= 20 && strings.ContainsAny(name, "0123456789") && strings.ContainsAny(strings.ToLower(name), "abcdefghijklmnopqrstuvwxyz")
}

// hostLike reports text that reads as a host: it has a dot or a port, or
// is localhost.
func hostLike(s string) bool {
	return s == "localhost" || strings.ContainsAny(s, ".:")
}

// urlCredential reports a URL with a credential in it, anywhere in the
// value: a credential whatever the variable is called, even a *_URL.
//
//   - a password (postgres://u:p@host, redis://:p@host), though it has a
//     slash in it (which is written, though it should not be)
//   - a name and no password that reads as a token (https://<token>@host
//     is how one is given to a Git host). A short name is the account, as
//     in ssh://git@host and https://org@host, and is kept.
//   - a credential as a query parameter (?token=, ?access_token=, ?sig=)
//
// Not caught, and said in the guide: a token as a name that is short, and
// a password that starts with digits and a slash for a host with no dot
// in its name, which reads as a port and a path.
func urlCredential(value string) bool {
	for _, m := range urlRE.FindAllStringSubmatch(value, -1) {
		rest := m[2]
		if urlQueryRE.MatchString(rest) {
			return true
		}
		authority := rest
		if i := strings.IndexAny(rest, "/?#"); i >= 0 {
			authority = rest[:i]
		}
		if at := strings.LastIndex(authority, "@"); at >= 0 {
			user, pass, hasPass := strings.Cut(authority[:at], ":")
			if hasPass && pass != "" {
				return true
			}
			if tokenShaped(user) {
				return true
			}
			continue
		}
		// No "@" before the first slash. A password with a slash in it
		// puts the "@" after one: scheme://user:pa/ss@host. A port and a
		// path with an "@" in it look the same (https://host:443/@scope/x),
		// so it takes a user with no dot in it and, where what follows the
		// colon is digits, something that reads as a host after the "@".
		if strings.HasPrefix(authority, "[") {
			continue // an IPv6 host has colons of its own
		}
		user, first, ok := strings.Cut(authority, ":")
		at := strings.LastIndex(rest, "@")
		if !ok || first == "" || at < len(authority) || strings.Contains(user, ".") {
			continue
		}
		after := rest[at+1:]
		if i := strings.IndexAny(after, "/?#"); i >= 0 {
			after = after[:i]
		}
		if !digitsRE.MatchString(first) || hostLike(after) {
			return true
		}
	}
	return false
}

// urlFields are fields that hold a URL someone may have put a credential
// in, and urlLists fields that hold several.
var (
	urlFields = map[string]bool{"url": true, "repoURL": true, "endpoint": true, "repo": true}
	urlLists  = map[string]bool{"urls": true, "sourceRepos": true}
)

// --- names of free-form values ---

var (
	valuesSeparators = regexp.MustCompile(`[.\-\[\]/\s]+`)
	valuesCamel      = regexp.MustCompile(`([a-z0-9])([A-Z])`)
	// refRE is a key under which a thing is named and not held
	// (secretKeyRef, valueFrom).
	refRE = regexp.MustCompile(`(Ref|Refs|From)$`)
	// nameShapedRE is what a Kubernetes object may be called.
	nameShapedRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
)

// valuesName is a value's name as a variable's would be written, so that
// its parts can be read: auth.token and apiKey are auth_token and api_key.
func valuesName(n string) string {
	return strings.ToLower(valuesCamel.ReplaceAllString(valuesSeparators.ReplaceAllString(n, "_"), "${1}_${2}"))
}

// What a name says of its value.
const (
	nameSilent    = iota // nothing: the value is read for a URL that signs in
	nameStrong           // a credential (password, token, apiKey)
	nameAmbiguous        // a secret, or the name of one (secret, pullSecret, secretKey)
)

// aboutNames are last parts that say the value is about a credential and
// is not one: where it is, what it is called, a setting of it.
var aboutNames = map[string]bool{}

// strongEndings are names of two parts that say a credential, where the
// last part alone ("key", "secret") only names one.
var strongEndings = map[string]bool{}

func init() {
	for _, n := range strings.Fields("id ids name names url uri endpoint host port path file dir ref type enabled disabled ttl expiry expires header issuer audience scope scopes version length seconds minutes hours days size count max min timeout interval format algorithm serializer deserializer prefix suffix mode policy level rotation") {
		aboutNames[n] = true
	}
	for _, n := range strings.Fields("api_key access_key private_key license_key licence_key encryption_key signing_key master_key shared_key account_key storage_key auth_key client_secret app_secret webhook_secret jwt_secret shared_secret session_secret cookie_secret connection_string conn_str conn_string") {
		strongEndings[n] = true
	}
}

// valuesKind reads a free-form value's name. The last part decides where
// it only names a thing: a toleration's key, passwordKey (a key in a
// Secret), secretName. "secret" and "secretKey" are either, and the value
// decides (ambiguousCredential).
func valuesKind(name string) int {
	var parts []string
	for _, p := range strings.Split(valuesName(name), "_") {
		if p != "" && !digitsRE.MatchString(p) {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return nameSilent
	}
	last := parts[len(parts)-1]
	two := last
	if len(parts) > 1 {
		two = parts[len(parts)-2] + "_" + last
	}
	switch {
	case aboutNames[last] || two == "public_key":
		return nameSilent
	case strongEndings[two] || last == "apikey":
		return nameStrong
	case two == "secret_key" || last == "secretkey" || last == "secret" || last == "secrets":
		return nameAmbiguous
	case last == "key" || last == "keys":
		return nameSilent
	}
	for _, p := range parts {
		switch {
		case strings.Contains(p, "password") || strings.Contains(p, "passwd") || strings.Contains(p, "passphrase"):
			return nameStrong
		case p == "pwd" || p == "token" || p == "tokens" || p == "credentials" || p == "credential" || p == "dsn" || p == "sas":
			return nameStrong
		case len(p) > 4 && strings.HasSuffix(p, "pass") && p != "bypass" && p != "compass":
			return nameStrong
		}
	}
	return nameSilent
}

// ambiguousCredential decides a value named "secret": the name of a
// Secret reads as an object's name, and a secret does not, or is long
// with nothing to break it up.
func ambiguousCredential(v string) bool {
	return !nameShapedRE.MatchString(v) || (len(v) >= 24 && !strings.ContainsAny(v, "-."))
}

// --- slots ---

// How a slot is judged.
const (
	ruleEnv       = iota // a variable: by credential(name, value)
	ruleURL              // only a URL that signs in, or an Authorization value
	ruleStrong           // its name says a credential
	ruleAmbiguous        // its name says a secret or the name of one
	ruleText             // a document as text: withheld whole if a credential is in it
)

// slot is one value that may be withheld: an env entry, a ConfigMap key, a
// URL, a value of what a GitOps source installs with.
type slot struct {
	path, name, value string
	set               func(string)
	rule              int
}

// withheld reports whether the slot's value is to be withheld.
func (sl slot) withheld() bool {
	v := sl.value
	if v == "" || envRefRE.MatchString(v) {
		return false
	}
	switch sl.rule {
	case ruleText:
		return textHolds(v)
	case ruleStrong:
		return !filePathRE.MatchString(v) && !templateOnlyRE.MatchString(v) && v != "true" && v != "false"
	case ruleAmbiguous:
		return urlCredential(v) || (!templateOnlyRE.MatchString(v) && ambiguousCredential(v))
	case ruleURL:
		return urlCredential(v) || bearerRE.MatchString(v)
	}
	return credential(sl.name, v)
}

// templateOnlyRE is a value that is only a template's reference to
// another: the credential is wherever that points.
var templateOnlyRE = regexp.MustCompile(`^\s*(\{\{[^{}]*\}\}|\$\{[^{}]*\}|\$\([^()]*\))\s*$`)

func ruleOf(kind int) int {
	switch kind {
	case nameStrong:
		return ruleStrong
	case nameAmbiguous:
		return ruleAmbiguous
	}
	return ruleURL
}

// pathPart is a key as a part of a slot's path. Paths are kept as a
// comma-separated list, so a comma in a key is written another way.
func pathPart(k string) string {
	return strings.NewReplacer("%", "%25", ",", "%2C").Replace(k)
}

// slots finds every value of obj that may be withheld:
//
//   - every env entry with a literal value (any list under "env" whose
//     items are {name, value}: pod templates, Argo's container and script,
//     Tekton's steps, Helm values)
//   - every key of a ConfigMap's data
//   - where a repository or a chart is read from (url, repoURL, endpoint,
//     repo, urls, sourceRepos)
//   - what a GitOps source installs with, read by each value's name: a
//     Flux HelmRelease's values and a Kustomization's postBuild
//     substitutions; an Argo CD application's or application set's
//     valuesObject, parameters (Helm's, a plugin's, jsonnet's), generator
//     elements and inputs, and its values and templatePatch as text
//   - an Argo workflow's parameters, as variables
//
// Each has a path unique within obj: a list item is named by its "name"
// where that is unique in its list, and by its index otherwise, so two
// templates that each have a container "main" setting DB_PASSWORD are two
// slots (review of #41).
func slots(obj map[string]any) []slot {
	var out []slot
	kind := strOf(obj["kind"])
	configMap := kind == "ConfigMap"
	if configMap {
		if d, ok := obj["data"].(map[string]any); ok {
			for k, v := range d {
				if s, ok := v.(string); ok {
					out = append(out, slot{path: "data[" + k + "]", name: k, value: s, set: func(x string) { d[k] = x }})
				}
			}
		}
	}
	group, _, _ := strings.Cut(strOf(obj["apiVersion"]), "/")
	argoApp := group == "argoproj.io" && (kind == "Application" || kind == "ApplicationSet")
	argoOther := group == "argoproj.io" && !argoApp
	fluxRelease := group == "helm.toolkit.fluxcd.io" && kind == "HelmRelease"
	fluxKustomization := group == "kustomize.toolkit.fluxcd.io" && kind == "Kustomization"

	// scalar is a leaf as text, if it is one a credential can be: a
	// string, or a number (a numeric password).
	scalar := func(v any) (string, bool) {
		switch x := v.(type) {
		case string:
			return x, true
		case int, int64, float64, uint64:
			return fmt.Sprint(x), true
		}
		return "", false
	}

	const (
		plain  = iota
		values // free-form values: each is read by its name
		forced // under a name that says a credential: all of it is one
	)
	var walk func(v any, path string, mode int)
	// value adds a leaf of free-form values at path, named by the key it
	// is under.
	value := func(c any, path, key string, mode int, set func(string)) bool {
		s, ok := scalar(c)
		if !ok {
			return false
		}
		rule := ruleOf(valuesKind(key))
		if mode == forced {
			rule = ruleStrong
		}
		if _, isString := c.(string); !isString && rule != ruleStrong {
			return true // a number is a credential only where its name says so
		}
		// Text of several lines under a name that says nothing is a
		// document of its own (values inside a patch): read as one.
		if rule == ruleURL && strings.Contains(s, "\n") {
			rule = ruleText
		}
		out = append(out, slot{path: path, name: key, value: s, set: set, rule: rule})
		return true
	}
	// named adds the entries of a list of {name, value}: variables (env,
	// a workflow's parameters) or, for an application, values named in
	// full (auth.token).
	named := func(c any, p string, asValues bool, skipKey bool) {
		l := list(c)
		for i, e := range l {
			m, ok := e.(map[string]any)
			if !ok {
				continue
			}
			at := p + "[" + pathPart(item(l, i)) + "]"
			name := strOf(m["name"])
			if skipKey && strings.EqualFold(name, "key") {
				continue // a workflow's input called "key" is not one
			}
			rule, kind := ruleEnv, nameSilent
			if asValues {
				kind = valuesKind(name)
				rule = ruleOf(kind)
			}
			for _, field := range []string{"value", "string"} {
				if s, isStr := m[field].(string); isStr && (field == "value" || asValues) {
					out = append(out, slot{path: at, name: name, value: s, set: func(v string) { m[field] = v }, rule: rule})
					break
				}
			}
			if !asValues {
				continue
			}
			// A plugin's parameter may be a list or a map of strings.
			if arr, isList := m["array"].([]any); isList {
				for j, e := range arr {
					if s, isStr := e.(string); isStr {
						out = append(out, slot{path: at + ".array[" + strconv.Itoa(j) + "]", name: name, value: s, set: func(v string) { arr[j] = v }, rule: rule})
					}
				}
			}
			if mm, isMap := m["map"].(map[string]any); isMap {
				for mk, mv := range mm {
					if s, isStr := mv.(string); isStr {
						r := ruleOf(valuesKind(mk))
						if kind == nameStrong {
							r = ruleStrong
						}
						out = append(out, slot{path: at + ".map." + pathPart(mk), name: mk, value: s, set: func(v string) { mm[mk] = v }, rule: r})
					}
				}
			}
		}
	}
	walk = func(v any, path string, mode int) {
		switch x := v.(type) {
		case map[string]any:
			for k, c := range x {
				p := join(path, pathPart(k))
				if configMap && path == "" && k == "data" {
					continue // its keys are slots already
				}
				s, isStr := c.(string)
				switch {
				case isStr && urlFields[k]:
					out = append(out, slot{path: p, name: k, value: s, set: func(v string) { x[k] = v }, rule: ruleURL})
					continue
				case urlLists[k]:
					if l, ok := c.([]any); ok {
						for i, e := range l {
							if es, ok := e.(string); ok {
								out = append(out, slot{path: p + "[" + strconv.Itoa(i) + "]", name: k, value: es, set: func(v string) { l[i] = v }, rule: ruleURL})
							}
						}
						continue
					}
				case k == "env":
					named(c, p, false, false)
					continue
				case argoApp && (k == "parameters" || k == "extVars" || k == "tlas") && mode == plain:
					// Name and value, the name written in full.
					if _, isList := c.([]any); isList {
						named(c, p, true, false)
						continue
					}
				case argoOther && k == "parameters":
					named(c, p, false, true)
					continue
				case argoApp && isStr && (k == "values" || k == "templatePatch"):
					// Values written as text: read for a credential, and
					// withheld whole when there is one.
					out = append(out, slot{path: p, name: k, value: s, set: func(v string) { x[k] = v }, rule: ruleText})
					continue
				}
				next := mode
				if mode == plain {
					_, isMap := c.(map[string]any)
					_, isList := c.([]any)
					switch {
					case argoApp && (k == "valuesObject" || k == "elements" || k == "input") && (isMap || isList),
						argoApp && k == "values" && isMap,
						fluxRelease && path == "spec" && k == "values",
						fluxKustomization && path == "spec.postBuild" && k == "substitute":
						// The key that opens the values names nothing itself.
						walk(c, p, values)
						continue
					}
				}
				if next == plain {
					walk(c, p, plain)
					continue
				}
				if value(c, p, k, mode, func(v string) { x[k] = v }) {
					continue
				}
				// What is under a name that says a credential is one,
				// whatever its own names; under a reference it is named.
				switch {
				case refRE.MatchString(k):
					next = values
				case valuesKind(k) == nameStrong:
					next = forced
				}
				if l, isList := c.([]any); isList {
					for i, e := range l {
						at := p + "[" + strconv.Itoa(i) + "]"
						if !value(e, at, k, next, func(v string) { l[i] = v }) {
							walk(e, at, next)
						}
					}
					continue
				}
				walk(c, p, next)
			}
		case []any:
			for i, c := range x {
				walk(c, path+"["+pathPart(item(x, i))+"]", mode)
			}
		}
	}
	walk(obj, "", plain)
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

// --- values as text ---

// textLineRE is a line of YAML that sets a key to a value on the line.
var textLineRE = regexp.MustCompile(`^\s*(?:-\s+)?["']?([A-Za-z0-9_.\-/]+)["']?\s*:\s*(.*?)\s*$`)

// textHolds reports a credential in values written as text. The text is
// read as YAML, every document of it. Text that does not read as YAML (a
// template, most often) is read line by line instead, by the same names:
// it is never kept for want of a parse.
func textHolds(text string) bool {
	dec := yaml.NewDecoder(bytes.NewReader([]byte(text)))
	var docs []any
	for {
		var doc any
		err := dec.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			return linesHold(text)
		}
		docs = append(docs, stringKeys(doc))
	}
	// As a HelmRelease's values, which are read the same way.
	probe := map[string]any{"apiVersion": "helm.toolkit.fluxcd.io/v2", "kind": "HelmRelease", "spec": map[string]any{"values": map[string]any{"documents": docs}}}
	for _, sl := range slots(probe) {
		if sl.withheld() {
			return true
		}
	}
	return false
}

// stringKeys is a decoded document with every map keyed by text, as an
// object's are: YAML allows keys that are not.
func stringKeys(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, c := range x {
			x[k] = stringKeys(c)
		}
		return x
	case map[any]any:
		out := map[string]any{}
		for k, c := range x {
			out[fmt.Sprint(k)] = stringKeys(c)
		}
		return out
	case []any:
		for i, c := range x {
			x[i] = stringKeys(c)
		}
	}
	return v
}

// linesHold reads text that is not YAML line by line: a key whose name
// says a credential with a value after it, or a URL that signs in.
func linesHold(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		if urlCredential(line) {
			return true
		}
		m := textLineRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		v := strings.Trim(m[2], `"'`)
		if v == "" || templateOnlyRE.MatchString(v) {
			continue
		}
		switch valuesKind(m[1]) {
		case nameStrong:
			if v != "true" && v != "false" {
				return true // a block that follows ("|") is taken as one too
			}
		case nameAmbiguous:
			if v != "|" && v != ">" && ambiguousCredential(v) {
				return true
			}
		}
	}
	return false
}
