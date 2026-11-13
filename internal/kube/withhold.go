package kube

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// What is withheld from an object that is not a Secret: a credential set
// as plain configuration. Each candidate is a slot, found by where it is
// and never by what it holds, so that a restore finds the same slots in a
// snapshot whose values are gone; whether a slot is withheld is then
// decided from its name and its value.
//
// Helm values (a HelmRelease's, an application's valuesObject and values
// text) are not read here beyond the variables in them: telling a
// credential from the name of one by a value's name alone fails both
// ways, and a value withheld that was no credential makes the object one
// a restore refuses without the cluster it came from.

// --- URLs ---

var (
	// urlRE is a URL's scheme and what follows.
	// Up to a space and nothing sooner: a password has quotes and angle
	// brackets in it as readily as letters.
	urlRE = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*)://(\S+)`)
	// urlQueryRE is a credential given as a query parameter.
	urlQueryRE = regexp.MustCompile(`(?i)[?&#;](access_token|private_token|client_secret|token|api_?key|password|passwd|pwd|secret|sig|signature)=[^&;\s"'#]+`)
	// bearerRE is the value of an Authorization header.
	// What follows the word is a token's shape: long, with a digit in it
	// ("Basic authentication" is prose).
	bearerRE = regexp.MustCompile(`(?i)^\s*(bearer|basic|token)\s+([A-Za-z0-9._~+/-]*[0-9][A-Za-z0-9._~+/-]*=*)\s*$`)
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
		// The "@" of a password is before any question: one after it is
		// in what is asked (?mail=ops@example.com).
		if i := strings.IndexAny(rest, "?#"); i >= 0 {
			rest = rest[:i]
		}
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

// bearer reports the value of an Authorization header: the word, and a
// token of some length after it.
func bearer(value string) bool {
	m := bearerRE.FindStringSubmatch(value)
	return m != nil && len(m[2]) >= 16
}

// --- slots ---

// slot is one value that may be withheld: an env entry, a ConfigMap key,
// a URL, an Argo CD application's parameter.
type slot struct {
	path, name, value string
	set               func(string)
	// url: the name says nothing, and only a URL that signs in is
	// withheld.
	url bool
}

// withheld reports whether the slot's value is to be withheld.
func (sl slot) withheld() bool {
	if sl.url {
		return urlCredential(sl.value)
	}
	return credential(sl.name, sl.value)
}

// slots finds every value of obj that may be withheld:
//
//   - every env entry with a literal value (any list under "env" whose
//     items are {name, value}: pod templates, Argo's container and script,
//     Tekton's steps, a HelmRelease's values)
//   - every key of a ConfigMap's data
//   - where a repository or a chart is read from (url, repoURL, endpoint,
//     repo, urls, sourceRepos): only a URL that signs in
//   - an Argo CD application's or application set's parameters, which are
//     name and value as env is
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
	// Only an application's: a workflow's parameters are its inputs.
	argoApp := group == "argoproj.io" && (kind == "Application" || kind == "ApplicationSet")
	var walk func(v any, path string)
	walk = func(v any, path string) {
		switch x := v.(type) {
		case map[string]any:
			for k, c := range x {
				p := join(path, k)
				if configMap && path == "" && k == "data" {
					continue // its keys are slots already
				}
				if s, isStr := c.(string); isStr && urlFields[k] {
					out = append(out, slot{path: p, name: k, value: s, set: func(v string) { x[k] = v }, url: true})
					continue
				}
				if l, isList := c.([]any); isList && urlLists[k] {
					for i, e := range l {
						if s, isStr := e.(string); isStr {
							out = append(out, slot{path: p + "[" + strconv.Itoa(i) + "]", name: k, value: s, set: func(v string) { l[i] = v }, url: true})
						}
					}
					continue
				}
				if k == "env" || (k == "parameters" && argoApp) {
					for i, e := range list(c) {
						m, ok := e.(map[string]any)
						s, isStr := m["value"].(string)
						if ok && isStr {
							out = append(out, slot{path: p + "[" + item(list(c), i) + "]", name: strOf(m["name"]), value: s, set: func(v string) { m["value"] = v }})
						}
					}
					continue
				}
				walk(c, p)
			}
		case []any:
			for i, c := range x {
				walk(c, path+"["+item(x, i)+"]")
			}
		}
	}
	walk(obj, "")
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}
