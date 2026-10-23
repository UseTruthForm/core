package saas

import (
	"sort"
	"strings"
)

// DeriveRules turn a provider's OpenAPI description into collections, so
// coverage follows the API instead of a list in code. The rules are data:
// which path scopes to look in, and which categories are configuration
// rather than activity.
type DeriveRules struct {
	Scopes []Scope
	// Categories are configuration categories (x-github.category), each
	// with the subcategories to leave out ("*" in Allow means all of it).
	Allow map[string][]string
	Deny  map[string][]string
}

// Scope is a path prefix whose collections hang off a parent: every
// /repos/{owner}/{repo}/... collection belongs to a repository.
type Scope struct {
	Name   string // "repo", "org": the kind prefix
	Prefix string
	Parent string
	Bind   map[string]string
}

// GitHubDerive covers what GitHub's description groups as configuration:
// Actions settings, variables and secrets, environments, repository and
// organisation rules, custom properties, autolinks and deploy keys. Runs,
// jobs, artifacts, caches, runners and everything people produce (issues,
// pulls, comments, releases) are activity, not configuration.
var GitHubDerive = &DeriveRules{
	Scopes: []Scope{
		{Name: "repo", Prefix: "/repos/{owner}/{repo}/", Parent: "github/repository", Bind: map[string]string{"owner": "account", "repo": "parent:name"}},
		{Name: "org", Prefix: "/orgs/{org}/", Bind: map[string]string{"org": "account"}},
	},
	Allow: map[string][]string{
		"actions": {"*"}, "deployments": {"*"}, "repos": {"*"}, "orgs": {"*"}, "dependabot": {"*"},
		"code-security": {"*"}, "pages": {"*"}, "teams": {"*"},
	},
	Deny: map[string][]string{
		"actions":     {"workflow-runs", "workflow-jobs", "artifacts", "cache", "self-hosted-runners", "workflows", "oidc"},
		"orgs":        {"members", "outside-collaborators", "personal-access-tokens", "api-insights", "issue-types", "artifact-metadata", "attestations", "bypass-requests", "orgs"},
		"repos":       {"repos", "contents", "statistics", "traffic", "forks", "attestations", "bypass-requests"},
		"deployments": {"deployments", "statuses"},
	},
}

// Derive returns the collections a description offers under the rules,
// leaving out any whose list path a hand-written collection already has.
func Derive(s *Spec, r *DeriveRules, have []Collection) []Collection {
	taken := map[string]bool{}
	for _, c := range have {
		taken[c.List] = true
	}
	paths, _ := s.doc["paths"].(map[string]any)
	var out []Collection
	for _, path := range sortedKeys(paths) {
		if taken[path] {
			continue
		}
		var scope *Scope
		for i := range r.Scopes {
			if strings.HasPrefix(path, r.Scopes[i].Prefix) {
				scope = &r.Scopes[i]
			}
		}
		get := s.operation(path, "get")
		if scope == nil || get == nil || !r.allowed(get) {
			continue
		}
		rest := strings.TrimPrefix(path, scope.Prefix)
		if strings.Contains(rest, "{") {
			continue // nested under another item; not followed yet
		}
		kind := "github/" + scope.Name + "/" + rest
		resp := s.ResponseSchema(path, "get")
		arr, isList := listShape(s, resp)
		bind := copyBind(scope.Bind)
		switch {
		case isList:
			c := Collection{Kind: kind, Parent: scope.Parent, List: path, Array: arr, Bind: bind}
			item, param := itemPath(s, path)
			switch {
			case s.Has(path, "post"):
				c.Create, c.CreateMethod = path, "POST"
			case item != "" && s.Has(item, "put"):
				c.Create, c.CreateMethod = item, "PUT"
			default:
				continue // listed but never created through the API
			}
			if item != "" && s.Has(item, "get") {
				c.Get = item
			}
			if item != "" && s.Has(item, "patch") {
				c.Update = item
			}
			itemSchema := s.ResponseSchema(item, "get")
			if itemSchema == nil {
				itemSchema = s.resolve(listItems(s, resp, arr))
			}
			c.Name = nameField(s, itemSchema)
			// Named only by a server ID, an item names something else in
			// every account; and a collection keyed by another resource's
			// ID (permissions/repositories/{repository_id}) would restore
			// the source's IDs. Neither is portable, so neither is derived.
			if c.Name[0] == "id" || (c.CreateMethod == "PUT" && strings.HasSuffix(param, "_id")) {
				continue
			}
			if param != "" {
				c.Bind[param] = "item:" + paramField(param, c.Name)
			}
			out = append(out, c)
		case s.Has(path, "put") || s.Has(path, "patch"):
			m := "PUT"
			if !s.Has(path, "put") {
				m = "PATCH"
			}
			out = append(out, Collection{Kind: kind, Parent: scope.Parent, List: path, Get: "", Create: path, CreateMethod: m, Singleton: true, Bind: bind})
		}
	}
	return out
}

func (r *DeriveRules) allowed(op map[string]any) bool {
	xg, _ := op["x-github"].(map[string]any)
	cat, _ := xg["category"].(string)
	sub, _ := xg["subcategory"].(string)
	subs, ok := r.Allow[cat]
	if !ok {
		return false
	}
	for _, d := range r.Deny[cat] {
		if d == sub {
			return false
		}
	}
	for _, a := range subs {
		if a == "*" || a == sub {
			return true
		}
	}
	return false
}

// listShape reports a list response: a bare array, or an object whose one
// array property holds the items ({total_count, variables: [...]}).
func listShape(s *Spec, resp map[string]any) (string, bool) {
	if resp == nil {
		return "", false
	}
	if t, _ := resp["type"].(string); t == "array" {
		return "", true
	}
	props, _ := resp["properties"].(map[string]any)
	var arrays []string
	for k, v := range props {
		if t, _ := s.resolve(v)["type"].(string); t == "array" {
			arrays = append(arrays, k)
		}
	}
	if len(arrays) == 1 {
		return arrays[0], true
	}
	return "", false
}

func listItems(s *Spec, resp map[string]any, arr string) any {
	if arr == "" {
		return resp["items"]
	}
	props, _ := resp["properties"].(map[string]any)
	return s.resolve(props[arr])["items"]
}

// itemPath finds the path of one item under a collection: path/{param}.
func itemPath(s *Spec, path string) (string, string) {
	paths, _ := s.doc["paths"].(map[string]any)
	var found []string
	for p := range paths {
		rest := strings.TrimPrefix(p, path+"/")
		if rest != p && strings.HasPrefix(rest, "{") && strings.HasSuffix(rest, "}") && !strings.Contains(rest, "/") {
			found = append(found, p)
		}
	}
	sort.Strings(found)
	if len(found) != 1 {
		return "", ""
	}
	rest := strings.TrimPrefix(found[0], path+"/")
	return found[0], rest[1 : len(rest)-1]
}

// nameField picks the field that names an item. A server-assigned id is
// the last resort, and is not portable between accounts.
func nameField(s *Spec, item map[string]any) []string {
	props, _ := s.resolve(item)["properties"].(map[string]any)
	for _, f := range []string{"name", "property_name", "key", "title", "key_prefix", "login", "pattern", "slug"} {
		if _, ok := props[f]; ok {
			return []string{f}
		}
	}
	return []string{"id"}
}

// paramField says which item field fills an item path's parameter:
// {name} is name, {environment_name} is name, {hook_id} is id.
func paramField(param string, name []string) string {
	switch {
	case strings.HasSuffix(param, "_id"):
		return "id"
	case strings.HasSuffix(param, "_name") || param == "name":
		return "name"
	}
	if len(name) == 1 {
		return name[0]
	}
	return param
}

func copyBind(m map[string]string) map[string]string {
	c := make(map[string]string, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}
