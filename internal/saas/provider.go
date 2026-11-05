package saas

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Provider describes one SaaS: where its API is, its response conventions,
// and which collections hold configuration. It is data; the engine has no
// code for any provider.
type Provider struct {
	Name string
	// Spec is the OpenAPI description's file name in the spec directory,
	// and SpecURL where the provider publishes it.
	Spec    string
	SpecURL string
	// Base is the API root; tests point it at a local server.
	Base string
	// Envelope is the field that wraps every response (Cloudflare's
	// "result"), or "" when responses are bare (GitHub).
	Envelope string
	// Paging is "link" (an RFC 8288 Link header, rel="next") or "page"
	// (page/per_page with result_info.total_pages).
	Paging string
	// PageSize is per_page (100 unless set; Cloudflare's /zones allows 50).
	PageSize int
	// Account names what a target points at (a GitHub organisation, a
	// Cloudflare account ID). Its value is tokenized out of every spec.
	Account string
	// Headers are sent with every request (API version, media type).
	Headers map[string]string
	// TokenEnv is the environment variable holding the API token.
	TokenEnv string
	// OAuth is the provider's sign-in for a person, used when TokenEnv is
	// not set; nil where only a token works.
	OAuth *OAuth
	// Unavailable are messages with which the provider refuses a feature
	// the account's plan does not include. Such a collection is recorded
	// as not available, not as a failed read: GitHub answers rulesets on a
	// private repository of a free organisation with "Upgrade to GitHub
	// Pro" (seen capturing StackDNA, 2026-10-22).
	Unavailable []string
	Collections []Collection
	// Derive, if set, adds the collections the description offers under
	// these rules to the hand-written ones.
	Derive *DeriveRules
}

// Collection is one kind of configuration. Paths are the description's
// own templates; Bind fills their parameters:
//
//	"account"        the target's account
//	"parent:<field>" a field of the parent item (repo name for its labels)
//	"item:<field>"   a field of the item itself (an ID to read it by)
type Collection struct {
	Kind   string
	Parent string
	List   string
	Get    string // optional: a full read when List returns summaries
	Create string // POST
	Update string // optional PATCH, for fields the create does not take
	Bind   map[string]string
	// Name is the fields that name an item; joined with " ".
	Name []string
	// Array is the property holding the items when a list is wrapped
	// ({"total_count": 2, "variables": [...]}); "" for a bare array.
	Array string
	// CreateMethod is POST (to Create) or PUT (to Create, an item path:
	// GitHub creates environments and secrets with PUT .../{name}).
	CreateMethod string
	// UpdateMethod is PATCH unless set.
	UpdateMethod string
	// ListQuery adds query parameters to the list, bound like path
	// parameters ("account.id": "account"). Cloudflare's /zones lists every
	// account the token can see; without the filter, --account limited
	// nothing and another account's zones landed in the snapshot (review,
	// 2026-10-22).
	ListQuery map[string]string
	// Singleton is settings with no list: GET and PUT on one path
	// (Actions permissions). Captured as one item named "settings"; a
	// restore applies it, since the target always has some value.
	Singleton bool
	// Transient names, for a listed item that is not configuration but a
	// moment's state, why it is left out; "" keeps it. Such an item is
	// neither captured nor counted, so a capture taken mid-way through it
	// equals one taken before; the rule is stated in docs/guide.md.
	Transient func(item map[string]any) string
}

// listPath is the list's path for a parent, with its query.
func (c *Collection) listPath(account string, parent map[string]any) (string, bool) {
	p, ok := expand(c.List, c.Bind, account, parent, nil)
	if !ok || len(c.ListQuery) == 0 {
		return p, ok
	}
	q := url.Values{}
	for _, k := range sortedKeys(c.ListQuery) {
		v, ok := expand("{"+k+"}", map[string]string{k: c.ListQuery[k]}, account, parent, nil)
		if !ok {
			return "", false
		}
		q.Set(k, v)
	}
	return p + "?" + q.Encode(), true
}

func (c *Collection) createMethod() string {
	if c.CreateMethod != "" {
		return c.CreateMethod
	}
	return "POST"
}

func (c *Collection) updateMethod() string {
	if c.UpdateMethod != "" {
		return c.UpdateMethod
	}
	return "PATCH"
}

// GitHub is the descriptor for github.com organisations.
var GitHub = Provider{
	Name: "github", Spec: "github.json", Base: "https://api.github.com", Paging: "link", Account: "org",
	SpecURL:  "https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json",
	Headers:  map[string]string{"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
	TokenEnv: "GITHUB_TOKEN",
	Unavailable: []string{"Upgrade to GitHub Pro", "Upgrade to GitHub Team", "Upgrade to GitHub Enterprise",
		// A setting that does not apply to this repository.
		"is not allowed for private repositories"},
	Derive: GitHubDerive,
	Collections: []Collection{
		{Kind: "github/repository", List: "/orgs/{org}/repos", Get: "/repos/{owner}/{repo}",
			Create: "/orgs/{org}/repos", Update: "/repos/{owner}/{repo}",
			Bind: map[string]string{"org": "account", "owner": "account", "repo": "item:name"}, Name: []string{"name"}},
		{Kind: "github/label", Parent: "github/repository", List: "/repos/{owner}/{repo}/labels", Create: "/repos/{owner}/{repo}/labels",
			Update: "/repos/{owner}/{repo}/labels/{name}",
			Bind:   map[string]string{"owner": "account", "repo": "parent:name", "name": "item:name"}, Name: []string{"name"}},
		{Kind: "github/webhook", Parent: "github/repository", List: "/repos/{owner}/{repo}/hooks", Get: "/repos/{owner}/{repo}/hooks/{hook_id}",
			Create: "/repos/{owner}/{repo}/hooks", Update: "/repos/{owner}/{repo}/hooks/{hook_id}",
			Bind: map[string]string{"owner": "account", "repo": "parent:name", "hook_id": "item:id"}, Name: []string{"config.url"}},
		{Kind: "github/ruleset", Parent: "github/repository", List: "/repos/{owner}/{repo}/rulesets", Get: "/repos/{owner}/{repo}/rulesets/{ruleset_id}",
			Create: "/repos/{owner}/{repo}/rulesets", Update: "/repos/{owner}/{repo}/rulesets/{ruleset_id}", UpdateMethod: "PUT",
			Bind: map[string]string{"owner": "account", "repo": "parent:name", "ruleset_id": "item:id"}, Name: []string{"name"}},
	},
}

// CloudflareClientID is StackDNA's registered Cloudflare OAuth client. It
// is public (PKCE, no secret); a build without it signs in by token only.
var CloudflareClientID = ""

// Cloudflare is the descriptor for a Cloudflare account's zones and DNS.
var Cloudflare = Provider{
	Name: "cloudflare", Spec: "cloudflare.json", Base: "https://api.cloudflare.com/client/v4", Envelope: "result", Paging: "page", PageSize: 50,
	SpecURL: "https://raw.githubusercontent.com/cloudflare/api-schemas/main/openapi.json",
	Account: "account", TokenEnv: "CLOUDFLARE_API_TOKEN",
	OAuth: &OAuth{ClientID: CloudflareClientID,
		AuthURL: "https://dash.cloudflare.com/oauth2/auth", TokenURL: "https://dash.cloudflare.com/oauth2/token",
		// What capture, diff and restore of zones and DNS records need, and
		// a refresh token so a sign-in outlives its hour.
		Scopes: []string{"zone:read", "dns_records:read", "dns_records:edit", "offline_access"},
		Ports:  []int{8976, 8977}},
	Collections: []Collection{
		{Kind: "cloudflare/zone", List: "/zones", Create: "/zones", Update: "/zones/{zone_id}", ListQuery: map[string]string{"account.id": "account"},
			Bind: map[string]string{"zone_id": "item:id"}, Name: []string{"name"}},
		// One name can hold several records, so type, name and content
		// together name a record.
		{Kind: "cloudflare/dns_record", Parent: "cloudflare/zone", List: "/zones/{zone_id}/dns_records",
			Get: "/zones/{zone_id}/dns_records/{dns_record_id}", Create: "/zones/{zone_id}/dns_records", Update: "/zones/{zone_id}/dns_records/{dns_record_id}",
			Bind: map[string]string{"zone_id": "parent:id", "dns_record_id": "item:id"}, Name: []string{"type", "name", "content"},
			Transient: acmeChallenge},
	},
}

// acmeChallenge is a DNS-01 challenge record. cert-manager (and any ACME
// client) adds a TXT record at _acme-challenge.<name> to prove it holds
// the domain, and removes it minutes later. Captured, a snapshot taken
// during a renewal would differ from one taken after, and a restore
// would put back a stale challenge. A CNAME there is kept: delegating
// _acme-challenge to another zone is lasting configuration.
func acmeChallenge(item map[string]any) string {
	t, _ := item["type"].(string)
	n, _ := item["name"].(string)
	if strings.EqualFold(t, "TXT") && (strings.EqualFold(n, "_acme-challenge") || strings.HasPrefix(strings.ToLower(n), "_acme-challenge.")) {
		return "ACME DNS-01 challenge record, made and removed by cert-manager or another ACME client during a certificate renewal"
	}
	return ""
}

// Providers lists the providers by name.
var Providers = map[string]Provider{"github": GitHub, "cloudflare": Cloudflare}

var paramRE = regexp.MustCompile(`\{([^}]+)\}`)

// expand fills a path template.
func expand(tmpl string, bind map[string]string, account string, parent, item map[string]any) (string, bool) {
	ok := true
	out := paramRE.ReplaceAllStringFunc(tmpl, func(m string) string {
		src := bind[m[1:len(m)-1]]
		var v any
		switch {
		case src == "account":
			v = account
		case strings.HasPrefix(src, "parent:"):
			v = field(parent, src[len("parent:"):])
		case strings.HasPrefix(src, "item:"):
			v = field(item, src[len("item:"):])
		}
		s := stringOf(v)
		if s == "" {
			ok = false
		}
		// One path segment: a label named "area/api" went out as
		// .../labels/area/api and found nothing.
		return url.PathEscape(s)
	})
	return out, ok
}

// field reads a dotted path.
func field(m map[string]any, path string) any {
	var cur any = m
	for _, p := range strings.Split(path, ".") {
		cm, _ := cur.(map[string]any)
		if cm == nil {
			return nil
		}
		cur = cm[p]
	}
	return cur
}

// stringOf renders a path value. JSON numbers decode as float64; an ID
// like 12345 must expand as "12345", not "12345.0" or "1.2345e+04".
func stringOf(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return ""
}
