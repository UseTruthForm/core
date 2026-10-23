package saas

import (
	"context"
	"strings"
	"testing"

	"github.com/stackdna/core/internal/drilltest"
	"github.com/stackdna/core/internal/platform"
)

var _ platform.Platform = (*Adapter)(nil)

func spec(t *testing.T, name string) *Spec {
	t.Helper()
	s, err := LoadSpec("../../testdata/saas/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// gitHub makes a fake organisation behave as GitHub does beyond the
// description: a repository gets an owner and counters, and is created
// with GitHub's default labels.
func gitHub(f *fake) {
	f.onCreate = func(f *fake, kind string, it map[string]any) {
		if kind != "github/repository" {
			return
		}
		it["owner"] = map[string]any{"login": f.account}
		it["stargazers_count"] = float64(0)
		labels := "/repos/" + f.account + "/" + stringOf(it["name"]) + "/labels"
		for _, l := range []string{"bug", "enhancement"} {
			f.seq++
			f.colls[labels] = append(f.colls[labels], map[string]any{"id": float64(f.seq), "name": l, "color": "d73a4a", "description": "default", "default": true})
		}
	}
}

func TestGitHubDrill(t *testing.T) {
	s := spec(t, "github.json")
	src, dst := newFake(t, GitHub, s, "acme-src"), newFake(t, GitHub, s, "acme-dst")
	dst.others = []string{"acme-src"}
	gitHub(src)
	gitHub(dst)
	// The description names the organisation in prose; it must survive
	// unchanged (the StackDNA organisation's repositories do this).
	src.seed(t, "/orgs/acme-src/repos", map[string]any{"name": "shop", "description": "acme-src shop: the storefront", "private": true, "has_wiki": false,
		"homepage": "https://github.com/acme-src/shop"})
	src.seed(t, "/repos/acme-src/shop/labels", map[string]any{"name": "priority", "color": "ff0000", "description": "do first"})
	src.seed(t, "/repos/acme-src/shop/hooks", map[string]any{"name": "web", "active": true, "events": []any{"push"},
		"config": map[string]any{"url": "https://ci.example.com/hook", "content_type": "json", "secret": "s3cr3t-hook"}})
	src.seed(t, "/repos/acme-src/shop/rulesets", map[string]any{"name": "protect-main", "target": "branch", "enforcement": "active",
		"conditions": map[string]any{"ref_name": map[string]any{"include": []any{"~DEFAULT_BRANCH"}, "exclude": []any{}}},
		"rules":      []any{map[string]any{"type": "deletion"}}})

	vals := map[string]map[string]any{"github/webhook/shop/https://ci.example.com/hook": {"config": map[string]any{"secret": "s3cr3t-hook"}}}
	snap := drilltest.Run(t, drilltest.Spec{
		Source: &Adapter{Client: src.client(true)},
		Target: &Adapter{Client: dst.client(false), Options: RestoreOptions{Values: vals}},
		ExpectKeys: []string{
			APIVersion + "|github/repository||shop",
			APIVersion + "|github/label||shop/bug",
			APIVersion + "|github/label||shop/enhancement",
			APIVersion + "|github/label||shop/priority",
			APIVersion + "|github/webhook||shop/https://ci.example.com/hook",
			APIVersion + "|github/ruleset||shop/protect-main",
		},
	})
	repo := dst.colls["/orgs/acme-dst/repos"][0]
	if repo["description"] != "acme-src shop: the storefront" || repo["homepage"] != "https://github.com/acme-dst/shop" {
		t.Errorf("prose must survive, URL segments must follow the account: %v / %v", repo["description"], repo["homepage"])
	}
	for _, o := range snap.Objects {
		body := canon(o.Body)
		for _, bad := range []string{"s3cr3t-hook", "stargazers_count", "created_at", "node_id"} {
			if strings.Contains(body, bad) {
				t.Errorf("%s holds %q: %s", o.Key(), bad, body)
			}
		}
	}
	// The hook secret was never captured, and still reached the target.
	hook := dst.colls["/repos/acme-dst/shop/hooks"][0]
	if hook["config"].(map[string]any)["secret"] != "s3cr3t-hook" {
		t.Error("webhook secret did not arrive")
	}
	// Without the value, the restore says what it was not given.
	empty := newFake(t, GitHub, s, "acme-empty")
	gitHub(empty)
	for _, r := range (&Adapter{Client: empty.client(false)}).Restore(context.Background(), snap) {
		if strings.Contains(r.Key, "webhook") && !strings.Contains(r.Detail, "secret, not supplied: config.secret") {
			t.Errorf("webhook restored without saying its secret was missing: %s", r.Detail)
		}
	}
}

// A feature the plan lacks is not a failed read: the capture is complete
// and says what was not available (rulesets on a free plan's private repo).
func TestPlanUnavailableIsNotAFailure(t *testing.T) {
	s := spec(t, "github.json")
	f := newFake(t, GitHub, s, "acme")
	gitHub(f)
	f.seed(t, "/orgs/acme/repos", map[string]any{"name": "shop"})
	f.refuse = map[string]string{"/rulesets": "Upgrade to GitHub Pro or make this repository public to enable this feature."}
	snap, err := (&Adapter{Client: f.client(true)}).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range snap.Coverage {
		if c.Kind == "github/ruleset" && !strings.HasPrefix(c.NotCaptured, "not available on this account's plan") {
			t.Errorf("ruleset coverage %q", c.NotCaptured)
		}
		if strings.HasPrefix(c.NotCaptured, "list failed") {
			t.Errorf("%s reported as a failure: %s", c.Kind, c.NotCaptured)
		}
	}
}

func cloudflare(f *fake) {
	f.onCreate = func(f *fake, kind string, it map[string]any) {
		if kind == "cloudflare/zone" {
			it["account"] = map[string]any{"id": f.account, "name": "acct"}
			it["status"] = "pending"
		}
	}
}

func TestCloudflareDrill(t *testing.T) {
	s := spec(t, "cloudflare.json")
	src, dst := newFake(t, Cloudflare, s, "acct-src-1111"), newFake(t, Cloudflare, s, "acct-dst-2222")
	dst.others = []string{"acct-src-1111"}
	cloudflare(src)
	cloudflare(dst)
	zone := src.seed(t, "/zones", map[string]any{"name": "example.com", "type": "full", "account": map[string]any{"id": "acct-src-1111"}})
	zid := stringOf(zone["id"])
	for _, r := range []map[string]any{
		{"type": "A", "name": "www.example.com", "content": "192.0.2.1", "ttl": 300, "proxied": false},
		{"type": "A", "name": "www.example.com", "content": "192.0.2.2", "ttl": 300, "proxied": false},
		{"type": "CNAME", "name": "api.example.com", "content": "www.example.com", "ttl": 1, "proxied": true},
	} {
		src.seed(t, "/zones/"+zid+"/dns_records", r)
	}
	drilltest.Run(t, drilltest.Spec{
		Source: &Adapter{Client: src.client(true)},
		Target: &Adapter{Client: dst.client(false)},
		ExpectKeys: []string{
			APIVersion + "|cloudflare/zone||example.com",
			APIVersion + "|cloudflare/dns_record||example.com/A www.example.com 192.0.2.1",
			APIVersion + "|cloudflare/dns_record||example.com/A www.example.com 192.0.2.2",
			APIVersion + "|cloudflare/dns_record||example.com/CNAME api.example.com www.example.com",
		},
	})
}

// What a write accepts is what a capture keeps; the rest is the server's.
func TestWritesDecideWhatIsKept(t *testing.T) {
	s := spec(t, "github.json")
	c := NewClient(GitHub, s, "o", "", true)
	w := c.writes(&GitHub.Collections[0])
	var masked []string
	kept, _ := keep(map[string]any{"name": "r", "description": "d", "stargazers_count": 3, "created_at": "t",
		"allow_squash_merge": false, "owner": map[string]any{"login": "o"}}, w, "", &masked)
	k := kept.(map[string]any)
	if k["name"] != "r" || k["allow_squash_merge"] != false {
		t.Errorf("configuration dropped: %v", k)
	}
	for _, f := range []string{"stargazers_count", "created_at", "owner"} {
		if _, ok := k[f]; ok {
			t.Errorf("server-computed %s kept", f)
		}
	}
}
