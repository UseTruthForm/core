package saas

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretURL(t *testing.T) {
	for s, want := range map[string]bool{
		"https://hooks.slack.com/services/T000/B000/XXXXXXXX":   true,
		"https://discord.com/api/webhooks/123/abcdef":           true,
		"https://contoso.webhook.office.com/webhookb2/abc":      true,
		"https://ci.example.com/hook?token=abc":                 true,
		"https://user:pass@ci.example.com/hook":                 true,
		"https://ci.example.com/hook":                           false,
		"https://ci.example.com/hook?ref=main":                  false,
		"https://example.com/hooks.slack.com/services/x":        false,
		"hooks.slack.com/services/T/B/x (not a URL, no scheme)": false,
	} {
		if got := secretURL(s); got != want {
			t.Errorf("%q: got %v, want %v", s, got, want)
		}
	}
}

const slack = "https://hooks.slack.com/services/T0001/B0001/s3cr3tT0k3n"

// A webhook posting to Slack: its URL is the credential, so no snapshot
// file, body or file name holds it; the hook is named by host and hash, a
// restore without the URL refuses, and with it creates the hook.
func TestCredentialWebhookURLIsSecret(t *testing.T) {
	s := spec(t, "github.json")
	src, dst := newFake(t, GitHub, s, "acme-src"), newFake(t, GitHub, s, "acme-dst")
	gitHub(src)
	gitHub(dst)
	src.seed(t, "/orgs/acme-src/repos", map[string]any{"name": "shop"})
	src.seed(t, "/repos/acme-src/shop/hooks", map[string]any{"name": "web", "active": true, "events": []any{"push"},
		"config": map[string]any{"url": slack, "content_type": "json"}})
	snap, err := (&Adapter{Client: src.client(true)}).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := snap.Write(dir); err != nil {
		t.Fatal(err)
	}
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			b, _ := os.ReadFile(p)
			if strings.Contains(string(b), "s3cr3tT0k3n") || strings.Contains(p, "s3cr3tT0k3n") {
				t.Errorf("%s holds the webhook token", p)
			}
		}
		return err
	})
	var key, name string
	for _, o := range snap.Objects {
		if o.Kind() == "github/webhook" {
			key, name = o.Key(), o.Name()
			ann := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
			if !strings.Contains(ann[annSecrets].(string), "config.url") {
				t.Errorf("secrets annotation %v does not name config.url", ann[annSecrets])
			}
		}
	}
	if !strings.HasPrefix(name, "shop/hooks.slack.com~") {
		t.Fatalf("webhook named %q, want host and hash", name)
	}
	for _, r := range (&Adapter{Client: dst.client(false)}).Restore(context.Background(), snap) {
		if r.Key == key && (r.OK || !strings.Contains(r.Detail, "needs config.url")) {
			t.Errorf("restored without its URL: ok=%v %s", r.OK, r.Detail)
		}
	}
	vals := map[string]map[string]any{"github/webhook/" + name: {"config": map[string]any{"url": slack}}}
	for _, r := range (&Adapter{Client: dst.client(false), Options: RestoreOptions{Values: vals}}).Restore(context.Background(), snap) {
		if !r.OK {
			t.Errorf("%s: %s", r.Key, r.Detail)
		}
	}
	if hooks := dst.colls["/repos/acme-dst/shop/hooks"]; len(hooks) != 1 || hooks[0]["config"].(map[string]any)["url"] != slack {
		t.Errorf("target hooks %v: the supplied URL did not arrive", hooks)
	}
}

// A write sends write-only fields; only a capture drops them. Reduced the
// capture's way, a supplied write-only value never reached the API.
func TestWritesKeepWriteOnly(t *testing.T) {
	f := &Fields{Children: map[string]*Fields{"name": {}, "token": {WriteOnly: true}}}
	got, _ := forWrite(map[string]any{"name": "x", "token": "t"}, f)
	if got.(map[string]any)["token"] != "t" {
		t.Errorf("write dropped the write-only field: %v", got)
	}
	var masked []string
	kept, _ := keep(map[string]any{"name": "x", "token": "t"}, f, "", &masked)
	if _, ok := kept.(map[string]any)["token"]; ok || len(masked) != 1 {
		t.Errorf("capture kept a write-only field: %v %v", kept, masked)
	}
}
