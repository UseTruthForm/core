package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/saas"
)

// A dry run anywhere else would apply everything it was meant to list.
func TestDryRunRefusedWhereARestoreWouldWrite(t *testing.T) {
	for _, p := range []string{"aws", "azure", "gcp", "kubernetes"} {
		if dryRunAccepted(p, true) == nil {
			t.Errorf("--dry-run accepted on %s", p)
		}
	}
	for _, p := range []string{"github", "cloudflare"} {
		if err := dryRunAccepted(p, true); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}

// --subdomain and --address mean something only to a Cloudflare restore
// or diff; taken anywhere else, the restore would write the names as they
// are.
func TestSubdomainFlagsRefusedWhereNothingReadsThem(t *testing.T) {
	parse := func(args ...string) *saasFlags {
		var s saasFlags
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		s.registerSubdomain(fs, true)
		if err := fs.Parse(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		return &s
	}
	if parse("--subdomain", "test.example.com").subdomainAccepted("github") == nil {
		t.Error("--subdomain accepted for github")
	}
	if parse("--address", "192.0.2.1=198.51.100.7").subdomainAccepted("cloudflare") == nil {
		t.Error("--address accepted without --subdomain")
	}
	if parse("--target", "app.example.net=app-test.example.net").subdomainAccepted("cloudflare") == nil {
		t.Error("--target accepted without --subdomain")
	}
	if tg := parse("--subdomain", "test.example.com", "--target", "App.Example.net.=app-test.example.net").targets; tg["app.example.net"] != "app-test.example.net" {
		t.Errorf("targets %v", tg)
	}
	s := parse("--subdomain", "test.example.com", "--address", "192.0.2.1=198.51.100.7,2001:db8::1=2001:db8::2")
	if err := s.subdomainAccepted("cloudflare"); err != nil {
		t.Error(err)
	}
	if s.addresses["192.0.2.1"] != "198.51.100.7" || s.addresses["2001:db8::1"] != "2001:db8::2" {
		t.Errorf("addresses %v", s.addresses)
	}
	var bad saasFlags
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	bad.registerSubdomain(fs, true)
	if fs.Parse([]string{"--address", "www.example.com=198.51.100.7"}) == nil {
		t.Error("a name taken as an address")
	}
	for _, v := range []string{"192.0.2.1=app.example.net", "app.example.net", "*.example.net=app.example.net"} {
		if fs.Parse([]string{"--target", v}) == nil {
			t.Errorf("--target %s taken", v)
		}
	}
}

// cloudflareAPI serves one zone over Cloudflare's API and fails the test
// on any request but a read.
func cloudflareAPI(t *testing.T) *httptest.Server {
	t.Helper()
	zone := map[string]any{"id": "z1", "name": "example.com", "type": "full", "paused": false, "account": map[string]any{"id": "acct-1111"}}
	records := []map[string]any{
		{"id": "r1", "type": "A", "name": "example.com", "content": "192.0.2.1", "ttl": 1, "proxied": false},
		{"id": "r2", "type": "CNAME", "name": "www.example.com", "content": "example.com", "ttl": 1, "proxied": false},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("a dry run sent %s %s", r.Method, r.URL.Path)
			http.Error(w, "write", http.StatusInternalServerError)
			return
		}
		var result any
		switch p := r.URL.Path; {
		case p == "/zones":
			result = []any{zone}
		case p == "/zones/z1/dns_records":
			result = records
		case strings.HasPrefix(p, "/zones/z1/dns_records/"):
			for _, rec := range records {
				if rec["id"] == strings.TrimPrefix(p, "/zones/z1/dns_records/") {
					result = rec
				}
			}
		}
		if result == nil {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result, "result_info": map[string]any{"page": 1, "total_pages": 1}})
	}))
	t.Cleanup(srv.Close)
	p := saas.Providers["cloudflare"]
	t.Cleanup(func() { saas.Providers["cloudflare"] = p })
	p.Base = srv.URL
	saas.Providers["cloudflare"] = p
	t.Setenv("CLOUDFLARE_API_TOKEN", "test-token")
	return srv
}

// A dry run through the command: it plans the subdomain, exits 0 and
// sends nothing. Its client is the read-only one too, so a write that got
// past the engine's DryRun would still not leave the machine.
func TestADryRunThroughTheCommandSendsNoWrite(t *testing.T) {
	srv := cloudflareAPI(t)
	specs, _ := filepath.Abs("../../testdata/saas")
	snap := filepath.Join(t.TempDir(), "snap")
	ctx := context.Background()
	if code := capture(ctx, []string{"--platform", "cloudflare", "--account", "acct-1111", "--spec-dir", specs, "--out", snap}); code != 0 {
		t.Fatalf("capture exit %d", code)
	}
	if code := restore(ctx, []string{"--platform", "cloudflare", "--account", "acct-1111", "--spec-dir", specs, "--from", snap,
		"--subdomain", "test.example.com", "--address", "192.0.2.1=198.51.100.7", "--dry-run"}); code != 0 {
		t.Errorf("dry run exit %d", code)
	}
	sf := saasFlags{account: "acct-1111", specDir: specs}
	ad, err := sf.connectRestore("cloudflare", true)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := ad.Client.HTTP.Post(srv.URL+"/zones/z1/dns_records", "application/json", strings.NewReader("{}")); err == nil {
		resp.Body.Close()
		t.Error("a dry run's client sent a write")
	}
}
