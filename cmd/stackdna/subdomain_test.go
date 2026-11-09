package main

import (
	"flag"
	"io"
	"testing"
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
}
