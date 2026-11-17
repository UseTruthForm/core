package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/usetruthform/core/internal/readonly"
	"github.com/usetruthform/core/internal/saas"
	"github.com/usetruthform/core/internal/snapshot"
)

// saasFlags are the GitHub and Cloudflare forms of capture, restore, diff.
type saasFlags struct {
	account, specDir string
	subdomain        string
	addresses        map[string]string
	targets          map[string]string
}

func (s *saasFlags) registerSubdomain(fs *flag.FlagSet, restore bool) {
	what := "cloudflare: compare the zone's records as a --subdomain restore put them, against the records under that name"
	if restore {
		what = "cloudflare: restore one zone's records one level down, under this name in the same zone (www.example.com becomes www.test.example.com for test.example.com), each marked as TruthForm's; mail, delegations and ACME records stay out, and a conflict with a record already there stops the restore before it writes"
	}
	fs.StringVar(&s.subdomain, "subdomain", "", what)
	fs.Func("address", "cloudflare --subdomain: comma-separated <source-ip>=<target-ip>; an A or AAAA record a subdomain restore makes points at the target's address, not the source's (a restore that would keep a source address stops)", func(v string) error {
		if s.addresses == nil {
			s.addresses = map[string]string{}
		}
		for _, p := range strings.Split(v, ",") {
			from, to, ok := strings.Cut(strings.TrimSpace(p), "=")
			if !ok || net.ParseIP(from) == nil || net.ParseIP(to) == nil {
				return fmt.Errorf("%q: give <source-ip>=<target-ip>", p)
			}
			s.addresses[from] = to
		}
		return nil
	})
	fs.Func("target", "cloudflare --subdomain: comma-separated <source-host>=<target-host>; a CNAME to a host outside the zone (an app service, a load balancer) points at the target's; the same host twice keeps it (a restore that would keep a source host unnamed stops)", func(v string) error {
		if s.targets == nil {
			s.targets = map[string]string{}
		}
		for _, p := range strings.Split(v, ",") {
			from, to, ok := strings.Cut(strings.TrimSpace(p), "=")
			from, to = strings.TrimSuffix(from, "."), strings.TrimSuffix(to, ".")
			if !ok || !hostname(from) || !hostname(to) {
				return fmt.Errorf("%q: give <source-host>=<target-host>", p)
			}
			s.targets[strings.ToLower(from)] = to
		}
		return nil
	})
}

// hostname reports whether v is a DNS name: dotted labels, no address,
// no wildcard.
func hostname(v string) bool {
	if v == "" || net.ParseIP(v) != nil || !strings.Contains(v, ".") {
		return false
	}
	for _, l := range strings.Split(v, ".") {
		if l == "" || strings.Trim(strings.ToLower(l), "abcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
			return false
		}
	}
	return true
}

func (s *saasFlags) subdomainAccepted(platform string) error {
	if s.subdomain != "" && platform != "cloudflare" {
		return fmt.Errorf("--subdomain is for --platform cloudflare; nothing was done")
	}
	if (len(s.addresses) > 0 || len(s.targets) > 0) && s.subdomain == "" {
		return fmt.Errorf("--address and --target are for a --subdomain restore or diff; nothing was done")
	}
	return nil
}

// sub maps the snapshot under --subdomain and prints what it left out.
func (s *saasFlags) sub(snap snapshot.Snapshot) (*saas.Subdomain, snapshot.Snapshot, error) {
	d := &saas.Subdomain{Name: s.subdomain, Addresses: s.addresses, Targets: s.targets}
	out, left, err := d.Map(snap)
	if err != nil {
		return nil, snap, err
	}
	for _, l := range left {
		fmt.Printf("left out %s: %s\n", l.Name, l.Reason)
	}
	return d, out, nil
}

func (s *saasFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&s.account, "account", "", "github: the organisation; cloudflare: the account ID")
	fs.StringVar(&s.specDir, "spec-dir", "", "directory holding the provider's OpenAPI description (default: the published one, cached for a day)")
}

// connect builds a client. The token comes from the provider's environment
// variable (GITHUB_TOKEN, CLOUDFLARE_API_TOKEN), else from the person's
// sign-in (truthform login cloudflare); it is never written to a snapshot.
func (s *saasFlags) connect(platform string, readOnly bool) (*saas.Adapter, error) {
	p, ok := saas.Providers[platform]
	if !ok {
		return nil, fmt.Errorf("unknown provider %q", platform)
	}
	if s.account == "" {
		return nil, fmt.Errorf("--account is required for --platform %s (capture and restore never guess their target)", platform)
	}
	// The environment's token, else the person's sign-in. A refresh goes
	// behind the read-only guard, which lets the token endpoint through.
	tokens, how, err := saas.Tokens(p, keychain, readonly.Client())
	if err != nil {
		return nil, err
	}
	tokenNote(platform, how)
	var spec *saas.Spec
	if s.specDir != "" {
		spec, err = saas.LoadSpec(filepath.Join(s.specDir, p.Spec))
	} else {
		var cache string
		if cache, err = os.UserCacheDir(); err == nil {
			spec, err = saas.FetchSpec(p, filepath.Join(cache, "truthform", "saas"), 24*time.Hour)
		}
	}
	if err != nil {
		return nil, err
	}
	c := saas.NewClient(p, spec, s.account, "", readOnly)
	c.Tokens = tokens
	return &saas.Adapter{Client: c}, nil
}

func captureSaaS(ctx context.Context, platform string, s *saasFlags, out string) int {
	ad, err := s.connect(platform, true)
	if err != nil {
		return fail(err)
	}
	snap, err := ad.Capture(ctx)
	if err != nil {
		return fail(err)
	}
	if err := snap.Write(out); err != nil {
		return fail(err)
	}
	emitCapture(out, snap, platform+" "+s.account)
	if err := writeReport(out, snap, platform+" "+s.account); err != nil {
		return fail(err)
	}
	d, _ := snapshot.Digest(out)
	read, _, failed := summarize(snap)
	fmt.Printf("captured %d items across %d collections into %s (%s)\n", len(snap.Objects), read, out, d)
	fmt.Println("NOTE: configuration only. Content (code, issues, DNS query data) and secret values are NOT in this snapshot")
	if len(failed) > 0 {
		fmt.Println("INCOMPLETE: these collections could not be read:")
		for _, f := range failed {
			fmt.Println("  ", f)
		}
		return 3
	}
	return 0
}

// connectRestore connects for a restore. A dry run's client is the
// read-only one, which refuses every write, beside the engine's own
// DryRun.
func (s *saasFlags) connectRestore(platform string, dryRun bool) (*saas.Adapter, error) {
	return s.connect(platform, captureOnly || dryRun)
}

func restoreSaaS(ctx context.Context, platform string, s *saasFlags, snap snapshot.Snapshot, valuesFile string, update, dryRun bool) int {
	ad, err := s.connectRestore(platform, dryRun)
	if err != nil {
		return fail(err)
	}
	ad.Options.Update, ad.Options.DryRun = update, dryRun
	if valuesFile != "" {
		b, err := os.ReadFile(valuesFile)
		if err != nil {
			return fail(err)
		}
		if err := yaml.Unmarshal(b, &ad.Options.Values); err != nil {
			return fail(fmt.Errorf("%s: %w", valuesFile, err))
		}
	}
	var results []snapshot.Result
	var conflicts []string
	if s.subdomain != "" {
		d, mapped, err := s.sub(snap)
		if err != nil {
			return fail(err)
		}
		var warnings []string
		if conflicts, warnings, results, err = ad.Client.RestoreUnder(ctx, d, mapped, ad.Options); err != nil {
			return fail(err)
		}
		for _, w := range warnings {
			fmt.Println("WARNING:", w)
		}
		for _, c := range conflicts {
			fmt.Println("CONFLICT:", c)
		}
		if len(conflicts) > 0 && !dryRun {
			fmt.Printf("stopped: %d conflicts, nothing was written\n", len(conflicts))
			return 3
		}
	} else {
		results = ad.Restore(ctx, snap)
	}
	ok := 0
	if jsonOut {
		defer emitRestore(results, platform+" "+s.account)
	}
	for _, r := range results {
		if r.OK {
			ok++
			if dryRun {
				fmt.Printf("%s: %s\n", r.Detail, r.Key)
			} else if r.Detail != "created" && r.Detail != "already present and identical" {
				fmt.Printf("applied %s: %s\n", r.Key, r.Detail)
			}
			continue
		}
		fmt.Printf("NOT APPLIED %s: %s\n", r.Key, r.Detail)
	}
	if dryRun {
		fmt.Printf("dry run: %d of %d items would apply to %s %s; nothing was written\n", ok, len(results), platform, s.account)
		if len(conflicts) > 0 {
			fmt.Printf("%d conflicts: the restore would stop before writing\n", len(conflicts))
			return 3
		}
	} else {
		fmt.Printf("applied %d of %d items to %s %s\n", ok, len(results), platform, s.account)
	}
	if ok != len(results) {
		return 3
	}
	return 0
}

func diffSaaS(ctx context.Context, platform string, s *saasFlags, want snapshot.Snapshot, from string) int {
	ad, err := s.connect(platform, true)
	if err != nil {
		return fail(err)
	}
	var d *saas.Subdomain
	if s.subdomain != "" {
		if d, want, err = s.sub(want); err != nil {
			return fail(err)
		}
	}
	got, err := ad.Capture(ctx)
	if err != nil {
		return fail(err)
	}
	if d != nil {
		got = d.Scope(got)
	}
	return report(differences(want, got, snapshot.Compare(want, got)), from, platform+" "+s.account)
}
