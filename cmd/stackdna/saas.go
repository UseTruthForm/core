package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/stackdna/core/internal/readonly"
	"github.com/stackdna/core/internal/saas"
	"github.com/stackdna/core/internal/snapshot"
)

// saasFlags are the GitHub and Cloudflare forms of capture, restore, diff.
type saasFlags struct {
	account, specDir string
}

func (s *saasFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&s.account, "account", "", "github: the organisation; cloudflare: the account ID")
	fs.StringVar(&s.specDir, "spec-dir", "", "directory holding the provider's OpenAPI description (default: the published one, cached for a day)")
}

// connect builds a client. The token comes from the provider's environment
// variable (GITHUB_TOKEN, CLOUDFLARE_API_TOKEN), else from the person's
// sign-in (stackdna login cloudflare); it is never written to a snapshot.
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
			spec, err = saas.FetchSpec(p, filepath.Join(cache, "stackdna", "saas"), 24*time.Hour)
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

func restoreSaaS(ctx context.Context, platform string, s *saasFlags, snap snapshot.Snapshot, valuesFile string, update bool) int {
	ad, err := s.connect(platform, captureOnly)
	if err != nil {
		return fail(err)
	}
	ad.Options.Update = update
	if valuesFile != "" {
		b, err := os.ReadFile(valuesFile)
		if err != nil {
			return fail(err)
		}
		if err := yaml.Unmarshal(b, &ad.Options.Values); err != nil {
			return fail(fmt.Errorf("%s: %w", valuesFile, err))
		}
	}
	ok := 0
	results := ad.Restore(ctx, snap)
	if jsonOut {
		defer emitRestore(results, platform+" "+s.account)
	}
	for _, r := range results {
		if r.OK {
			ok++
			if r.Detail != "created" && r.Detail != "already present and identical" {
				fmt.Printf("applied %s: %s\n", r.Key, r.Detail)
			}
			continue
		}
		fmt.Printf("NOT APPLIED %s: %s\n", r.Key, r.Detail)
	}
	fmt.Printf("applied %d of %d items to %s %s\n", ok, len(results), platform, s.account)
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
	got, err := ad.Capture(ctx)
	if err != nil {
		return fail(err)
	}
	return report(snapshot.Compare(want, got), from, platform+" "+s.account)
}
