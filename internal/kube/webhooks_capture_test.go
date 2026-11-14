package kube_test

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/kube"
	"github.com/usetruthform/core/internal/kubetest"
	"github.com/usetruthform/core/internal/snapshot"
)

// TestWebhooksOfARealCapture asks, of a snapshot a capture wrote from a
// real API server, whether each webhook's Service will answer after a
// restore. The shapes are the ones a capture writes in its own way (what
// an object owns, what a GitOps source renders, what is in a system
// namespace), so they are captured and not written by hand: three rounds
// of rules written against hand-made snapshots each missed one.
//
// Every row is one restore, and says for each webhook the one answer of
// three: nothing (it will answer), a reason it will not (and the restore
// is refused), or that the snapshot does not say.
func TestWebhooksOfARealCapture(t *testing.T) {
	srv := kubetest.Start(t, "webhooks")
	w, err := kube.Connect(srv.Kubeconfig, srv.Context, false)
	if err != nil {
		t.Fatal(err)
	}
	seed(t, w, "../../testdata/k8s/webhooks.yaml")
	ro, err := kube.Connect(srv.Kubeconfig, srv.Context, true)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := kube.Capture(context.Background(), ro, kube.Policy{})
	if err != nil {
		t.Fatal(err)
	}

	// What the capture wrote, which the rows below depend on: the
	// Services an object owns are one skip with their names, and are not
	// objects of the snapshot.
	ownedNames := map[string][]string{}
	for _, sk := range snap.Skips {
		if strings.HasSuffix(sk.Resource, "/services") && sk.Name == "*" {
			ownedNames[sk.Namespace] = append(ownedNames[sk.Namespace], sk.Names...)
		}
	}
	for ns, want := range map[string][]string{"owned": {"hook"}, "two": {"hook-a", "hook-b"}, "byargo": {"hook"}, "byflux": {"hook"}} {
		got := ownedNames[ns]
		sort.Strings(got)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("the Services an object owns in %s, as captured: %q, want %q", ns, got, want)
		}
	}

	without := func(s snapshot.Snapshot, keys ...string) snapshot.Snapshot {
		out := s
		out.Objects = nil
		for _, o := range s.Objects {
			drop := false
			for _, k := range keys {
				drop = drop || o.Kind()+"/"+o.Namespace()+"/"+o.Name() == k
			}
			if !drop {
				out.Objects = append(out.Objects, o)
			}
		}
		if len(out.Objects) != len(s.Objects)-len(keys) {
			t.Fatalf("%v: not all in the snapshot", keys)
		}
		return out
	}
	// A snapshot as captures wrote it before: what an object owns, with
	// no names.
	before := snap
	before.Skips = nil
	for _, sk := range snap.Skips {
		sk.Names = nil
		before.Skips = append(before.Skips, sk)
	}
	hold := func(ns string) kube.Scope {
		return kube.Scope{Narrow: []kube.ScopeEntry{{Namespaces: []string{ns}, Labels: map[string]string{"part": "answers"}, Objects: []string{"Service/*"}, Hold: true}}}
	}

	// Always: no Service of that name anywhere, and no skip that covers it.
	never := map[string]string{"nowhere": kube.WhyNotBrought, "soft": kube.WhyNotBrought, "owned-other": kube.WhyNotBrought}
	with := func(more map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range never {
			out[k] = v
		}
		for k, v := range more {
			if v == "" {
				delete(out, k)
			} else {
				out[k] = v
			}
		}
		return out
	}
	for _, row := range []struct {
		name   string
		whole  snapshot.Snapshot
		taken  []string // taken out before the scope (--leave-out)
		scope  *kube.Scope
		want   map[string]string // webhook -> why; one not listed answers
		blocks []string
	}{
		{name: "the whole snapshot, no scope", whole: snap, want: never, blocks: []string{"nowhere", "owned-other"}},
		{name: "the Service taken out", whole: snap, taken: []string{"Service/plain/hook"},
			want: with(map[string]string{"plain": kube.WhyNotBrought}), blocks: []string{"nowhere", "owned-other", "plain"}},
		{name: "what answers behind it taken out", whole: snap, taken: []string{"Deployment/plain/hook"},
			want: with(map[string]string{"plain": kube.WhyLeftOut}), blocks: []string{"nowhere", "owned-other", "plain"}},
		{name: "what answers behind it held", whole: snap, scope: ptr(hold("plain")),
			want: with(map[string]string{"plain": kube.WhyHeld}), blocks: []string{"nowhere", "owned-other", "plain"}},
		{name: "the owner taken out", whole: snap, taken: []string{"ConfigMap/owned/operand"},
			want: with(map[string]string{"owned": kube.WhyNotBrought}), blocks: []string{"nowhere", "owned", "owned-other"}},
		{name: "one owner of two taken out", whole: snap, taken: []string{"ConfigMap/two/owner-b"},
			want: with(map[string]string{"two-b": kube.WhyNotBrought}), blocks: []string{"nowhere", "owned-other", "two-b"}},
		{name: "the owner held", whole: snap, scope: ptr(kube.Scope{Narrow: []kube.ScopeEntry{{Namespaces: []string{"owned"}, Objects: []string{"ConfigMap/*"}, Hold: true}}}),
			// A ConfigMap runs nothing: the hold holds nothing of it, and
			// what it owns is taken to be there.
			want: never, blocks: []string{"nowhere", "owned-other"}},
		{name: "the root application taken out, two steps up", whole: snap, taken: []string{"Application/argocd/root"},
			want: with(map[string]string{"byargo": kube.WhyNotBrought}), blocks: []string{"byargo", "nowhere", "owned-other"}},
		{name: "the root application held", whole: snap, scope: ptr(kube.Scope{Narrow: []kube.ScopeEntry{{Namespaces: []string{"argocd"}, Objects: []string{"Application/*"}, Hold: true}}}),
			// Held, an application syncs nothing by itself: what it
			// would have made, two steps down, is not there.
			want: with(map[string]string{"byargo": kube.WhyNotBrought}), blocks: []string{"byargo", "nowhere", "owned-other"}},
		{name: "the HelmRelease taken out", whole: snap, taken: []string{"HelmRelease/flux/gadgets"},
			want: with(map[string]string{"byflux": kube.WhyNotBrought}), blocks: []string{"byflux", "nowhere", "owned-other"}},
		{name: "the HelmRelease held", whole: snap, scope: ptr(kube.Scope{Narrow: []kube.ScopeEntry{{Namespaces: []string{"flux"}, Objects: []string{"HelmRelease/*"}, Hold: true}}}),
			want: with(map[string]string{"byflux": kube.WhyNotBrought}), blocks: []string{"byflux", "nowhere", "owned-other"}},
		{name: "the composite taken out, which has a namespace", whole: snap, taken: []string{"Gadget/composed/thing-abc12"},
			want: with(map[string]string{"composed": kube.WhyNotBrought}), blocks: []string{"composed", "nowhere", "owned-other"}},
		{name: "a snapshot from before the names were written", whole: before,
			// Whether a Service is one an owner has is not said: every
			// one in a namespace where an object owns Services is open,
			// the one no owner has among them, and none refuses. In a
			// system namespace it is the platform's either way.
			want: with(map[string]string{"owned": kube.WhyUnknown, "owned-other": kube.WhyUnknown, "two-a": kube.WhyUnknown, "two-b": kube.WhyUnknown, "byargo": kube.WhyUnknown, "byflux": kube.WhyUnknown}), blocks: []string{"nowhere"}},
		{name: "from before, and the owner taken out", whole: before, taken: []string{"ConfigMap/owned/operand"},
			// With no owner brought, it is not there whichever it was.
			want: with(map[string]string{"owned": kube.WhyNotBrought, "two-a": kube.WhyUnknown, "two-b": kube.WhyUnknown, "byargo": kube.WhyUnknown, "byflux": kube.WhyUnknown}), blocks: []string{"nowhere", "owned", "owned-other"}},
	} {
		s := without(row.whole, row.taken...)
		var hooks []kube.ScopeWebhook
		if row.scope != nil {
			_, rep, err := kube.NarrowFrom(row.whole, s, *row.scope)
			if err != nil {
				t.Errorf("%s: %v", row.name, err)
				continue
			}
			hooks = rep.Webhooks
		} else {
			hooks = kube.WebhooksWithoutService(row.whole, s)
		}
		got, blocks := map[string]string{}, []string{}
		for _, h := range hooks {
			name := strings.TrimSuffix(h.Webhook, ".example.truthform.org")
			got[name] = h.Why
			if h.Blocks {
				blocks = append(blocks, name)
			}
		}
		sort.Strings(blocks)
		if !reflect.DeepEqual(got, row.want) || !reflect.DeepEqual(blocks, row.blocks) {
			t.Errorf("%s:\n   got %v, refusing for %v\n  want %v, refusing for %v", row.name, got, blocks, row.want, row.blocks)
		}
	}
}

func ptr[T any](v T) *T { return &v }
