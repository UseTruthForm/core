package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackdna/core/internal/azarm"
)

const (
	leaveSrc   = "11111111-1111-1111-1111-111111111111"
	leaveDst   = "22222222-2222-2222-2222-222222222222"
	leaveOther = "33333333-3333-3333-3333-333333333333"
	leaveDefs  = "../../testdata/azure/types"
	leaveKey   = "Microsoft.Network/privateDnsZones/A/rg/corp.example/www"
)

// output runs f with stdout and stderr each read into a string.
func output(t *testing.T, f func() int) (code int, stdout, stderr string) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	ro, wo, _ := os.Pipe()
	re, we, _ := os.Pipe()
	os.Stdout, os.Stderr = wo, we
	outc, errc := make(chan string), make(chan string)
	go func() { b, _ := io.ReadAll(ro); outc <- string(b) }()
	go func() { b, _ := io.ReadAll(re); errc <- string(b) }()
	code = f()
	wo.Close()
	we.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	return code, <-outc, <-errc
}

// leaveOutWorld is a source subscription captured to a snapshot, and an
// empty target that azureAPI hands restore and diff in place of Azure. The
// zone's tag names another subscription, for the NOTE.
func leaveOutWorld(t *testing.T) (dir, leave string, dst *azarm.Fake) {
	t.Helper()
	reg, err := azarm.LoadDefinitions(leaveDefs)
	if err != nil {
		t.Fatal(err)
	}
	w := azarm.NewWorld(reg)
	src := w.Subscription(leaveSrc, "tenant")
	dst = w.Subscription(leaveDst, "tenant")
	ctx := context.Background()
	stable := func(typ string) string {
		for _, v := range reg.Versions(typ) {
			if !strings.Contains(v, "preview") {
				return v
			}
		}
		return reg.Versions(typ)[0]
	}
	rg := "/subscriptions/" + leaveSrc + "/resourceGroups/rg"
	zone := rg + "/providers/Microsoft.Network/privateDnsZones/corp.example"
	for _, p := range []struct {
		id, typ string
		body    map[string]any
	}{
		{rg, "Microsoft.Resources/resourceGroups", map[string]any{"location": "eastus"}},
		{zone, "Microsoft.Network/privateDnsZones", map[string]any{"location": "global", "tags": map[string]any{"hub": "/subscriptions/" + leaveOther + "/resourceGroups/hub"}}},
		{zone + "/A/www", "Microsoft.Network/privateDnsZones/A", map[string]any{"properties": map[string]any{"ttl": 300, "aRecords": []any{map[string]any{"ipv4Address": "10.0.0.4"}}}}},
	} {
		if _, err := src.Put(ctx, p.id, stable(p.typ), p.body); err != nil {
			t.Fatalf("seed %s: %v", p.id, err)
		}
	}
	s, err := (&azarm.Adapter{API: src, Registry: reg}).Capture(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(t.TempDir(), "snap")
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	leave = filepath.Join(t.TempDir(), "leave.yaml")
	if err := os.WriteFile(leave, []byte("- "+leaveKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := azureAPI
	azureAPI = func(sub string, readOnly bool) (azarm.ARM, error) {
		if sub != leaveDst {
			return nil, errors.New("only the fake target")
		}
		// As NewSDK does, so the capture-only build sends no PUT here either.
		if readOnly {
			return readOnlyFake{dst}, nil
		}
		return dst, nil
	}
	t.Cleanup(func() { azureAPI = old; heldBack = nil })
	return dir, leave, dst
}

// readOnlyFake refuses every PUT, as the SDK does when read-only.
type readOnlyFake struct{ *azarm.Fake }

func (readOnlyFake) Put(context.Context, string, string, map[string]any) (map[string]any, error) {
	return nil, errors.New("read-only")
}

// Review of beta.14: restore and diff read --leave-out, warn about other
// subscriptions and refuse it with --config in main, and no test went through
// main; each call could be removed and the tests still passed. Through both
// commands against a fake target: what is left out is not sent, not expected,
// and named.
func TestLeaveOutReachesRestoreAndDiff(t *testing.T) {
	dir, leave, dst := leaveOutWorld(t)
	ctx := context.Background()
	target := []string{"--platform", "azure", "--subscription", leaveDst, "--definitions", leaveDefs, "--from", dir}

	code, out, errOut := output(t, func() int { return diff(ctx, target) })
	if code != 2 || !strings.Contains(out, "corp.example/www") {
		t.Fatalf("diff of an empty target: exit %d\n%s%s", code, out, errOut)
	}
	if !strings.Contains(errOut, "NOTE: 1 objects name another subscription") || !strings.Contains(errOut, leaveOther) {
		t.Errorf("diff does not say a zone names another subscription:\n%s", errOut)
	}

	// Against the empty target, the record left out is not expected.
	code, out, errOut = output(t, func() int { return diff(ctx, append(target, "--leave-out", leave)) })
	if code != 2 || strings.Contains(out, "privateDnsZones/A|") || !strings.Contains(out, "leaving out 1 objects (--leave-out): "+leaveKey) {
		t.Errorf("diff with --leave-out of an empty target: exit %d\n%s%s", code, out, errOut)
	}

	// --config diffs every target, and one file of keys cannot be for all.
	code, _, errOut = output(t, func() int {
		return diff(ctx, []string{"--config", filepath.Join(dir, "env.yaml"), "--from", dir, "--leave-out", leave})
	})
	if code != 1 || !strings.Contains(errOut, "not --config") {
		t.Errorf("--leave-out with --config: exit %d\n%s", code, errOut)
	}

	if captureOnly {
		return // restore is refused in the capture-only build
	}
	code, out, errOut = output(t, func() int { return restore(ctx, append(target, "--leave-out", leave)) })
	if code != 0 {
		t.Fatalf("restore: exit %d\n%s%s", code, out, errOut)
	}
	rg := "/subscriptions/" + leaveDst + "/resourceGroups/rg/providers/Microsoft.Network/privateDnsZones/corp.example"
	if _, err := dst.Get(ctx, rg, "2024-06-01"); err != nil {
		t.Errorf("the zone was not restored: %v", err)
	}
	if _, err := dst.Get(ctx, rg+"/A/www", "2024-06-01"); err == nil {
		t.Error("restore sent what --leave-out holds back")
	}
	if !strings.Contains(errOut, "   "+leaveKey) || !strings.Contains(out, "left out 1 (--leave-out): "+leaveKey) {
		t.Errorf("restore does not name what it left out:\n%s%s", out, errOut)
	}
	if !strings.Contains(errOut, "NOTE: 1 objects name another subscription") {
		t.Errorf("restore does not say a zone names another subscription:\n%s", errOut)
	}

	// Left out, the record is not expected; the diff is clean and says why.
	code, out, errOut = output(t, func() int { return diff(ctx, append(target, "--leave-out", leave)) })
	if code != 0 || !strings.Contains(out, "no differences") || !strings.Contains(out, "leaving out 1 objects (--leave-out): "+leaveKey) {
		t.Errorf("diff with --leave-out: exit %d\n%s%s", code, out, errOut)
	}
	d := asJSON(t, func() { diff(ctx, append(target, "--leave-out", leave)) })
	if got, _ := d["left_out"].([]any); len(got) != 1 || got[0] != leaveKey {
		t.Errorf("the diff document does not list it: %v", d["left_out"])
	}
}

// What a restore left out is in its document, as in a diff's.
func TestRestoreDocumentListsWhatWasLeftOut(t *testing.T) {
	heldBack = []string{leaveKey}
	defer func() { heldBack = nil }()
	r := asJSON(t, func() { emitRestore(nil, "azure x") })
	if got, _ := r["left_out"].([]any); len(got) != 1 || got[0] != leaveKey {
		t.Errorf("left_out: %v", r["left_out"])
	}
}

// A --values key that matches nothing was ignored, and the restore said
// "created" with the snapshot's value (re-review of #73). It is refused before
// anything is sent; a value for what --leave-out holds back is not a mistake.
func TestRestoreRefusesAValuesKeyThatMatchesNothing(t *testing.T) {
	if captureOnly {
		t.Skip("restore is refused in the capture-only build")
	}
	dir, leave, dst := leaveOutWorld(t)
	ctx := context.Background()
	vals := filepath.Join(t.TempDir(), "values.yaml")
	target := []string{"--platform", "azure", "--subscription", leaveDst, "--definitions", leaveDefs, "--from", dir, "--values", vals}
	write := func(s string) {
		if err := os.WriteFile(vals, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("microsoft.network/privatednszones/rg/corp.example:\n  tags: {a: b}\n")
	code, out, errOut := output(t, func() int { return restore(ctx, target) })
	if code != 1 || !strings.Contains(errOut, "--values: nothing in the snapshot has microsoft.network/privatednszones/rg/corp.example (the snapshot has Microsoft.Network/privateDnsZones/rg/corp.example)") {
		t.Errorf("a key in the wrong case: exit %d\n%s%s", code, out, errOut)
	}
	if _, err := dst.Get(ctx, "/subscriptions/"+leaveDst+"/resourceGroups/rg", "2024-11-01"); err == nil {
		t.Error("something was restored before the refusal")
	}
	write(leaveKey + ":\n  properties: {ttl: 60}\n")
	if code, out, errOut := output(t, func() int { return restore(ctx, append(target, "--leave-out", leave)) }); code != 0 {
		t.Errorf("a value for what is left out was refused: exit %d\n%s%s", code, out, errOut)
	}
}
