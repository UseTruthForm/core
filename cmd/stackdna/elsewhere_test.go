package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackdna/core/internal/azarm"
)

// Before a restore, nothing said which grants it needed outside its target:
// a diagnostic setting to another subscription's event hub needed that rule's
// keys, found only when Azure refused it. The report, the note before a diff
// or restore, and the JSON document now name each action and where.
func TestWhatARestoreNeedsElsewhereIsSaid(t *testing.T) {
	reg, err := azarm.LoadDefinitions(leaveDefs)
	if err != nil {
		t.Fatal(err)
	}
	w := azarm.NewWorld(reg)
	src := w.Subscription(leaveSrc, "tenant")
	dst := w.Subscription(leaveDst, "tenant")
	ctx := context.Background()
	rule := "/subscriptions/" + leaveOther + "/resourceGroups/hub/providers/Microsoft.EventHub/namespaces/logs/authorizationRules/send"
	setting := "/subscriptions/" + leaveSrc + "/providers/Microsoft.Insights/diagnosticSettings/to-hub"
	if _, err := src.Put(ctx, setting, "2021-05-01-preview", map[string]any{"properties": map[string]any{
		"eventHubAuthorizationRuleId": rule, "eventHubName": "activity",
		"logs": []any{map[string]any{"category": "Administrative", "enabled": true}}}}); err != nil {
		t.Fatal(err)
	}
	s, err := (&azarm.Adapter{API: src, Registry: reg}).Capture(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "snap")
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	need := "Microsoft.EventHub/namespaces/authorizationRules/listKeys/action on " + rule

	if err := writeReport(dir, s, "azure test"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "REPORT.md"))
	if r := string(b); !strings.Contains(r, "## Access a restore needs outside its target: 1") || !strings.Contains(r, need) {
		t.Errorf("report:\n%s", r)
	}

	old := azureAPI
	azureAPI = func(sub string, _ bool) (azarm.ARM, error) {
		if sub != leaveDst {
			return nil, errors.New("only the fake target")
		}
		return dst, nil
	}
	t.Cleanup(func() { azureAPI = old; needElsewhere = nil })
	args := []string{"--platform", "azure", "--subscription", leaveDst, "--definitions", leaveDefs, "--from", dir}
	_, _, errOut := output(t, func() int { return diff(ctx, args) })
	if !strings.Contains(errOut, "NOTE: a restore needs 1 actions outside its target") || !strings.Contains(errOut, need) {
		t.Errorf("no note before the diff:\n%s", errOut)
	}
	d := asJSON(t, func() { diff(ctx, args) })
	if got, _ := d["access_elsewhere"].([]any); len(got) != 1 || !strings.HasSuffix(got[0].(string), need) {
		t.Errorf("access_elsewhere: %v", d["access_elsewhere"])
	}
}
