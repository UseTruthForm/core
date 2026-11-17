package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/usetruthform/core/internal/azarm"
)

// Log Analytics returned one table as ACSCallAutomationStreamingUsage on one
// day and AcsCallAutomationStreamingUsage on the next. Each capture wrote it to
// a file of its own, and compare said one table removed and another added every
// day. Azure's names ignore case: it is one table.
const (
	caseSub   = "33333333-3333-3333-3333-333333333333"
	caseDst   = "44444444-4444-4444-4444-444444444444"
	tableUp   = "ACSCallAutomationStreamingUsage"
	tableDown = "AcsCallAutomationStreamingUsage"
	tableType = "Microsoft.OperationalInsights/workspaces/tables"
)

type caseWorld struct {
	reg      *azarm.Registry
	src, dst *azarm.Fake
	ws       string // the source workspace's ID
}

func newCaseWorld(t *testing.T) *caseWorld {
	t.Helper()
	reg, err := azarm.LoadDefinitions(leaveDefs)
	if err != nil {
		t.Fatal(err)
	}
	w := azarm.NewWorld(reg)
	cw := &caseWorld{reg: reg, src: w.Subscription(caseSub, "tenant"), dst: w.Subscription(caseDst, "tenant")}
	cw.ws = cw.seed(cw.src, caseSub)
	cw.table(cw.src, cw.ws, tableUp)
	old := azureAPI
	azureAPI = func(sub string, readOnly bool) (azarm.ARM, error) {
		switch sub {
		case caseSub:
			return readOnlyFake{cw.src}, nil
		case caseDst:
			if readOnly {
				return readOnlyFake{cw.dst}, nil
			}
			return cw.dst, nil
		}
		return nil, errors.New("only the fakes")
	}
	t.Cleanup(func() { azureAPI = old })
	return cw
}

func (cw *caseWorld) version(typ string) string {
	for _, v := range cw.reg.Versions(typ) {
		if !strings.Contains(v, "preview") {
			return v
		}
	}
	return cw.reg.Versions(typ)[0]
}

// seed makes the group and workspace, and returns the workspace's ID.
func (cw *caseWorld) seed(f *azarm.Fake, sub string) string {
	rg := "/subscriptions/" + sub + "/resourceGroups/logs"
	f.SeedAzure(rg, cw.version("Microsoft.Resources/resourceGroups"), map[string]any{"location": "eastus"})
	ws := rg + "/providers/Microsoft.OperationalInsights/workspaces/law"
	f.SeedAzure(ws, cw.version("Microsoft.OperationalInsights/workspaces"), map[string]any{"location": "eastus"})
	return ws
}

// table seeds the table, in the case given: the fake, like ARM, keeps one
// resource whatever the case, and returns it as it was last written.
func (cw *caseWorld) table(f *azarm.Fake, ws, name string) {
	f.SeedAzure(ws+"/tables/"+name, cw.version(tableType), map[string]any{"properties": map[string]any{
		"retentionInDays": 30, "retentionInDaysAsDefault": true, "totalRetentionInDays": 30, "totalRetentionInDaysAsDefault": true, "plan": "Analytics"}})
}

func (cw *caseWorld) capture(t *testing.T, dir string) {
	t.Helper()
	s, err := (&azarm.Adapter{API: cw.src, Registry: cw.reg}).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
}

// objectFiles lists a snapshot's object files, relative to it.
func objectFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(filepath.Join(dir, "objects"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			out = append(out, filepath.ToSlash(rel))
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAnAzureNameInAnotherCaseIsTheSameObject(t *testing.T) {
	cw := newCaseWorld(t)
	ctx := context.Background()
	up, down := filepath.Join(t.TempDir(), "up"), filepath.Join(t.TempDir(), "down")
	cw.capture(t, up)
	cw.table(cw.src, cw.ws, tableDown)
	cw.capture(t, down)

	// Capture: one file, the same one, each keeping the case Azure returned.
	fu, fd := objectFiles(t, up), objectFiles(t, down)
	if strings.Join(fu, "\n") != strings.Join(fd, "\n") {
		t.Errorf("the two captures store the objects in different files:\n%s\n--\n%s", strings.Join(fu, "\n"), strings.Join(fd, "\n"))
	}
	var tables []string
	for _, f := range fu {
		if strings.Contains(f, "%2Ftables/") {
			tables = append(tables, f)
		}
	}
	if len(tables) != 1 {
		t.Fatalf("table files: %v", tables)
	}
	for dir, name := range map[string]string{up: tableUp, down: tableDown} {
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(tables[0])))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "name: law/"+name+"\n") {
			t.Errorf("the file does not keep the case Azure returned (%s):\n%s", name, b)
		}
	}

	// Compare, both ways round.
	for _, pair := range [][]string{{up, down}, {down, up}} {
		code, out, errOut := output(t, func() int { return compare(pair) })
		if code != 0 || !strings.Contains(out, "no differences") {
			t.Errorf("compare %v: exit %d\n%s%s", pair, code, out, errOut)
		}
	}

	// Diff of the snapshot that has ACS against the source, which now says Acs.
	target := []string{"--platform", "azure", "--subscription", caseSub, "--definitions", leaveDefs}
	if code, out, errOut := output(t, func() int { return diff(ctx, append(target, "--from", up)) }); code != 0 || !strings.Contains(out, "no differences") {
		t.Errorf("diff: exit %d\n%s%s", code, out, errOut)
	}

	if captureOnly {
		return // restore is refused in the capture-only build
	}
	// Restore into a target that has the table in the other case: found, not
	// created beside it.
	dws := cw.seed(cw.dst, caseDst)
	cw.table(cw.dst, dws, tableDown)
	var mu sync.Mutex
	var sent []string
	cw.dst.PutError = func(id string, _ map[string]any) error {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, id)
		return nil
	}
	restoreTo := []string{"--platform", "azure", "--subscription", caseDst, "--definitions", leaveDefs, "--from", up}
	code, out, errOut := output(t, func() int { return restore(ctx, restoreTo) })
	if code != 0 {
		t.Errorf("restore over the table in the other case: exit %d\n%s%s", code, out, errOut)
	}
	for _, id := range sent {
		if strings.Contains(strings.ToLower(id), "/tables/") {
			t.Errorf("the table there in the other case was written: %s\n%s%s", id, out, errOut)
		}
	}
	got, err := cw.dst.Get(ctx, dws+"/tables/"+tableUp, cw.version(tableType))
	if err != nil || got["name"] != tableDown {
		t.Errorf("the target's table: %v %v", got["name"], err)
	}
}

// A --values file written against one capture names the table in the case of
// that capture. Looked up exactly, its value was refused against the next.
func TestAValuesKeyInAnotherCaseIsGivenToItsObject(t *testing.T) {
	if captureOnly {
		t.Skip("restore is refused in the capture-only build")
	}
	cw := newCaseWorld(t)
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "snap")
	cw.capture(t, dir)
	vals := filepath.Join(t.TempDir(), "values.yaml")
	write := func(s string) {
		if err := os.WriteFile(vals, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	key := tableType + "/LOGS/law/" + tableDown
	write(key + ":\n  properties: {plan: Basic}\n")
	var mu sync.Mutex
	var body string
	cw.dst.PutError = func(id string, b map[string]any) error {
		mu.Lock()
		defer mu.Unlock()
		if strings.HasSuffix(strings.ToLower(id), "/tables/"+strings.ToLower(tableUp)) {
			p, _ := b["properties"].(map[string]any)
			body = fmt.Sprint(p["plan"])
		}
		return nil
	}
	target := []string{"--platform", "azure", "--subscription", caseDst, "--definitions", leaveDefs, "--from", dir, "--values", vals}
	code, out, errOut := output(t, func() int { return restore(ctx, target) })
	if code != 0 || body != "Basic" {
		t.Errorf("a key in another case: exit %d, plan sent %q\n%s%s", code, body, out, errOut)
	}

	// Two keys for the one object cannot both be meant.
	write(key + ":\n  properties: {plan: Basic}\n" + tableType + "/logs/law/" + tableUp + ":\n  properties: {plan: Analytics}\n")
	code, out, errOut = output(t, func() int { return restore(ctx, target) })
	if code != 1 || !strings.Contains(errOut, "name one object") {
		t.Errorf("two keys for one object: exit %d\n%s%s", code, out, errOut)
	}
}
