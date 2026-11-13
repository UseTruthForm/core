package kube

import (
	"reflect"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

// A value is written into each place one was withheld at, and a place with
// no value, or that the object does not have, is an error: an object is
// not applied with a credential still empty.
func TestSetSlots(t *testing.T) {
	body := func() map[string]any {
		return map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"name": "api", "namespace": "shop"},
			"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "api", "env": []any{
				map[string]any{"name": "DB_PASSWORD", "value": ""}, map[string]any{"name": "API_TOKEN", "value": ""}}}}}}}}
	}
	const pw, tok = "spec.template.spec.containers[api].env[DB_PASSWORD]", "spec.template.spec.containers[api].env[API_TOKEN]"
	b := body()
	if err := setSlots(b, []string{pw, tok}, map[string]string{pw: "one", tok: "two"}); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, sl := range slots(b) {
		got[sl.path] = sl.value
	}
	if got[pw] != "one" || got[tok] != "two" {
		t.Errorf("after setSlots: %v", got)
	}
	if err := setSlots(body(), []string{pw, tok}, map[string]string{pw: "one"}); err == nil || !strings.Contains(err.Error(), "no value for "+tok) {
		t.Errorf("a place with no value: %v", err)
	}
	if err := setSlots(body(), []string{"spec.gone"}, map[string]string{"spec.gone": "x"}); err == nil || !strings.Contains(err.Error(), "no slot spec.gone") {
		t.Errorf("a place the object does not have: %v", err)
	}
}

// The objects a restore refuses until supplied are those with the
// annotation, each with its places, in the order of their keys.
func TestWithheldSettings(t *testing.T) {
	with := func(kind, name, paths string) snapshot.Object {
		o := planObject("v1", kind, "shop", name, nil)
		if paths != "" {
			o.Body["metadata"].(map[string]any)["annotations"] = map[string]any{WithheldEnvAnnotation: paths}
		}
		return o
	}
	got := WithheldSettings(snapshot.Snapshot{Objects: []snapshot.Object{with("ConfigMap", "b", "data[x],data[y]"), with("ConfigMap", "plain", ""), with("ConfigMap", "a", "data[url]")}})
	if len(got) != 2 || got[0].Key != "v1|ConfigMap|shop|a" || strings.Join(got[1].Paths, " ") != "data[x] data[y]" {
		t.Errorf("%+v", got)
	}
	if WithheldSettings(snapshot.Snapshot{}) == nil {
		t.Error("nil for none: a list as JSON has to be a list")
	}
}

// Every value withheld has a path of its own, whatever its list's names:
// a name that is a number is not another's index, and a comma in a name
// does not cut the list of paths in two.
func TestSlotPathsAreOnePerValue(t *testing.T) {
	obj := func() map[string]any {
		return map[string]any{"apiVersion": "example.com/v1", "kind": "Pipeline", "metadata": map[string]any{"name": "p", "namespace": "x"},
			"spec": map[string]any{
				"containers": []any{map[string]any{"name": "c", "env": []any{
					map[string]any{"name": "1", "value": "postgres://u:s3cr3t-a@h/db"},
					map[string]any{"name": "API_TOKEN", "value": "s3cr3t-b"},
					map[string]any{"name": "API_TOKEN", "value": "s3cr3t-c"},
					map[string]any{"name": "DB,PASSWORD", "value": "s3cr3t-d"},
					map[string]any{"name": "PCT%_PASSWORD", "value": "s3cr3t-e"},
				}}},
				"steps": []any{
					map[string]any{"env": []any{map[string]any{"name": "API_TOKEN", "value": "s3cr3t-f"}}},
					map[string]any{"name": "0", "env": []any{map[string]any{"name": "API_TOKEN", "value": "s3cr3t-g"}}},
				},
			}}
	}
	o := obj()
	live := map[string]string{}
	for _, sl := range slots(o) {
		live[sl.path] = sl.value
	}
	normalize("example.com", "pipelines", o)
	held := WithheldSettings(snapshot.Snapshot{Objects: []snapshot.Object{{Body: o}}})
	if len(held) != 1 || len(held[0].Paths) != 7 {
		t.Fatalf("withheld: %+v", held)
	}
	seen := map[string]bool{}
	for _, p := range held[0].Paths {
		if seen[p] || strings.ContainsAny(p, ",") {
			t.Errorf("the path %q is not one value's alone", p)
		}
		seen[p] = true
	}
	// Filled from what was there, every value is back where it was.
	body := deepCopy(o)
	if err := setSlots(body, withheldEnv(body), live); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(body["spec"], obj()["spec"]) {
		t.Errorf("after filling:\n got %v\nwant %v", body["spec"], obj()["spec"])
	}
	// Asked for twice, a path is refused.
	if err := setSlots(deepCopy(o), []string{held[0].Paths[0], held[0].Paths[0]}, live); err == nil || !strings.Contains(err.Error(), "two values of the object") {
		t.Errorf("a path asked for twice: %v", err)
	}
}

// What the API server says of an object it refuses does not repeat a value
// that was supplied for it.
func TestRedacted(t *testing.T) {
	got := redacted(`spec.env[0].value: Invalid value: "s3cr3t-value": must match ^x`, []string{"s3cr3t-value", "ab", ""})
	if strings.Contains(got, "s3cr3t") || !strings.Contains(got, "(a supplied value)") || !strings.Contains(got, "must match") {
		t.Errorf("redacted: %q", got)
	}
}
