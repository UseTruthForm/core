package kube

import (
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
