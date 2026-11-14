package kube

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

func imageSnapshot() snapshot.Snapshot {
	c := func(name, image string) map[string]any { return map[string]any{"name": name, "image": image} }
	pod := func(m map[string]any) map[string]any { return map[string]any{"spec": m} }
	return snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{
		planObject("apps/v1", "Deployment", "shop", "web", map[string]any{"spec": map[string]any{"template": pod(map[string]any{
			"initContainers": []any{c("init", "old.example.io/shop/init:2")},
			"containers":     []any{c("web", "old.example.io/shop/web:latest"), c("proxy", "envoyproxy/envoy:v1.30")},
			"volumes":        []any{map[string]any{"name": "data", "image": map[string]any{"reference": "old.example.io/shop/data:1"}}},
		})}}),
		planObject("batch/v1", "CronJob", "shop", "nightly", map[string]any{"spec": map[string]any{"jobTemplate": map[string]any{"spec": map[string]any{"template": pod(map[string]any{
			"containers": []any{c("run", "old.example.io/shop/web:latest")},
		})}}}}),
		planObject("keda.sh/v1alpha1", "ScaledJob", "shop", "queue", map[string]any{"spec": map[string]any{"jobTargetRef": map[string]any{"template": pod(map[string]any{
			"containers": []any{c("run", "ghcr.io/acme/queue@sha256:"+strings.Repeat("a", 64))},
		})}}}),
		// Not a pod: a field that happens to be called image.
		planObject("v1", "ConfigMap", "shop", "notes", map[string]any{"data": map[string]any{"image": "old.example.io/shop/web:latest"}}),
		planObject("example.com/v1", "Gadget", "shop", "g", map[string]any{"spec": map[string]any{"image": "old.example.io/shop/web:latest", "containers": "three"}}),
		// Lists that are not a pod's: entries with no name, and init
		// containers with no containers beside them.
		planObject("example.com/v1", "Gadget", "shop", "h", map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"image": "old.example.io/shop/web:latest"}}}}),
		planObject("example.com/v1", "Gadget", "shop", "i", map[string]any{"spec": map[string]any{"initContainers": []any{c("x", "old.example.io/shop/web:latest")}}}),
	}}
}

// A start is applied to every container's image, wherever the pod spec
// is, and to nothing that is not one; what no start fits is counted by
// registry.
func TestRenameImages(t *testing.T) {
	s := imageSnapshot()
	out, rep, err := RenameStores(s, map[string]string{"old.example.io/shop/": "new.example.io/drill/", "ghcr.io/": "ghcr.io/"})
	if err != nil {
		t.Fatal(err)
	}
	var changed []string
	for _, r := range rep.Images {
		changed = append(changed, r.Object+" "+r.Field+": "+r.From+" -> "+r.To)
	}
	want := []string{
		"Deployment shop/web spec.template.spec.containers[].image: old.example.io/shop/web:latest -> new.example.io/drill/web:latest",
		"Deployment shop/web spec.template.spec.initContainers[].image: old.example.io/shop/init:2 -> new.example.io/drill/init:2",
		"Deployment shop/web spec.template.spec.volumes[].image.reference: old.example.io/shop/data:1 -> new.example.io/drill/data:1",
		"CronJob shop/nightly spec.jobTemplate.spec.template.spec.containers[].image: old.example.io/shop/web:latest -> new.example.io/drill/web:latest",
	}
	if !reflect.DeepEqual(changed, want) {
		t.Errorf("changed:\n got %q\nwant %q", changed, want)
	}
	if len(rep.ImagesKept) != 1 || !strings.HasPrefix(rep.ImagesKept[0].From, "ghcr.io/acme/queue@") {
		t.Errorf("kept: %v", rep.ImagesKept)
	}
	if want := []ImagesLeft{{Registry: "docker.io", References: 1}}; !reflect.DeepEqual(rep.ImagesLeft, want) {
		t.Errorf("left: %v, want %v", rep.ImagesLeft, want)
	}
	web := out.Objects[0].Body["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	if got := web["containers"].([]any)[0].(map[string]any)["image"]; got != "new.example.io/drill/web:latest" {
		t.Errorf("the image restored is %v", got)
	}
	if got := web["containers"].([]any)[1].(map[string]any)["image"]; got != "envoyproxy/envoy:v1.30" {
		t.Errorf("an image no start fits became %v", got)
	}
	// What is not a container's image is as it was, and so is the
	// snapshot given.
	for i := 3; i < len(s.Objects); i++ {
		if !reflect.DeepEqual(out.Objects[i].Body, s.Objects[i].Body) {
			t.Errorf("%s was changed", s.Objects[i].Name())
		}
	}
	if !reflect.DeepEqual(s, imageSnapshot()) {
		t.Error("the snapshot given was changed")
	}
	// No store reference is among them, so nothing is listed as one.
	if n := len(rep.Changed) + len(rep.Kept) + len(rep.Unnamed) + len(rep.Within); n != 0 {
		t.Errorf("%d images were reported as store references", n)
	}
}

// A start that fits neither a store reference nor an image is a mistake.
func TestRenameRefusesAStartNoImageFits(t *testing.T) {
	_, _, err := RenameStores(imageSnapshot(), map[string]string{"old.example.io/shop/": "new.example.io/", "old.example.com/": "x/"})
	if err == nil || !strings.Contains(err.Error(), "old.example.com/") || strings.Contains(err.Error(), "old.example.io") {
		t.Errorf("got %v", err)
	}
}

func TestRegistryOf(t *testing.T) {
	for image, want := range map[string]string{
		"nginx":                          "docker.io",
		"library/nginx:1":                "docker.io",
		"acme/team/app:1":                "docker.io",
		"registry.example.io/app:1":      "registry.example.io",
		"localhost/app":                  "localhost",
		"localhost:5000/app":             "localhost:5000",
		"registry:5000/app":              "registry:5000",
		"nginx:1.27":                     "docker.io", // a tag, not a port: no slash follows
		"ghcr.io/acme/app@sha256:abcdef": "ghcr.io",
	} {
		if got := RegistryOf(image); got != want {
			t.Errorf("%s: got %s, want %s", image, got, want)
		}
	}
}

// The plan counts each image once, by registry, and how many have no
// digest.
func TestImagesOf(t *testing.T) {
	want := []PlanImages{
		{Registry: "docker.io", Images: 1, Unpinned: 1},
		{Registry: "ghcr.io", Images: 1, Unpinned: 0},
		{Registry: "old.example.io", Images: 3, Unpinned: 3},
	}
	s := imageSnapshot()
	if got := ImagesOf(s); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if !reflect.DeepEqual(s, imageSnapshot()) {
		t.Error("the snapshot given was changed")
	}
}

// A start ends where a part of an image's reference does: a registry is
// not the start of another whose name begins the same, nor of itself on
// another port, and a path is not the start of its neighbour.
func TestAStartEndsWhereAPartDoes(t *testing.T) {
	for _, c := range []struct {
		image, start string
		want         bool
	}{
		{"registry.corp/app:1", "registry.corp", true},
		{"registry.corp/app:1", "registry.corp/", true},
		{"registry.corp.evil.com/app:1", "registry.corp", false},
		{"registry.corp:5000/app@sha256:abc", "registry.corp", false},
		{"registry.corp:5000/app:1", "registry.corp:5000", true},
		{"registry.corp/team/app:1", "registry.corp/team", true},
		{"registry.corp/team-b/app:1", "registry.corp/team", false},
		{"registry.corp/team:1", "registry.corp/team", true},
		{"registry.corp/team@sha256:abc", "registry.corp/team", true},
		{"registry.corp/team", "registry.corp/team", true},
		{"registry.corp/team-b/app:1", "registry.corp/team-", false},
	} {
		if got := startsImage(c.image, c.start); got != c.want {
			t.Errorf("startsImage(%q, %q) = %v, want %v", c.image, c.start, got, c.want)
		}
	}
	// In a rename: the neighbour is left and counted, not rewritten.
	c := func(name, image string) map[string]any { return map[string]any{"name": name, "image": image} }
	s := snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{
		planObject("v1", "Pod", "shop", "p", map[string]any{"spec": map[string]any{"containers": []any{
			c("a", "registry.corp/app:1"), c("b", "registry.corp.evil.com/app:1"), c("c", "registry.corp:5000/app:1")}}}),
		// Containers under other names: a workflow's and a task's.
		planObject("argoproj.io/v1alpha1", "WorkflowTemplate", "shop", "w", map[string]any{"spec": map[string]any{"templates": []any{
			map[string]any{"name": "t", "container": map[string]any{"image": "registry.corp/step:1"}},
			map[string]any{"name": "u", "script": map[string]any{"image": "registry.corp/script:1", "source": "echo"}}}}}),
		planObject("tekton.dev/v1", "Task", "shop", "t", map[string]any{"spec": map[string]any{
			"stepTemplate": map[string]any{"image": "registry.corp/base:1"},
			"steps":        []any{map[string]any{"name": "build", "image": "registry.corp/build:1"}}, "sidecars": []any{map[string]any{"name": "dind", "image": "registry.corp/dind:1"}}}}),
	}}
	out, rep, err := RenameStores(s, map[string]string{"registry.corp": "drill.corp"})
	if err != nil {
		t.Fatal(err)
	}
	var changed []string
	for _, r := range rep.Images {
		changed = append(changed, r.From+" -> "+r.To)
	}
	sort.Strings(changed)
	want := []string{"registry.corp/app:1 -> drill.corp/app:1", "registry.corp/base:1 -> drill.corp/base:1", "registry.corp/build:1 -> drill.corp/build:1", "registry.corp/dind:1 -> drill.corp/dind:1",
		"registry.corp/script:1 -> drill.corp/script:1", "registry.corp/step:1 -> drill.corp/step:1"}
	if !reflect.DeepEqual(changed, want) {
		t.Errorf("changed:\n got %q\nwant %q", changed, want)
	}
	b, _ := json.Marshal(out.Objects[0].Body)
	if !strings.Contains(string(b), "registry.corp.evil.com/app:1") || !strings.Contains(string(b), "registry.corp:5000/app:1") {
		t.Errorf("another registry's image was rewritten: %s", b)
	}
	if left := fmt.Sprint(rep.ImagesLeft); !strings.Contains(left, "registry.corp.evil.com") || !strings.Contains(left, "registry.corp:5000") || len(rep.ImagesLeft) != 2 {
		t.Errorf("left: %v", left)
	}
	for image, want := range map[string]string{"Registry.Corp/app": "registry.corp", "index.docker.io/library/nginx": "docker.io", "nginx": "docker.io"} {
		if got := RegistryOf(image); got != want {
			t.Errorf("RegistryOf(%q) = %q, want %q", image, got, want)
		}
	}
}
