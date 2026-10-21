package kube_test

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/restmapper"
	"sigs.k8s.io/yaml"

	"github.com/stackdna/core/internal/drilltest"
	"github.com/stackdna/core/internal/kube"
	"github.com/stackdna/core/internal/kubetest"
)

// TestDrillOnAPIServer runs the full restore drill on two real API servers
// (no nodes, no Docker), so every `go test` proves a round trip in seconds.
// scripts/drill-kind.sh is the slower full-fidelity version with running
// controllers.
func TestDrillOnAPIServer(t *testing.T) {
	src, dst := kubetest.Start(t, "drill-src"), kubetest.Start(t, "drill-dst")
	srcC, err := kube.Connect(src.Kubeconfig, src.Context)
	if err != nil {
		t.Fatal(err)
	}
	dstC, err := kube.Connect(dst.Kubeconfig, dst.Context)
	if err != nil {
		t.Fatal(err)
	}

	// Baseline: the fresh target, as a new cluster of this kind would be.
	base, err := kube.Capture(context.Background(), dstC, kube.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	pol := kube.Policy{}.WithBaseline(base, "sha256:fresh-api-server")

	seed(t, srcC, "../../testdata/k8s/workload.yaml")
	seed(t, srcC, "../../testdata/k8s/widget.yaml")

	drilltest.Run(t, drilltest.Spec{
		Source: &kube.Adapter{Clients: srcC, Policy: pol},
		Target: &kube.Adapter{Clients: dstC, Policy: pol, Options: kube.RestoreOptions{SecretSource: srcC}},
		ExpectKeys: []string{
			"apiextensions.k8s.io/v1|CustomResourceDefinition||widgets.example.stackdna.org",
			"apps/v1|Deployment|shop|shop-api",
			"example.stackdna.org/v1|Widget|shop|blue-widget",
			"networking.k8s.io/v1|Ingress|shop|shop",
			"networking.k8s.io/v1|NetworkPolicy|shop|shop-api-ingress",
			"rbac.authorization.k8s.io/v1|Role|shop|read-config",
			"rbac.authorization.k8s.io/v1|RoleBinding|shop|shop-api-read-config",
			"v1|ConfigMap|shop|shop-config",
			"v1|Namespace||shop",
			"v1|PersistentVolumeClaim|shop|shop-data",
			"v1|Secret|shop|shop-db",
			"v1|Service|shop|shop-api",
			"v1|ServiceAccount|shop|shop-api",
		},
	})
}

// seed creates the fixture with plain creates, deliberately not through
// StackDNA's restore, so a restore bug cannot hide behind the seeding path.
func seed(t *testing.T, c *kube.Clients, file string) {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, doc := range bytes.Split(raw, []byte("\n---")) {
		if strings.TrimSpace(stripComments(string(doc))) == "" {
			continue
		}
		obj := map[string]any{}
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		u := &unstructured.Unstructured{Object: obj}
		gvk := u.GroupVersionKind()
		var mapping *meta.RESTMapping
		// A CRD's new type takes a moment to appear in discovery.
		for i := 0; i < 50; i++ {
			mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(c.Discovery))
			if mapping, err = mapper.RESTMapping(gvk.GroupKind(), gvk.Version); err == nil {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("map %s: %v", gvk, err)
		}
		ri := c.Dynamic.Resource(mapping.Resource)
		if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
			_, err = ri.Namespace(u.GetNamespace()).Create(ctx, u, metav1.CreateOptions{})
		} else {
			_, err = ri.Create(ctx, u, metav1.CreateOptions{})
		}
		if err != nil {
			t.Fatalf("create %s %s: %v", gvk.Kind, u.GetName(), err)
		}
		if gvk.Kind == "CustomResourceDefinition" {
			waitEstablished(t, c, u.GetName())
		}
	}
}

func waitEstablished(t *testing.T, c *kube.Clients, name string) {
	t.Helper()
	gvr := schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
	for i := 0; i < 100; i++ {
		u, err := c.Dynamic.Resource(gvr).Get(context.Background(), name, metav1.GetOptions{})
		if err == nil {
			conds, _, _ := unstructured.NestedSlice(u.Object, "status", "conditions")
			for _, cd := range conds {
				m, _ := cd.(map[string]any)
				if m["type"] == "Established" && m["status"] == "True" {
					return
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("CRD %s never became established", name)
}

func stripComments(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			b.WriteString(line + "\n")
		}
	}
	return b.String()
}
