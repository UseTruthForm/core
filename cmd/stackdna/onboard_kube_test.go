package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/yaml"

	"github.com/stackdna/core/internal/kube"
	"github.com/stackdna/core/internal/kubetest"
	"github.com/stackdna/core/internal/onboard"
)

// The Kubernetes grant stackdna permissions writes, applied to a real API
// server with RBAC on: a service account bound by it can capture every
// type (Secrets included) and write nothing; before it is applied, and
// after it is deleted, the same capture is refused, and check reports the
// refusals as denied, not as an empty cluster.
func TestKubernetesGrantLetsACaptureReadAndNothingElse(t *testing.T) {
	s := kubetest.Start(t, "grant")
	ctx := context.Background()
	admin, err := kube.Connect(s.Kubeconfig, s.Context, false)
	if err != nil {
		t.Fatal(err)
	}
	cs := kubernetes.NewForConfigOrDie(admin.Config)
	for _, obj := range []func() error{
		func() error {
			_, err := cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "stackdna"}}, metav1.CreateOptions{})
			return err
		},
		func() error {
			_, err := cs.CoreV1().ServiceAccounts("stackdna").Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "reader"}}, metav1.CreateOptions{})
			return err
		},
		func() error {
			_, err := cs.CoreV1().ConfigMaps("default").Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "seed"}, Data: map[string]string{"a": "b"}}, metav1.CreateOptions{})
			return err
		},
	} {
		if err := obj(); err != nil {
			t.Fatal(err)
		}
	}
	tr, err := cs.CoreV1().ServiceAccounts("stackdna").CreateToken(ctx, "reader", &authv1.TokenRequest{}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := clientcmd.LoadFromFile(s.Kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	for _, ai := range cfg.AuthInfos {
		ai.Token = tr.Status.Token
	}
	asReader := filepath.Join(t.TempDir(), "reader.kubeconfig")
	if err := clientcmd.WriteToFile(*cfg, asReader); err != nil {
		t.Fatal(err)
	}

	p, err := onboard.Build(onboard.Request{Platform: "kubernetes", Context: s.Context, Subject: "ServiceAccount:stackdna/reader"})
	if err != nil {
		t.Fatal(err)
	}
	var objs []*unstructured.Unstructured
	for _, doc := range strings.Split(string(p.Files["stackdna-kubernetes.yaml"]), "\n---\n") {
		u := &unstructured.Unstructured{}
		if err := yaml.Unmarshal([]byte(doc), &u.Object); err != nil {
			t.Fatal(err)
		}
		objs = append(objs, u)
	}
	gvr := map[string]schema.GroupVersionResource{
		"ClusterRole":        {Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterroles"},
		"ClusterRoleBinding": {Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterrolebindings"},
	}

	check := func() readCheck {
		snap, err := captureTarget(ctx, Target{Platform: "kubernetes", Kubeconfig: asReader, Context: s.Context})
		// Any other error is not a refusal: the test accepted one before
		// (review of #23).
		if err != nil {
			t.Logf("capture as the reader: %v", err)
			return readCheck{Failed: []string{err.Error()}}
		}
		return classify(snap)
	}
	// RBAC reaches the authorizer through an informer: a change is not
	// seen at once.
	until := func(what string, ok func(readCheck) bool) readCheck {
		var rc readCheck
		for i := 0; i < 40; i++ {
			if rc = check(); ok(rc) {
				return rc
			}
			time.Sleep(250 * time.Millisecond)
		}
		t.Fatalf("%s: never happened; last check %+v", what, rc)
		return rc
	}

	refused := func(rc readCheck) bool {
		return len(rc.Denied) > 0 && strings.Contains(strings.Join(rc.Denied, "\n"), "forbidden")
	}
	until("refused before the grant", refused)

	for _, u := range objs {
		if _, err := admin.Dynamic.Resource(gvr[u.GetKind()]).Create(ctx, u, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	rc := until("every type read after the grant", func(rc readCheck) bool { return len(rc.Denied) == 0 && len(rc.Failed) == 0 })
	if rc.WithObjects == 0 {
		t.Errorf("read nothing: %+v", rc)
	}
	snap, err := captureTarget(ctx, Target{Platform: "kubernetes", Kubeconfig: asReader, Context: s.Context})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, o := range snap.Objects {
		found = found || o.Kind() == "ConfigMap" && o.Name() == "seed"
	}
	if !found {
		t.Error("the seeded ConfigMap is not in the reader's capture")
	}

	// The cluster's own answer for what the grant must not give. get on
	// "*" covered pods/exec and nodes/proxy, and the restore role could
	// mint tokens (review of #23).
	for _, c := range []struct {
		verb, resource, sub string
		want                bool
	}{
		{"list", "secrets", "", true},
		{"list", "pods", "", true},
		{"get", "secrets", "", false},
		{"get", "pods", "exec", false},
		{"create", "pods", "exec", false},
		{"get", "nodes", "proxy", false},
		{"get", "services", "proxy", false},
		{"create", "serviceaccounts", "token", false},
		{"watch", "pods", "", false},
		{"delete", "configmaps", "", false},
	} {
		sar, err := cs.AuthorizationV1().SubjectAccessReviews().Create(ctx, &authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{
			User:               "system:serviceaccount:stackdna:reader",
			Groups:             []string{"system:serviceaccounts", "system:serviceaccounts:stackdna", "system:authenticated"},
			ResourceAttributes: &authzv1.ResourceAttributes{Verb: c.verb, Resource: c.resource, Subresource: c.sub},
		}}, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if sar.Status.Allowed != c.want {
			t.Errorf("%s %s/%s: allowed=%v, want %v", c.verb, c.resource, c.sub, sar.Status.Allowed, c.want)
		}
	}

	// Writes are refused by the cluster itself, not only by StackDNA's
	// guard: this client has no guard.
	reader, err := kube.Connect(asReader, s.Context, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = kubernetes.NewForConfigOrDie(reader.Config).CoreV1().ConfigMaps("default").Create(ctx,
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "written-by-reader"}}, metav1.CreateOptions{})
	if !apierrors.IsForbidden(err) {
		t.Errorf("the capture role wrote, or failed some other way: %v", err)
	}

	// The plan's undo: deleting the same objects takes the access away.
	for _, u := range objs {
		if err := admin.Dynamic.Resource(gvr[u.GetKind()]).Delete(ctx, u.GetName(), metav1.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	until("refused again after the undo", refused)
	_ = os.Remove(asReader)
}
