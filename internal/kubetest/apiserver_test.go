package kubetest_test

import (
	"testing"

	"github.com/stackdna/core/internal/kube"
	"github.com/stackdna/core/internal/kubetest"
)

func TestStartServesTheAPI(t *testing.T) {
	s := kubetest.Start(t, "smoke")
	c, err := kube.Connect(s.Kubeconfig, s.Context, true)
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.Discovery.ServerVersion()
	if err != nil {
		t.Fatalf("server version: %v", err)
	}
	if v.GitVersion == "" {
		t.Fatal("empty server version")
	}
	t.Logf("API server %s up", v.GitVersion)
}
