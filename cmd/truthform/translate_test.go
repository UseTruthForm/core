package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

func sbObject(kind, name string, props map[string]any) snapshot.Object {
	return snapshot.Object{Body: map[string]any{"apiVersion": "azure.truthform.org/v1", "kind": kind,
		"metadata": map[string]any{"name": name, "namespace": "rg"}, "spec": map[string]any{"properties": props}}}
}

// translate writes a snapshot per target and its report, in both builds;
// it rewrites its own directory, removing a platform the new map no longer
// writes, and refuses anyone else's.
func TestTranslateCommand(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "azure")
	s := snapshot.Snapshot{Platform: "azure", Policy: "default", Objects: []snapshot.Object{
		sbObject("Microsoft.ServiceBus/namespaces", "shop", map[string]any{"disableLocalAuth": true, "minimumTlsVersion": "1.2"}),
		sbObject("Microsoft.ServiceBus/namespaces/queues", "shop/orders", map[string]any{"lockDuration": "PT1M", "maxDeliveryCount": 10, "defaultMessageTimeToLive": "P1D"}),
	}}
	if err := s.Write(src); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	aws := write("aws.yaml", "to: aws\nregion: eu-west-1\ndestinations:\n  messaging: sqs-sns\n")
	out := filepath.Join(dir, "out")
	schemas := filepath.Join("..", "..", "testdata", "aws", "schemas")
	if code := translateCmd([]string{"--from", src, "--map", aws, "--out", out, "--schemas", schemas}); code != 0 {
		t.Fatalf("aws: exit %d", code)
	}
	back, err := snapshot.Read(filepath.Join(out, "aws"))
	if err != nil {
		t.Fatal(err)
	}
	if back.Platform != "aws" || len(back.Objects) != 2 {
		t.Fatalf("aws snapshot: %s, %d objects", back.Platform, len(back.Objects))
	}
	if _, err := os.Stat(filepath.Join(out, reportFile)); err != nil {
		t.Fatal(err)
	}
	// In the cluster with no certificate: plain text where Service Bus
	// took only TLS, so exit 3; and the aws snapshot goes.
	rmq := write("rmq.yaml", "to: aws\nregion: eu-west-1\ndestinations:\n  messaging: rabbitmq\nrabbitmq:\n  namespace: messaging\n  replicas: 3\n")
	if code := translateCmd([]string{"--from", src, "--map", rmq, "--out", out}); code != 3 {
		t.Fatalf("rabbitmq: exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(out, "aws")); !os.IsNotExist(err) {
		t.Errorf("the earlier aws snapshot is still there: %v", err)
	}
	if _, err := snapshot.Read(filepath.Join(out, "kubernetes")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(out, reportFile))
	if !strings.Contains(string(b), "widens: true") {
		t.Errorf("the report does not say the brokers are less protected:\n%s", b)
	}
	// Someone else's directory is refused.
	other := filepath.Join(dir, "other")
	os.MkdirAll(other, 0o755)
	write("other/notes.txt", "mine")
	if code := translateCmd([]string{"--from", src, "--map", aws, "--out", other, "--schemas", schemas}); code != 1 {
		t.Errorf("a foreign directory: exit %d", code)
	}
	// A snapshot of another platform is refused.
	if code := translateCmd([]string{"--from", filepath.Join(out, "kubernetes"), "--map", aws, "--out", filepath.Join(dir, "x"), "--schemas", schemas}); code != 1 {
		t.Errorf("a kubernetes snapshot: exit %d", code)
	}
}
