package awscc

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

// A type Cloud Control reads and cannot list is looked for by the
// identifier its snapshot gives: created when absent, found when present,
// reported when it differs, and refused when the identifier is not given.
func TestRestoreLooksUpWhatCannotBeListed(t *testing.T) {
	dir := t.TempDir()
	for src, name := range map[string]string{
		filepath.Join("..", "..", "testdata", "aws", "schemas", "aws-sqs-queue.json"):         "q.json",
		filepath.Join("..", "translate", "testdata", "aws", "aws-sqs-queueinlinepolicy.json"): "p.json",
	} {
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dir, name), b, 0o644)
	}
	reg, err := ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	obj := func(kind, name string, spec map[string]any) snapshot.Object {
		return snapshot.Object{Body: map[string]any{"apiVersion": APIVersion, "kind": kind, "metadata": map[string]any{"name": name}, "spec": spec}}
	}
	doc := func(effect string) map[string]any {
		return map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": effect, "Principal": "*", "Action": "sqs:SendMessage", "Resource": "*"}}}
	}
	snap := func(effect string) snapshot.Snapshot {
		return snapshot.Snapshot{Platform: "aws", Objects: []snapshot.Object{
			obj("AWS::SQS::Queue", "q", map[string]any{"QueueName": "q"}),
			obj("AWS::SQS::QueueInlinePolicy", "q", map[string]any{"Queue": "{{truthform|AWS::SQS::Queue|q|QueueUrl}}", "PolicyDocument": doc(effect)}),
		}}
	}
	f := NewWorld(reg).Account("111111111111", "eu-west-1")
	detail := func(s snapshot.Snapshot) string {
		for _, r := range Restore(context.Background(), f, reg, s, RestoreOptions{}, Tuning{}) {
			if strings.Contains(r.Key, "QueueInlinePolicy") {
				return r.Detail
			}
		}
		return ""
	}
	if d := detail(snap("Allow")); !strings.HasPrefix(d, "created ") {
		t.Fatalf("first: %s", d)
	}
	if d := detail(snap("Allow")); d != "already present and identical" {
		t.Errorf("again: %s", d)
	}
	if d := detail(snap("Deny")); !strings.Contains(d, "differs (PolicyDocument)") {
		t.Errorf("changed: %s", d)
	}
	if n := f.Count()["AWS::SQS::QueueInlinePolicy"]; n != 1 {
		t.Errorf("%d policies", n)
	}
	// In a dry run, one whose identifier is known is looked for even when
	// another of its values names what would only then be created: said to
	// be created, a policy that is there and differs went unreported.
	dry := func(s snapshot.Snapshot) string {
		for _, r := range Restore(context.Background(), f, reg, s, RestoreOptions{DryRun: true}, Tuning{}) {
			if strings.Contains(r.Key, "QueueInlinePolicy") {
				return r.Detail
			}
		}
		return ""
	}
	later := doc("Allow")
	later["Statement"].([]any)[0].(map[string]any)["Resource"] = "{{truthform|AWS::SQS::Queue|new|Arn}}"
	partly := snap("Allow")
	partly.Objects = append(partly.Objects, obj("AWS::SQS::Queue", "new", map[string]any{"QueueName": "new"}))
	partly.Objects[1].Body["spec"].(map[string]any)["PolicyDocument"] = later
	if d := dry(partly); !strings.Contains(d, "differs (PolicyDocument)") {
		t.Errorf("identifier known, another value not: %s", d)
	}
	// When the identifier itself is not known yet, there is nothing to ask with.
	unmade := snapshot.Snapshot{Platform: "aws", Objects: []snapshot.Object{
		obj("AWS::SQS::Queue", "new", map[string]any{"QueueName": "new"}),
		obj("AWS::SQS::QueueInlinePolicy", "new", map[string]any{"Queue": "{{truthform|AWS::SQS::Queue|new|QueueUrl}}", "PolicyDocument": doc("Allow")}),
	}}
	if d := dry(unmade); !strings.HasPrefix(d, "would create") {
		t.Errorf("identifier not known: %s", d)
	}
	if n := f.Count()["AWS::SQS::Queue"]; n != 1 {
		t.Errorf("a dry run made a queue: %d", n)
	}

	// With no queue to name it by, it cannot be looked for.
	bare := snapshot.Snapshot{Platform: "aws", Objects: []snapshot.Object{obj("AWS::SQS::QueueInlinePolicy", "x", map[string]any{"PolicyDocument": doc("Allow")})}}
	if d := detail(bare); !strings.Contains(d, "does not give its identifier") {
		t.Errorf("no identifier: %s", d)
	}
}
