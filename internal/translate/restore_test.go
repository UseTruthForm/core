package translate

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/awscc"
	"github.com/usetruthform/core/internal/gcp"
)

// The AWS translation restores, as it is, into the schema-driven fake: it
// refuses an unknown, read-only or missing property, and a reference left
// unresolved, as Cloud Control does. Each queue, topic, subscription and
// policy is created, and every reference resolves to what the account
// generated.
func TestTheAWSTranslationRestores(t *testing.T) {
	reg := targets(t).AWS
	r := run(t, maps()["sqs-sns"])
	s := r.Snapshots["aws"]
	f := awscc.NewWorld(reg).Account("111111111111", "eu-west-1")
	results := awscc.Restore(context.Background(), f, reg, s, awscc.RestoreOptions{}, awscc.Tuning{})
	if len(results) != len(s.Objects) {
		t.Fatalf("%d results for %d objects", len(results), len(s.Objects))
	}
	for _, res := range results {
		if !res.OK {
			t.Errorf("%s: %s", res.Key, res.Detail)
		}
	}
	counts := f.Count()
	// The namespace answered only its firewall's range, so every queue
	// has a policy (the four subscriptions' hold SNS's allow too), and the
	// topic one.
	if counts[awsQueue] != 14 || counts[awsTopic] != 1 || counts[awsSub] != 4 || counts[awsPolicy] != 14 || counts[awsTopicPolicy] != 1 {
		t.Errorf("created: %v", counts)
	}
	// A second restore finds everything, the inline policies included,
	// which Cloud Control reads by their queue and cannot list.
	for _, res := range awscc.Restore(context.Background(), f, reg, s, awscc.RestoreOptions{}, awscc.Tuning{}) {
		if !res.OK || res.Detail != "already present and identical" {
			t.Errorf("again: %s: %v %s", res.Key, res.OK, res.Detail)
		}
	}
	if after := f.Count(); after[awsQueue] != 14 || after[awsPolicy] != 14 || after[awsTopicPolicy] != 1 {
		t.Errorf("a second restore created more: %v", after)
	}
	// The subscription points at what the account made, not a token.
	for _, id := range f.IDs(awsSub) {
		p := f.Stored(awsSub, id)
		for _, k := range []string{"TopicArn", "Endpoint"} {
			v, _ := p[k].(string)
			if !strings.HasPrefix(v, "arn:") {
				t.Errorf("subscription %s: %s is %q", id, k, v)
			}
		}
	}
}

// The Pub/Sub translation restores into the Discovery-driven fake: topics
// and subscriptions are created with Pub/Sub's own PUT at their names, a
// subscription after its topic, and a second restore finds them all.
func TestThePubSubTranslationRestores(t *testing.T) {
	docs := targets(t).GCP
	s := run(t, maps()["pubsub"]).Snapshots["gcp"]
	f := gcp.NewWorld(docs).Project("target-project", "123456789")
	results := gcp.Restore(context.Background(), f, docs, s, gcp.RestoreOptions{})
	if len(results) != len(s.Objects) {
		t.Fatalf("%d results for %d objects", len(results), len(s.Objects))
	}
	for _, res := range results {
		if !res.OK {
			t.Errorf("%s: %s", res.Key, res.Detail)
		}
	}
	got, err := f.Call(context.Background(), "GET", "https://pubsub.googleapis.com/v1/projects/target-project/subscriptions/events-shipping", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got["topic"] != "projects/target-project/topics/events" || !strings.Contains(fmt.Sprint(got["filter"]), "order.shipped") {
		t.Errorf("events-shipping: %v", got)
	}
	for _, res := range gcp.Restore(context.Background(), f, docs, s, gcp.RestoreOptions{}) {
		if !res.OK || res.Detail != "already present and identical" {
			t.Errorf("again: %s: %v %s", res.Key, res.OK, res.Detail)
		}
	}
}
