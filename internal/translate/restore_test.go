package translate

import (
	"context"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/awscc"
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
	if counts[awsQueue] != 10 || counts[awsTopic] != 1 || counts[awsSub] != 2 || counts[awsPolicy] != 2 {
		t.Errorf("created: %v", counts)
	}
	// A second restore finds everything, the inline policies included,
	// which Cloud Control reads by their queue and cannot list.
	for _, res := range awscc.Restore(context.Background(), f, reg, s, awscc.RestoreOptions{}, awscc.Tuning{}) {
		if !res.OK || res.Detail != "already present and identical" {
			t.Errorf("again: %s: %v %s", res.Key, res.OK, res.Detail)
		}
	}
	if after := f.Count(); after[awsQueue] != 10 || after[awsPolicy] != 2 {
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
