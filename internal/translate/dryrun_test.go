package translate

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/awscc"
	"github.com/usetruthform/core/internal/gcp"
	"github.com/usetruthform/core/internal/snapshot"
)

// awsNoWrites is an account that fails the test on any write.
type awsNoWrites struct {
	awscc.CloudControl
	t *testing.T
}

func (a awsNoWrites) Create(_ context.Context, typeName string, _ map[string]any) (string, error) {
	a.t.Errorf("a dry run created a %s", typeName)
	return "", fmt.Errorf("write refused")
}

// Get fails the test when asked for an identifier a dry run could not know.
func (a awsNoWrites) Get(ctx context.Context, typeName, id string) (map[string]any, error) {
	if strings.Contains(id, "known once created") {
		a.t.Errorf("a dry run read %s by an identifier nothing has given yet: %s", typeName, id)
	}
	return a.CloudControl.Get(ctx, typeName, id)
}

func (a awsNoWrites) Update(_ context.Context, typeName, id string, _ []awscc.PatchOp) error {
	a.t.Errorf("a dry run updated %s %s", typeName, id)
	return fmt.Errorf("write refused")
}

// gcpNoWrites is a project that fails the test on any write. Reading an
// allow policy is a POST on some APIs, and is a read.
type gcpNoWrites struct {
	gcp.API
	t *testing.T
}

func (g gcpNoWrites) Call(ctx context.Context, method, url string, body any) (map[string]any, error) {
	if method != "GET" && !strings.Contains(url, ":getIamPolicy") {
		g.t.Errorf("a dry run sent %s %s", method, url)
		return nil, fmt.Errorf("write refused")
	}
	return g.API.Call(ctx, method, url, body)
}

func okKeys(results []snapshot.Result) map[string]bool {
	m := map[string]bool{}
	for _, r := range results {
		if r.OK {
			m[r.Key] = true
		}
	}
	return m
}

// A dry run into AWS writes nothing, says "would create" of exactly the
// objects a restore then creates, and after that restore finds every one
// already there. A queue's inline policy, read by an identifier its queue
// has not yet given, is planned too and not looked for.
func TestAnAWSDryRunWritesNothingAndMatchesTheRestore(t *testing.T) {
	reg := targets(t).AWS
	for name, s := range map[string]snapshot.Snapshot{
		"sqs-sns":  run(t, maps()["sqs-sns"]).Snapshots["aws"],
		"identity": runIdentity(t, identityFixture(), identityMaps()["aws"]).Snapshots["aws"],
	} {
		f := awscc.NewWorld(reg).Account("111111111111", "eu-west-1")
		dry := awscc.Restore(context.Background(), awsNoWrites{f, t}, reg, s, awscc.RestoreOptions{DryRun: true}, awscc.Tuning{})
		if len(dry) != len(s.Objects) || len(s.Objects) == 0 {
			t.Fatalf("%s: %d results for %d objects", name, len(dry), len(s.Objects))
		}
		for _, r := range dry {
			if r.OK && !strings.HasPrefix(r.Detail, "would create") {
				t.Errorf("%s: %s: %s", name, r.Key, r.Detail)
			}
		}
		if c := f.Count(); len(c) != 0 {
			t.Errorf("%s: a dry run left %v", name, c)
		}
		real := awscc.Restore(context.Background(), f, reg, s, awscc.RestoreOptions{}, awscc.Tuning{})
		want, got := okKeys(real), okKeys(dry)
		if len(want) == 0 {
			t.Fatalf("%s: the restore applied nothing", name)
		}
		for _, r := range real {
			if want[r.Key] != got[r.Key] {
				t.Errorf("%s: %s: the dry run said %v, the restore %v (%s)", name, r.Key, got[r.Key], want[r.Key], r.Detail)
			}
		}
		for _, r := range awscc.Restore(context.Background(), awsNoWrites{f, t}, reg, s, awscc.RestoreOptions{DryRun: true}, awscc.Tuning{}) {
			if want[r.Key] && r.Detail != "already present and identical" {
				t.Errorf("%s: after the restore: %s: %s", name, r.Key, r.Detail)
			}
		}
	}
}

// With --update a dry run says what it would change, and changes nothing.
func TestAnAWSDryRunSaysWhatItWouldUpdate(t *testing.T) {
	reg := targets(t).AWS
	s := run(t, maps()["sqs-sns"]).Snapshots["aws"]
	f := awscc.NewWorld(reg).Account("111111111111", "eu-west-1")
	awscc.Restore(context.Background(), f, reg, s, awscc.RestoreOptions{}, awscc.Tuning{})
	var changed string
	for i, o := range s.Objects {
		if o.Kind() == awsQueue && changed == "" {
			body := deepCopyAny(o.Body).(map[string]any)
			body["spec"].(map[string]any)["VisibilityTimeout"] = 777
			s.Objects[i] = snapshot.Object{Body: body}
			changed = o.Key()
		}
	}
	for _, opt := range []awscc.RestoreOptions{{DryRun: true}, {DryRun: true, Update: true}} {
		for _, r := range awscc.Restore(context.Background(), awsNoWrites{f, t}, reg, s, opt, awscc.Tuning{}) {
			if r.Key != changed {
				continue
			}
			switch {
			case !opt.Update && (r.OK || !strings.Contains(r.Detail, "differs")):
				t.Errorf("without --update: %v %s", r.OK, r.Detail)
			case opt.Update && (!r.OK || !strings.HasPrefix(r.Detail, "would update") || !strings.Contains(r.Detail, "VisibilityTimeout")):
				t.Errorf("with --update: %v %s", r.OK, r.Detail)
			}
		}
	}
	if f.Updates != 0 {
		t.Errorf("%d updates were sent", f.Updates)
	}
}

// The same on GCP: nothing written, "would create" (and, for a grant on a
// resource it would create, "would add") of exactly what a restore then
// applies.
func TestAGCPDryRunWritesNothingAndMatchesTheRestore(t *testing.T) {
	docs := targets(t).GCP
	for name, s := range map[string]snapshot.Snapshot{
		"pubsub":   run(t, maps()["pubsub"]).Snapshots["gcp"],
		"identity": runIdentity(t, identityFixture(), identityMaps()["gcp"]).Snapshots["gcp"],
	} {
		f := gcp.NewWorld(docs).Project("target-project", "123456789")
		f.EmailNames = true
		dry := gcp.Restore(context.Background(), gcpNoWrites{f, t}, docs, s, gcp.RestoreOptions{DryRun: true})
		if len(dry) != len(s.Objects) || len(s.Objects) == 0 {
			t.Fatalf("%s: %d results for %d objects", name, len(dry), len(s.Objects))
		}
		adds := 0
		for _, r := range dry {
			if strings.HasPrefix(r.Detail, "would add") {
				adds++
			}
			if r.OK && !strings.HasPrefix(r.Detail, "would create") && !strings.HasPrefix(r.Detail, "would add") {
				t.Errorf("%s: %s: %s", name, r.Key, r.Detail)
			}
		}
		if name == "identity" && adds == 0 {
			t.Errorf("identity: no grant was planned")
		}
		if f.Count() != 0 || f.PolicyWrites != 0 {
			t.Errorf("%s: a dry run left %v and wrote %d policies", name, f.Names(), f.PolicyWrites)
		}
		real := gcp.Restore(context.Background(), f, docs, s, gcp.RestoreOptions{})
		want, got := okKeys(real), okKeys(dry)
		if len(want) == 0 {
			t.Fatalf("%s: the restore applied nothing", name)
		}
		for _, r := range real {
			if want[r.Key] != got[r.Key] {
				t.Errorf("%s: %s: the dry run said %v, the restore %v (%s)", name, r.Key, got[r.Key], want[r.Key], r.Detail)
			}
		}
		for _, r := range gcp.Restore(context.Background(), gcpNoWrites{f, t}, docs, s, gcp.RestoreOptions{DryRun: true}) {
			if want[r.Key] && r.Detail != "already present and identical" {
				t.Errorf("%s: after the restore: %s: %s", name, r.Key, r.Detail)
			}
		}
	}
}

// With --update a GCP dry run says what it would change, and changes nothing.
func TestAGCPDryRunSaysWhatItWouldUpdate(t *testing.T) {
	docs := targets(t).GCP
	s := run(t, maps()["pubsub"]).Snapshots["gcp"]
	f := gcp.NewWorld(docs).Project("target-project", "123456789")
	gcp.Restore(context.Background(), f, docs, s, gcp.RestoreOptions{})
	var changed string
	for i, o := range s.Objects {
		if strings.Contains(o.Name(), "/subscriptions/") && changed == "" {
			body := deepCopyAny(o.Body).(map[string]any)
			body["spec"].(map[string]any)["ackDeadlineSeconds"] = 77
			s.Objects[i] = snapshot.Object{Body: body}
			changed = o.Key()
		}
	}
	if changed == "" {
		t.Fatal("no subscription in the fixture")
	}
	seen := false
	for _, r := range gcp.Restore(context.Background(), gcpNoWrites{f, t}, docs, s, gcp.RestoreOptions{DryRun: true, Update: true}) {
		if r.Key == changed {
			seen = true
			if !r.OK || !strings.HasPrefix(r.Detail, "would update") || !strings.Contains(r.Detail, "ackDeadlineSeconds") {
				t.Errorf("%v %s", r.OK, r.Detail)
			}
		}
	}
	if !seen {
		t.Error("no result for the changed subscription")
	}
}

// A grant missing from a resource that exists is said, and not written.
func TestAGCPDryRunSaysTheGrantItWouldAdd(t *testing.T) {
	docs := targets(t).GCP
	s := runIdentity(t, identityFixture(), identityMaps()["gcp"]).Snapshots["gcp"]
	f := gcp.NewWorld(docs).Project("target-project", "123456789")
	f.EmailNames = true
	gcp.Restore(context.Background(), f, docs, s, gcp.RestoreOptions{})
	writes := f.PolicyWrites
	var changed string
	for i, o := range s.Objects {
		if o.Kind() == gcp.BindingKind && changed == "" {
			body := deepCopyAny(o.Body).(map[string]any)
			b := body["spec"].(map[string]any)["bindings"].([]any)[0].(map[string]any)
			b["members"] = append(b["members"].([]any), "serviceAccount:extra@target-project.iam.gserviceaccount.com")
			s.Objects[i] = snapshot.Object{Body: body}
			changed = o.Key()
		}
	}
	seen := false
	for _, r := range gcp.Restore(context.Background(), gcpNoWrites{f, t}, docs, s, gcp.RestoreOptions{DryRun: true}) {
		if r.Key == changed {
			seen = true
			if !r.OK || !strings.HasPrefix(r.Detail, "would add") || !strings.Contains(r.Detail, "extra@") {
				t.Errorf("%v %s", r.OK, r.Detail)
			}
		}
	}
	if !seen || f.PolicyWrites != writes {
		t.Errorf("seen %v; %d policy writes during the dry run", seen, f.PolicyWrites-writes)
	}
}
