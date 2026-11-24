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
	// taken are bucket names another account holds: read, never listed.
	taken map[string]bool
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
	if typeName == awsBucket && a.taken[id] {
		return map[string]any{"BucketName": id}, nil
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
	// disabled are the services not enabled, taken the bucket names
	// another project holds, accounts the service accounts the project
	// already has.
	disabled, taken, accounts map[string]bool
}

func (g gcpNoWrites) Call(ctx context.Context, method, url string, body any) (map[string]any, error) {
	if host, ok := strings.CutPrefix(url, "https://serviceusage.googleapis.com/v1/projects/target-project/services/"); ok && method == "GET" {
		if g.disabled[host] {
			return map[string]any{"state": "DISABLED"}, nil
		}
		return map[string]any{"state": "ENABLED"}, nil
	}
	if name, ok := strings.CutPrefix(url, "https://storage.googleapis.com/storage/v1/b/"); ok && method == "GET" && g.taken[name] {
		return nil, fmt.Errorf("GET %s: HTTP 403: caller does not have storage.buckets.get access", url)
	}
	if i := strings.Index(url, "/serviceAccounts/"); i >= 0 && method == "GET" && g.accounts[url[i+len("/serviceAccounts/"):]] {
		return map[string]any{"email": url[i+len("/serviceAccounts/"):]}, nil
	}
	if method != "GET" && !strings.Contains(url, ":getIamPolicy") {
		g.t.Errorf("a dry run sent %s %s", method, url)
		return nil, fmt.Errorf("write refused")
	}
	return g.API.Call(ctx, method, url, body)
}

// gcpNodeAccounts is the node service account the identity fixture's map
// names, which the project has to hold already.
var gcpNodeAccounts = map[string]bool{"gke-shop-nodes@target-project.iam.gserviceaccount.com": true}

// noNotes fails the test when a dry run could not check something.
func noNotes(t *testing.T) func(string) {
	return func(s string) { t.Errorf("not checked: %s", s) }
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
		// The roles the fixture's map names for the cluster and its
		// nodes, which the account has to hold already.
		for _, role := range []string{"eks-shop", "eks-shop-nodes"} {
			f.Seed("AWS::IAM::Role", map[string]any{"RoleName": role, "AssumeRolePolicyDocument": map[string]any{}})
		}
		dry := awscc.Restore(context.Background(), awsNoWrites{CloudControl: f, t: t}, reg, s, awscc.RestoreOptions{DryRun: true, Note: noNotes(t)}, awscc.Tuning{})
		if len(dry) != len(s.Objects) || len(s.Objects) == 0 {
			t.Fatalf("%s: %d results for %d objects", name, len(dry), len(s.Objects))
		}
		for _, r := range dry {
			if r.OK && !strings.HasPrefix(r.Detail, "would create") {
				t.Errorf("%s: %s: %s", name, r.Key, r.Detail)
			}
		}
		if c := f.Count(); len(c) != 1 || c["AWS::IAM::Role"] != 2 {
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
		for _, r := range awscc.Restore(context.Background(), awsNoWrites{CloudControl: f, t: t}, reg, s, awscc.RestoreOptions{DryRun: true, Note: noNotes(t)}, awscc.Tuning{}) {
			if want[r.Key] && !strings.HasPrefix(r.Detail, "already present") {
				t.Errorf("%s: after the restore: %s: %s", name, r.Key, r.Detail)
			}
		}
		// A restore again says the same: the cluster names its roles by
		// their ARNs, the account's inventory by their names, and that is
		// no difference.
		for _, r := range awscc.Restore(context.Background(), f, reg, s, awscc.RestoreOptions{}, awscc.Tuning{}) {
			if want[r.Key] && !strings.HasPrefix(r.Detail, "already present") {
				t.Errorf("%s: a second restore: %s: %s", name, r.Key, r.Detail)
			}
		}
		if f.Updates != 0 {
			t.Errorf("%s: %d updates were sent", name, f.Updates)
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
		for _, r := range awscc.Restore(context.Background(), awsNoWrites{CloudControl: f, t: t}, reg, s, opt, awscc.Tuning{}) {
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
		dry := gcp.Restore(context.Background(), gcpNoWrites{API: f, t: t, accounts: gcpNodeAccounts}, docs, s, gcp.RestoreOptions{DryRun: true, Note: noNotes(t)})
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
		for _, r := range gcp.Restore(context.Background(), gcpNoWrites{API: f, t: t, accounts: gcpNodeAccounts}, docs, s, gcp.RestoreOptions{DryRun: true, Note: noNotes(t)}) {
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
	for _, r := range gcp.Restore(context.Background(), gcpNoWrites{API: f, t: t, accounts: gcpNodeAccounts}, docs, s, gcp.RestoreOptions{DryRun: true, Update: true}) {
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
			b["members"] = append(b["members"].([]any), "user:extra@example.com")
			s.Objects[i] = snapshot.Object{Body: body}
			changed = o.Key()
		}
	}
	seen := false
	for _, r := range gcp.Restore(context.Background(), gcpNoWrites{API: f, t: t, accounts: gcpNodeAccounts}, docs, s, gcp.RestoreOptions{DryRun: true, Note: noNotes(t)}) {
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

// What the account's inventory does not show and would refuse a create is
// read for: a bucket name another account holds, and a role a resource
// names that is neither in the account nor in the snapshot. What refers to
// one refused is refused with it, and the rest is still planned.
func TestAnAWSDryRunFindsWhatWouldRefuseACreate(t *testing.T) {
	reg := targets(t).AWS
	s := runIdentity(t, identityFixture(), identityMaps()["aws"]).Snapshots["aws"]
	var bucket string
	for _, o := range s.Objects {
		if o.Kind() == awsBucket && bucket == "" {
			bucket, _ = spec(o)["BucketName"].(string)
		}
	}
	if bucket == "" {
		t.Fatal("no bucket in the fixture")
	}
	f := awscc.NewWorld(reg).Account("111111111111", "eu-west-1")
	api := awsNoWrites{CloudControl: f, t: t, taken: map[string]bool{bucket: true}}
	got := map[string]string{}
	planned := 0
	for _, r := range awscc.Restore(context.Background(), api, reg, s, awscc.RestoreOptions{DryRun: true, Note: noNotes(t)}, awscc.Tuning{}) {
		kind := strings.Split(r.Key, "|")[1]
		if r.OK {
			planned++
			continue
		}
		got[kind] += r.Detail + "\n"
	}
	for kind, want := range map[string]string{
		awsBucket:             "the name " + bucket + " is taken",
		awsBucketPolicy:       "which would not be created",
		"AWS::EKS::Cluster":   "names role eks-shop, which is neither in the account nor in the snapshot",
		"AWS::EKS::Nodegroup": "names role eks-shop-nodes, which is neither",
		"AWS::EKS::Addon":     "which would not be created",
	} {
		if !strings.Contains(got[kind], want) {
			t.Errorf("%s: %q", kind, got[kind])
		}
	}
	if strings.Count(got[awsBucket], "\n") != 1 || planned == 0 {
		t.Errorf("%d planned; buckets refused: %q", planned, got[awsBucket])
	}
	if c := f.Count(); len(c) != 0 {
		t.Errorf("left %v", c)
	}
}

// The same on GCP: a service that is not enabled, a bucket name another
// project holds, and a service account that is nowhere.
func TestAGCPDryRunFindsWhatWouldRefuseAWrite(t *testing.T) {
	docs := targets(t).GCP
	s := runIdentity(t, identityFixture(), identityMaps()["gcp"]).Snapshots["gcp"]
	var bucket string
	for _, o := range s.Objects {
		if o.Kind() == "storage.googleapis.com/Bucket" && bucket == "" {
			bucket = o.Name()[strings.LastIndex(o.Name(), "/")+1:]
		}
	}
	if bucket == "" {
		t.Fatal("no bucket in the fixture")
	}
	f := gcp.NewWorld(docs).Project("target-project", "123456789")
	f.EmailNames = true
	api := gcpNoWrites{API: f, t: t, disabled: map[string]bool{"pubsub.googleapis.com": true}, taken: map[string]bool{bucket: true}}
	got := map[string]string{}
	planned := 0
	for _, r := range gcp.Restore(context.Background(), api, docs, s, gcp.RestoreOptions{DryRun: true, Note: noNotes(t)}) {
		kind := strings.Split(r.Key, "|")[1]
		if r.OK {
			planned++
			continue
		}
		got[kind] += r.Detail + "\n"
	}
	for kind, want := range map[string]string{
		"pubsub.googleapis.com/Topic":        "pubsub.googleapis.com is disabled in project target-project",
		"pubsub.googleapis.com/Subscription": "pubsub.googleapis.com is disabled",
		"storage.googleapis.com/Bucket":      "the name " + bucket + " is taken",
		"container.googleapis.com/Cluster":   "names service account gke-shop-nodes@target-project.iam.gserviceaccount.com, which is neither in the project nor in the snapshot",
		gcp.BindingKind:                      "which would not be created",
	} {
		if !strings.Contains(got[kind], want) {
			t.Errorf("%s: %q", kind, got[kind])
		}
	}
	if strings.Count(got["storage.googleapis.com/Bucket"], "\n") != 1 || planned == 0 {
		t.Errorf("%d planned; buckets refused: %q", planned, got["storage.googleapis.com/Bucket"])
	}
	if f.Count() != 0 || f.PolicyWrites != 0 {
		t.Errorf("left %v", f.Names())
	}
}

// A check that could not be made is said, and the object stays planned.
func TestADryRunSaysWhatItCouldNotCheck(t *testing.T) {
	docs := targets(t).GCP
	s := run(t, maps()["pubsub"]).Snapshots["gcp"]
	f := gcp.NewWorld(docs).Project("target-project", "123456789")
	var notes []string
	// The fake itself knows no Service Usage: it answers not found.
	for _, r := range gcp.Restore(context.Background(), f, docs, s, gcp.RestoreOptions{DryRun: true, Note: func(n string) { notes = append(notes, n) }}) {
		if !r.OK {
			t.Errorf("%s: %s", r.Key, r.Detail)
		}
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "could not check that pubsub.googleapis.com is enabled") {
		t.Errorf("notes: %q", notes)
	}
}

// A role the snapshot itself brings is not looked for in the account, even
// named by its ARN and not by a reference.
func TestAnAWSDryRunKnowsTheSnapshotsOwnRoles(t *testing.T) {
	reg := targets(t).AWS
	s := runIdentity(t, identityFixture(), identityMaps()["aws"]).Snapshots["aws"]
	var role, changed string
	for _, o := range s.Objects {
		if o.Kind() == awsRole && role == "" {
			role = o.Name()
		}
	}
	for i, o := range s.Objects {
		if o.Kind() == awsPodAssociation && changed == "" {
			body := deepCopyAny(o.Body).(map[string]any)
			body["spec"].(map[string]any)["RoleArn"] = "arn:aws:iam::{{truthform|account|self|id}}:role/" + role
			s.Objects[i] = snapshot.Object{Body: body}
			changed = o.Key()
		}
	}
	if role == "" || changed == "" {
		t.Fatal("the fixture has no role or no association")
	}
	f := awscc.NewWorld(reg).Account("111111111111", "eu-west-1")
	for _, r := range awscc.Restore(context.Background(), awsNoWrites{CloudControl: f, t: t}, reg, s, awscc.RestoreOptions{DryRun: true, Note: noNotes(t)}, awscc.Tuning{}) {
		if r.Key == changed && !r.OK && !strings.Contains(r.Detail, "would not be created") {
			t.Errorf("%s", r.Detail)
		}
	}
}

// What a policy allows on is a pattern AWS never looks up: a role named
// there, with a wildcard or whole, refuses nothing. A role a property
// takes, missing, still does.
func TestAnAWSDryRunDoesNotLookUpWhatAPolicyAllowsOn(t *testing.T) {
	reg := targets(t).AWS
	s := runIdentity(t, identityFixture(), identityMaps()["aws"]).Snapshots["aws"]
	edited := false
	for i, o := range s.Objects {
		if o.Kind() == awsRole && !edited {
			body := deepCopyAny(o.Body).(map[string]any)
			acct := "arn:aws:iam::{{truthform|account|self|id}}:role/"
			body["spec"].(map[string]any)["Policies"] = []any{map[string]any{"PolicyName": "pass", "PolicyDocument": map[string]any{
				"Version": "2012-10-17", "Statement": []any{
					map[string]any{"Effect": "Allow", "Action": "iam:PassRole", "Resource": acct + "app-*"},
					map[string]any{"Effect": "Allow", "Action": "iam:PassRole", "Resource": []any{acct + "not-there", acct + "path/*"}}}}}}
			s.Objects[i] = snapshot.Object{Body: body}
			edited = true
		}
	}
	if !edited {
		t.Fatal("no role in the fixture")
	}
	f := awscc.NewWorld(reg).Account("111111111111", "eu-west-1")
	f.Seed("AWS::IAM::Role", map[string]any{"RoleName": "eks-shop", "AssumeRolePolicyDocument": map[string]any{}})
	refused := map[string]string{}
	for _, r := range awscc.Restore(context.Background(), awsNoWrites{CloudControl: f, t: t}, reg, s, awscc.RestoreOptions{DryRun: true, Note: noNotes(t)}, awscc.Tuning{}) {
		if !r.OK {
			refused[strings.Split(r.Key, "|")[1]] += r.Detail + "\n"
		}
	}
	// Only the node role is missing: the node group, and nothing for the
	// policy's sake.
	if !strings.Contains(refused["AWS::EKS::Nodegroup"], "names role eks-shop-nodes") || refused[awsRole] != "" || refused[awsPodAssociation] != "" {
		t.Errorf("refused: %q", refused)
	}
	for kind, why := range refused {
		for _, name := range []string{"app-", "not-there", "path"} {
			if strings.Contains(why, "role "+name) {
				t.Errorf("%s: %s", kind, why)
			}
		}
	}
}

// gcpBucketsFail answers every bucket read with a failure that is not a
// refusal, in a text that holds the digits 403.
type gcpBucketsFail struct{ gcp.API }

func (g gcpBucketsFail) Call(ctx context.Context, method, url string, body any) (map[string]any, error) {
	if strings.HasPrefix(url, "https://storage.googleapis.com/storage/v1/b/") && method == "GET" && !strings.Contains(url[len("https://storage.googleapis.com/storage/v1/b/"):], "/") {
		return nil, fmt.Errorf("GET %s: HTTP 503: backend unavailable (request 14037)", url)
	}
	return g.API.Call(ctx, method, url, body)
}

// A bucket read that failed is not a name taken: it is said as not
// checked, and the bucket stays planned.
func TestAGCPDryRunDoesNotTakeAFailedReadForATakenName(t *testing.T) {
	docs := targets(t).GCP
	s := runIdentity(t, identityFixture(), identityMaps()["gcp"]).Snapshots["gcp"]
	f := gcp.NewWorld(docs).Project("target-project", "123456789")
	f.EmailNames = true
	api := gcpBucketsFail{gcpNoWrites{API: f, t: t, accounts: gcpNodeAccounts}}
	var notes []string
	buckets := 0
	for _, r := range gcp.Restore(context.Background(), api, docs, s, gcp.RestoreOptions{DryRun: true, Note: func(n string) { notes = append(notes, n) }}) {
		if !r.OK {
			t.Errorf("%s: %s", r.Key, r.Detail)
		}
		if strings.Split(r.Key, "|")[1] == "storage.googleapis.com/Bucket" {
			buckets++
		}
	}
	unchecked := 0
	for _, n := range notes {
		if strings.Contains(n, "could not check whether the name") {
			unchecked++
		}
	}
	if buckets == 0 || unchecked != buckets {
		t.Errorf("%d buckets, %d said as not checked: %q", buckets, unchecked, notes)
	}
}

// One that would not be created takes with it what waits for it, however
// that is said: a grant that lists the cluster among what it comes after
// holds no reference to it.
func TestAGCPDryRunFollowsWhatAGrantWaitsFor(t *testing.T) {
	docs := targets(t).GCP
	s := runIdentity(t, identityFixture(), identityMaps()["gcp"]).Snapshots["gcp"]
	waits := map[string]bool{}
	for _, o := range s.Objects {
		ann, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
		if after, _ := ann["truthform.org/after"].(string); o.Kind() == gcp.BindingKind && strings.Contains(after, "/clusters/") {
			waits[o.Key()] = true
		}
	}
	if len(waits) == 0 {
		t.Fatal("no grant in the fixture waits for a cluster")
	}
	f := gcp.NewWorld(docs).Project("target-project", "123456789")
	f.EmailNames = true
	// The node service account is nowhere: the cluster would be refused.
	for _, r := range gcp.Restore(context.Background(), gcpNoWrites{API: f, t: t}, docs, s, gcp.RestoreOptions{DryRun: true, Note: noNotes(t)}) {
		if waits[r.Key] && (r.OK || !strings.Contains(r.Detail, "which would not be created")) {
			t.Errorf("%s: %v %s", r.Key, r.OK, r.Detail)
		}
	}
}

// An update is checked as a create is: a role whose trust is changed to
// name, as a principal, a role that is nowhere would be refused by AWS, and
// the dry run says so of the update and of what depends on it.
func TestAnAWSDryRunChecksWhatAnUpdateNames(t *testing.T) {
	reg := targets(t).AWS
	s := runIdentity(t, identityFixture(), identityMaps()["aws"]).Snapshots["aws"]
	f := awscc.NewWorld(reg).Account("111111111111", "eu-west-1")
	for _, role := range []string{"eks-shop", "eks-shop-nodes"} {
		f.Seed("AWS::IAM::Role", map[string]any{"RoleName": role, "AssumeRolePolicyDocument": map[string]any{}})
	}
	for _, r := range awscc.Restore(context.Background(), f, reg, s, awscc.RestoreOptions{}, awscc.Tuning{}) {
		if !r.OK {
			t.Fatalf("%s: %s", r.Key, r.Detail)
		}
	}
	var changed string
	for i, o := range s.Objects {
		if o.Kind() == awsRole && changed == "" {
			body := deepCopyAny(o.Body).(map[string]any)
			doc := body["spec"].(map[string]any)["AssumeRolePolicyDocument"].(map[string]any)
			doc["Statement"] = append(doc["Statement"].([]any), map[string]any{"Effect": "Allow", "Action": "sts:AssumeRole",
				"Principal": map[string]any{"AWS": "arn:aws:iam::{{truthform|account|self|id}}:role/gone"}})
			s.Objects[i] = snapshot.Object{Body: body}
			changed = o.Key()
		}
	}
	seen := false
	for _, r := range awscc.Restore(context.Background(), awsNoWrites{CloudControl: f, t: t}, reg, s, awscc.RestoreOptions{DryRun: true, Update: true, Note: noNotes(t)}, awscc.Tuning{}) {
		if r.Key == changed {
			seen = true
			if r.OK || !strings.Contains(r.Detail, "names role gone, which is neither in the account nor in the snapshot") {
				t.Errorf("%v %s", r.OK, r.Detail)
			}
		} else if !r.OK && !strings.Contains(r.Detail, "which would not be created") {
			t.Errorf("%s: %s", r.Key, r.Detail)
		}
	}
	if !seen || f.Updates != 0 {
		t.Errorf("seen %v; %d updates were sent", seen, f.Updates)
	}
}

// gcpNoEtags answers every allow policy without its etag.
type gcpNoEtags struct{ gcp.API }

func (g gcpNoEtags) Call(ctx context.Context, method, url string, body any) (map[string]any, error) {
	got, err := g.API.Call(ctx, method, url, body)
	if strings.Contains(strings.ToLower(url), "iampolicy") || strings.HasSuffix(url, "/iam") || strings.Contains(url, "/iam?") {
		delete(got, "etag")
	}
	return got, err
}

// A grant on a policy read without its etag is not written by a restore,
// and a dry run says the same, not "would add".
func TestAGCPDryRunRefusesAGrantWithoutAnEtagAsTheRestoreDoes(t *testing.T) {
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
			b["members"] = append(b["members"].([]any), "user:extra@example.com")
			s.Objects[i] = snapshot.Object{Body: body}
			changed = o.Key()
		}
	}
	for _, dry := range []bool{true, false} {
		seen := false
		api := gcp.API(gcpNoEtags{f})
		if dry {
			api = gcpNoEtags{gcpNoWrites{API: f, t: t, accounts: gcpNodeAccounts}}
		}
		for _, r := range gcp.Restore(context.Background(), api, docs, s, gcp.RestoreOptions{DryRun: dry, Note: func(string) {}}) {
			if r.Key == changed {
				seen = true
				if r.OK || !strings.Contains(r.Detail, "came without an etag") {
					t.Errorf("dry run %v: %v %s", dry, r.OK, r.Detail)
				}
			}
		}
		if !seen || f.PolicyWrites != writes {
			t.Errorf("dry run %v: seen %v; %d policy writes", dry, seen, f.PolicyWrites-writes)
		}
	}
}
