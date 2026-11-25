package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

// What a dry run says once: each type's write-only values with how many
// resources they are for, and each thing it could not check, once.
func TestDryNotesAreSaidOncePerTypeAndPerCheck(t *testing.T) {
	var n dryNotes
	for i := 0; i < 3; i++ {
		n.without(kindOfKey("aws.truthform.org/v1|AWS::SNS::Subscription||h-1"), "Region")
		n.add("could not check that role r exists: denied")
	}
	n.without("AWS::RDS::DBInstance", "MasterUserPassword")
	n.count("aws.truthform.org/v1|AWS::SQS::Queue||a", true, "would create; write-only, not supplied: X")
	n.count("aws.truthform.org/v1|AWS::SQS::Queue||b", true, "would create")
	n.count("aws.truthform.org/v1|AWS::SQS::Queue||c", true, "already present and identical")
	n.count("aws.truthform.org/v1|AWS::EKS::Cluster||d", false, "names role r, which is neither")
	out := captureStdout(t, n.print)
	for _, want := range []string{"AWS::SNS::Subscription (3): Region", "AWS::RDS::DBInstance (1): MasterUserPassword", "NOT CHECKED: could not check that role r exists: denied",
		"AWS::SQS::Queue: 2 would create, 1 already present", "AWS::EKS::Cluster: 1 would not apply"} {
		if strings.Count(out, want) != 1 {
			t.Errorf("%q is in the output %d times:\n%s", want, strings.Count(out, want), out)
		}
	}
}

func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	f()
	w.Close()
	os.Stdout = old
	b, _ := io.ReadAll(r)
	return string(b)
}

// The JSON document of a dry run says it is one, and what it could not
// check; a real restore's says neither.
func TestADryRunsDocumentSaysItIsOne(t *testing.T) {
	results := []snapshot.Result{{Key: "a", OK: true, Detail: "would create"}}
	real := asJSON(t, func() { emitRestore(results, "aws us-east-1") })
	if _, ok := real["dry_run"]; ok {
		t.Errorf("a real restore: %v", real)
	}
	n := &dryNotes{}
	n.add("could not check that role r exists: denied")
	n.add("could not check that role r exists: denied")
	dryRunOut = n
	defer func() { dryRunOut = nil }()
	dry := asJSON(t, func() { emitRestore(results, "aws us-east-1") })
	if nc, _ := dry["not_checked"].([]any); dry["dry_run"] != true || len(nc) != 1 {
		t.Errorf("a dry run: %v", dry)
	}
}

// Resources of one type that would go without different values are
// counted apart.
func TestDryNotesKeepDifferentValuesApart(t *testing.T) {
	var n dryNotes
	n.without("AWS::RDS::DBInstance", "MasterUserPassword")
	n.without("AWS::RDS::DBInstance", "MasterUserPassword")
	n.without("AWS::RDS::DBInstance", "MasterUserPassword, TdeCredentialPassword")
	out := captureStdout(t, n.print)
	for _, want := range []string{"AWS::RDS::DBInstance (2): MasterUserPassword\n", "AWS::RDS::DBInstance (1): MasterUserPassword, TdeCredentialPassword\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q is not in:\n%s", want, out)
		}
	}
}
