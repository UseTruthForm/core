package main

import (
	"io"
	"os"
	"strings"
	"testing"
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
