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
	out := captureStdout(t, n.print)
	for _, want := range []string{"AWS::SNS::Subscription (3): Region", "AWS::RDS::DBInstance (1): MasterUserPassword", "NOT CHECKED: could not check that role r exists: denied"} {
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
