package gcp

import (
	"strings"
	"testing"
)

func TestDescribe(t *testing.T) {
	docs := fixtures(t)
	sa, err := docs.Describe("iam", "v1", "projects.serviceAccounts", 3)
	if err != nil {
		t.Fatal(err)
	}
	flags := map[string]bool{}
	for _, f := range sa.Fields {
		flags[f.Path] = f.ReadOnly
	}
	if !flags["email"] || !flags["uniqueId"] || flags["displayName"] {
		t.Errorf("output-only flags wrong: %v", flags)
	}
	if !strings.Contains(strings.Join(sa.Notes, " "), "iam.projects.serviceAccounts.patch") {
		t.Errorf("notes %v", sa.Notes)
	}
	cs, err := docs.Collections("compute", "v1")
	if err != nil || !strings.Contains(strings.Join(cs, "\n"), "networks (Network)") {
		t.Errorf("collections %v %v", cs, err)
	}
}
