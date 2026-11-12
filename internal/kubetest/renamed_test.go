package kubetest

import (
	"strings"
	"testing"
)

// A variable left under the tool's old name is reported, for either name.
//
// The failure this pins: after the rename STACKDNA_REQUIRE_KUBE_ASSETS was
// read by nothing, so a CI that still set it had every API-server test
// skip, and the run passed.
func TestAVariableUnderTheOldNameIsReported(t *testing.T) {
	names := []string{"STACKDNA_KUBE_ASSETS", "STACKDNA_REQUIRE_KUBE_ASSETS", AssetsEnv, RequireEnv}
	set := func(vals ...string) {
		for i, n := range names {
			t.Setenv(n, vals[i])
		}
	}
	for _, c := range []struct {
		vals []string
		want string
	}{
		{[]string{"", "", "", ""}, ""},
		{[]string{"", "", "dir", "1"}, ""},
		{[]string{"old", "1", "dir", "1"}, ""},
		{[]string{"old", "", "", ""}, "STACKDNA_KUBE_ASSETS is set, and this build reads TRUTHFORM_KUBE_ASSETS"},
		{[]string{"", "1", "", ""}, "STACKDNA_REQUIRE_KUBE_ASSETS is set, and this build reads TRUTHFORM_REQUIRE_KUBE_ASSETS"},
		{[]string{"old", "1", "dir", ""}, "STACKDNA_REQUIRE_KUBE_ASSETS is set"},
	} {
		set(c.vals...)
		got := renamed()
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("with %v: %q, want %q", c.vals, got, c.want)
		}
	}
}
