package saas

import (
	"strings"
	"testing"
)

func TestDescribe(t *testing.T) {
	c := NewClient(GitHub, spec(t, "github.json"), "", "", true)
	env, err := c.Describe("github/repo/environments", 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range env.Fields {
		if f.Path == "name" && (f.ReadOnly || !f.Required) {
			t.Errorf("an environment's name names it (in the PUT path); got %+v", f)
		}
		if f.Path == "id" && !f.ReadOnly {
			t.Error("id is the server's")
		}
	}
	if !strings.Contains(strings.Join(env.Notes, " "), "wait_timer") {
		t.Errorf("notes must name what no snapshot can hold: %v", env.Notes)
	}
	l, _ := c.Describe("github/label", 2)
	if len(l.Docs) == 0 || !strings.HasPrefix(l.Docs[0], "https://docs.github.com/rest/issues/labels") {
		t.Errorf("label docs %v", l.Docs)
	}
}
