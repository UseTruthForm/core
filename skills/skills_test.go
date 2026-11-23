package skills

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestEverySkillParses(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	dirs := 0
	for _, e := range ents {
		if e.IsDir() {
			dirs++
		}
	}
	if len(all) == 0 || len(all) != dirs {
		t.Fatalf("%d skills embedded, %d folders: a folder without a SKILL.md", len(all), dirs)
	}
	for _, s := range all {
		// The limits of the Agent Skills layout: a lower-case hyphenated
		// name of at most 64, a description of at most 1024 that says
		// when to use it.
		if !regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`).MatchString(s.Name) || len(s.Name) > 64 {
			t.Errorf("%s: not a skill name", s.Name)
		}
		if len(s.Description) > 1024 || !strings.Contains(s.Description, "Use when") {
			t.Errorf("%s: description must say when to use it, in at most 1024 characters", s.Name)
		}
		for _, must := range []string{"## The rules", "## Read the work list", "## Check", "## What this cannot show", "translation.yaml"} {
			if !strings.Contains(s.Text, must) {
				t.Errorf("%s: no %q", s.Name, must)
			}
		}
		if strings.ContainsAny(s.Text, "<>") && regexp.MustCompile(`<[A-Za-z_-]+>`).MatchString(strings.ReplaceAll(s.Text, "<group/server>", "")) {
			t.Errorf("%s: a placeholder in angle brackets, which an agent may paste into a command", s.Name)
		}
	}
	if _, err := Get("no-such"); err == nil || !strings.Contains(err.Error(), "translate-move-data") {
		t.Errorf("an unknown name must list the skills: %v", err)
	}
}

func TestFrontMatterIsChecked(t *testing.T) {
	for name, text := range map[string]string{
		"no front matter": "# x\n",
		"another name":    "---\nname: other\ndescription: Use when x\n---\n",
		"no description":  "---\nname: x\n---\n",
		"an unknown key":  "---\nname: x\ndescription: Use when x\nallowed-tools: Bash\n---\n",
	} {
		if _, err := parse("x", text); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if s, err := parse("x", "---\nname: x\ndescription: Use when x\n---\nbody\n"); err != nil || s.Description != "Use when x" {
		t.Errorf("a good one: %v %+v", err, s)
	}
}

// A skill tells an agent to look for the translation's own words in its
// report. Each phrase here is in a skill and in the translation's code:
// when a requirement is reworded, this fails and the skill is reworded
// with it.
func TestSkillsQuoteWhatTheTranslationWrites(t *testing.T) {
	var code strings.Builder
	paths, _ := filepath.Glob("../internal/translate/*.go")
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		code.Write(b)
	}
	if code.Len() == 0 {
		t.Fatal("the translation's code was not found")
	}
	for skill, phrases := range map[string][]string{
		"translate-move-data": {"Blobs are not copied", "Images are not copied", "hold no value", "then move its data", "persistent volumes' data is not moved",
			"AWS DataSync or S3 Batch Operations; the Storage Transfer Service", "crane copy", "--values"},
		"translate-grant-access": {"People, groups and pipelines are not translated", "dentity of a VM, an app service or a pipeline", "custom role", "gives nothing there on Azure"},
		"translate-rebuild-machines": {`attached: requirement`, "to virtual appliance", "forwarded traffic for other addresses", "accepted traffic the peer forwarded",
			"canIpForward", "not looked at"},
		"translate-sql-tls":   {"properties.minimalTlsVersion", "acceptTlsFloor", "rds.force_ssl", "ENCRYPTED_ONLY"},
		"translate-flow-logs": {"AWS::EC2::FlowLog", "logConfig", "tcp-flags", "vpc_flows"},
	} {
		s, err := Get(skill)
		if err != nil {
			t.Fatal(err)
		}
		flat := strings.Join(strings.Fields(s.Text), " ")
		for _, p := range phrases {
			q := strings.TrimPrefix(p, "attached: ")
			if !strings.Contains(flat, p) {
				t.Errorf("%s no longer says %q", skill, p)
			}
			if !strings.Contains(code.String(), q) {
				t.Errorf("%s quotes %q, which the translation no longer writes", skill, q)
			}
		}
	}
}
