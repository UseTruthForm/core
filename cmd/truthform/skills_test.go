package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/usetruthform/core/skills"
)

// The MCP server serves the text of the folders, not a copy of it.
func TestMCPServesTheSkills(t *testing.T) {
	tools := map[string]func(context.Context, map[string]any) (string, error){}
	for _, tool := range mcpTools() {
		tools[tool.Name] = tool.Call
	}
	list, err := tools["list_skills"](context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	all, err := skills.All()
	if err != nil || len(all) != 6 {
		t.Fatalf("%d skills, %v", len(all), err)
	}
	for _, s := range all {
		if !strings.Contains(list, s.Name+"\n  "+s.Description) {
			t.Errorf("list_skills does not name %s with its description", s.Name)
		}
		got, err := tools["skill"](context.Background(), map[string]any{"name": s.Name})
		file, ferr := os.ReadFile(filepath.Join("..", "..", "skills", s.Name, "SKILL.md"))
		if err != nil || ferr != nil || got != string(file) {
			t.Errorf("skill %s is not its file's text (%v, %v)", s.Name, err, ferr)
		}
	}
	if _, err := tools["skill"](context.Background(), map[string]any{"name": "../../etc/passwd"}); err == nil {
		t.Error("a name that is not a skill was served")
	}
	if !strings.Contains(mcpInstructions, "list_skills") {
		t.Error("the server's instructions do not point at the skills")
	}
}

func TestSkillsWritesFoldersAndKeepsAnEditedOne(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "skills")
	if code := skillsCmd([]string{"--out", dir}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	p := filepath.Join(dir, "translate-move-data", "SKILL.md")
	b, err := os.ReadFile(p)
	if err != nil || !strings.HasPrefix(string(b), "---\nname: translate-move-data\n") {
		t.Fatalf("%v %.40q", err, b)
	}
	// Again: nothing to do, and no error.
	if code := skillsCmd([]string{"--out", dir}); code != 0 {
		t.Errorf("a second write: exit %d", code)
	}
	if err := os.WriteFile(p, []byte("mine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := skillsCmd([]string{"--out", dir}); code != 1 {
		t.Errorf("an edited skill: exit %d, want 1", code)
	}
	if b, _ := os.ReadFile(p); string(b) != "mine\n" {
		t.Errorf("an edited skill was overwritten: %q", b)
	}
	if code := skillsCmd([]string{"no-such"}); code == 0 {
		t.Error("an unknown skill printed")
	}
	if code := skillsCmd([]string{"--out", dir, "translate-move-data"}); code != 1 {
		t.Error("a name with --out was accepted")
	}
}
