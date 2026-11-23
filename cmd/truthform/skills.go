package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/usetruthform/core/internal/mcp"
	"github.com/usetruthform/core/skills"
)

// skillsCmd lists the agent skills the binary carries, prints one, or
// writes them out as folders an agent loads (<dir>/<name>/SKILL.md). It
// makes no request. A SKILL.md that is already there with other text is
// left as it is and named: it may be the person's own edit.
func skillsCmd(args []string) int {
	fs := flag.NewFlagSet("skills", flag.ContinueOnError)
	out := fs.String("out", "", "directory to write each skill into, as <dir>/<name>/SKILL.md (for Claude Code: .claude/skills)")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	all, err := skills.All()
	if err != nil {
		return fail(err)
	}
	switch {
	case *out != "" && fs.NArg() == 0:
		kept := 0
		for _, s := range all {
			p := filepath.Join(*out, s.Name, "SKILL.md")
			if old, err := os.ReadFile(p); err == nil {
				if !bytes.Equal(old, []byte(s.Text)) {
					fmt.Fprintf(os.Stderr, "skills: %s is there with other text; left as it is (move it away to take this build's)\n", p)
					kept++
				}
				continue
			}
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				return fail(err)
			}
			if err := os.WriteFile(p, []byte(s.Text), 0o644); err != nil {
				return fail(err)
			}
			fmt.Println(p)
		}
		if kept > 0 {
			return 1
		}
	case *out == "" && fs.NArg() == 1:
		s, err := skills.Get(fs.Arg(0))
		if err != nil {
			return fail(err)
		}
		fmt.Print(s.Text)
	case *out == "" && fs.NArg() == 0:
		fmt.Print(skillsList(all))
	default:
		fmt.Fprintln(os.Stderr, "usage: truthform skills [<name> | --out <dir>]")
		return 1
	}
	return 0
}

func skillsList(all []skills.Skill) string {
	var b strings.Builder
	for _, s := range all {
		fmt.Fprintf(&b, "%s\n  %s\n", s.Name, s.Description)
	}
	return b.String()
}

// skillTools serve the same text over MCP, for an agent that has the
// server and not the folders.
func skillTools() []mcp.Tool {
	return []mcp.Tool{
		{Name: "list_skills", ReadOnly: true,
			Description: "The skills TruthForm carries for the work a translation to another cloud leaves to people (moving data, granting access, rebuilding machines, a TLS floor the target cannot match, reading the target's flow logs): each name, and when to use it.",
			Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
			Call: func(context.Context, map[string]any) (string, error) {
				all, err := skills.All()
				if err != nil {
					return "", err
				}
				return skillsList(all), nil
			}},
		{Name: "skill", ReadOnly: true,
			Description: "Read one skill in full (its SKILL.md): the rules, the work list to read from translation.yaml, the steps, and how the result is checked. Read it before starting that work, and follow it.",
			Schema: map[string]any{"type": "object", "required": []string{"name"},
				"properties": map[string]any{"name": map[string]any{"type": "string", "description": "a name from list_skills"}}},
			Call: func(_ context.Context, a map[string]any) (string, error) {
				s, err := skills.Get(arg(a, "name", ""))
				return s.Text, err
			}},
	}
}
