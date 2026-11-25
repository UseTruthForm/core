// Package skills holds TruthForm's agent skills: one folder each, with a
// SKILL.md in the open Agent Skills layout (YAML front matter with a name
// and a description, then instructions). They are for the work a
// translation to another cloud leaves to people: moving data, granting
// access, rebuilding machines, a TLS floor the target cannot match,
// reading the target's flow logs, and estimating what it would cost there.
//
// The folders are the source. The binary embeds them, so `truthform
// skills` can write them out and `truthform mcp` can serve the same text.
package skills

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed */SKILL.md
var files embed.FS

// Skill is one skill: its folder name, its description (when an agent
// should load it) and the whole SKILL.md.
type Skill struct {
	Name        string
	Description string
	Text        string
}

// All returns every skill, by name.
func All() ([]Skill, error) {
	paths, err := fs.Glob(files, "*/SKILL.md")
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	var out []Skill
	for _, p := range paths {
		b, err := files.ReadFile(p)
		if err != nil {
			return nil, err
		}
		s, err := parse(strings.TrimSuffix(p, "/SKILL.md"), string(b))
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// Get returns the skill of that name.
func Get(name string) (Skill, error) {
	all, err := All()
	if err != nil {
		return Skill{}, err
	}
	var names []string
	for _, s := range all {
		if s.Name == name {
			return s, nil
		}
		names = append(names, s.Name)
	}
	return Skill{}, fmt.Errorf("no skill %q (there are: %s)", name, strings.Join(names, ", "))
}

// parse reads the front matter: exactly a name, which must be the
// folder's, and a description, each on one line.
func parse(dir, text string) (Skill, error) {
	rest, ok := strings.CutPrefix(text, "---\n")
	head, _, found := strings.Cut(rest, "\n---\n")
	if !ok || !found {
		return Skill{}, fmt.Errorf("skill %s: SKILL.md does not start with front matter between --- lines", dir)
	}
	s := Skill{Text: text}
	for _, line := range strings.Split(head, "\n") {
		k, v, ok := strings.Cut(line, ": ")
		switch {
		case ok && k == "name":
			s.Name = v
		case ok && k == "description":
			s.Description = v
		default:
			return Skill{}, fmt.Errorf("skill %s: front matter line %q is neither name nor description", dir, line)
		}
	}
	if s.Name != dir {
		return Skill{}, fmt.Errorf("skill %s: its name is %q, which must be its folder's", dir, s.Name)
	}
	if s.Description == "" {
		return Skill{}, fmt.Errorf("skill %s: no description", dir)
	}
	return s, nil
}
