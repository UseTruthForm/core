package awsreads

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// AWS's API models (aws/api-models-aws): one request lists every file, and
// each file is public. No credentials.
const (
	ModelsTree = "https://api.github.com/repos/aws/api-models-aws/git/trees/main?recursive=1"
	ModelsRaw  = "https://raw.githubusercontent.com/aws/api-models-aws/main/"
)

var (
	// secretField is a field name that holds a secret when AWS marks it
	// sensitive. The mark alone is not enough: AWS marks names,
	// descriptions and times too (126 of the first add-on's actions had
	// some), and refusing on it would refuse ordinary configuration.
	secretField = regexp.MustCompile(`(?i)(password|secret|credential|privatekey|apikey|activationcode|url$|^username$|token$)`)
	// A bare value or key is a secret when the shape holding it is one:
	// ivs's StreamKey.value, location's DescribeKeyResponse.Key.
	bareValue   = regexp.MustCompile(`(?i)^(value|key)$`)
	secretOwner = regexp.MustCompile(`(?i)(key|secret|token|credential|password)`)
)

const sensitiveTrait = "smithy.api#sensitive"

type member struct {
	Target string         `json:"target"`
	Traits map[string]any `json:"traits"`
}

type shape struct {
	Type    string            `json:"type"`
	Output  *member           `json:"output"`
	Members map[string]member `json:"members"`
	Member  *member           `json:"member"`
	Key     *member           `json:"key"`
	Value   *member           `json:"value"`
	Traits  map[string]any    `json:"traits"`
}

// FetchSecretFields reads, for each action, the API operations behind it
// in AWS's own models, and records the output fields AWS marks sensitive
// that are named like a secret. An action it could not check is left out
// of ref.SecretFields, and Judge lists it as unverified.
func FetchSecretFields(ref *Reference, actions []string) error {
	b, err := get(ModelsTree)
	if err != nil {
		return err
	}
	var tree struct {
		Truncated bool `json:"truncated"`
		Tree      []struct {
			Path string `json:"path"`
		} `json:"tree"`
	}
	if err := json.Unmarshal(b, &tree); err != nil {
		return fmt.Errorf("models tree: %w", err)
	}
	if tree.Truncated {
		return fmt.Errorf("the models tree came back truncated")
	}
	paths := map[string]string{} // model name -> its service JSON
	for _, t := range tree.Tree {
		parts := strings.Split(t.Path, "/")
		if len(parts) == 5 && parts[0] == "models" && parts[2] == "service" && strings.HasSuffix(t.Path, ".json") {
			paths[parts[1]] = t.Path
		}
	}
	if len(paths) < 100 {
		return fmt.Errorf("the models tree names only %d services; refusing a partial check", len(paths))
	}
	models := map[string]map[string]shape{}
	load := func(name string) (map[string]shape, error) {
		if s, ok := models[name]; ok {
			return s, nil
		}
		p, ok := paths[name]
		if !ok {
			models[name] = nil
			return nil, nil
		}
		mb, err := get(ModelsRaw + p)
		if err != nil {
			return nil, err
		}
		var m struct {
			Shapes map[string]shape `json:"shapes"`
		}
		if err := json.Unmarshal(mb, &m); err != nil {
			return nil, fmt.Errorf("model %s: %w", name, err)
		}
		models[name] = m.Shapes
		return m.Shapes, nil
	}
	// The canary's action is always checked, so the canary always runs.
	for _, a := range append(actions, "ivs:GetStreamKey") {
		k := strings.ToLower(a)
		for _, op := range ref.ops[k] {
			shapes, err := load(op.model)
			if err != nil {
				return err
			}
			if shapes == nil {
				continue
			}
			out, found := outputOf(shapes, op.name)
			if !found {
				continue
			}
			fields := map[string]bool{}
			for _, f := range ref.SecretFields[k] {
				fields[f] = true
			}
			secretFields(shapes, out, map[string]bool{}, fields)
			list := []string{}
			for f := range fields {
				list = append(list, f)
			}
			sort.Strings(list)
			ref.SecretFields[k] = list
		}
	}
	// Canary: the stream key is the case this check exists for. If it is
	// not found, the models are not being read as they should be.
	if f := ref.SecretFields["ivs:getstreamkey"]; len(f) == 0 {
		return fmt.Errorf("found no secret field in ivs:GetStreamKey's output; AWS's models may not be read as they should be")
	}
	return nil
}

// outputOf finds an operation's output shape; "" with found true means it
// has none, so there is nothing to check.
func outputOf(shapes map[string]shape, op string) (string, bool) {
	for id, s := range shapes {
		if s.Type == "operation" && strings.HasSuffix(id, "#"+op) {
			if s.Output == nil {
				return "", true
			}
			return s.Output.Target, true
		}
	}
	return "", false
}

func secretFields(shapes map[string]shape, id string, seen, out map[string]bool) {
	if id == "" || seen[id] {
		return
	}
	seen[id] = true
	s, ok := shapes[id]
	if !ok {
		return
	}
	owner := id[strings.LastIndex(id, "#")+1:]
	for name, m := range s.Members {
		_, marked := m.Traits[sensitiveTrait]
		if t, ok := shapes[m.Target]; ok {
			_, onShape := t.Traits[sensitiveTrait]
			marked = marked || onShape
		}
		// NextToken is paging, not a secret.
		if marked && !strings.EqualFold(name, "nexttoken") && (secretField.MatchString(name) || bareValue.MatchString(name) && secretOwner.MatchString(owner)) {
			out[owner+"."+name] = true
		}
		secretFields(shapes, m.Target, seen, out)
	}
	for _, m := range []*member{s.Member, s.Key, s.Value} {
		if m != nil {
			secretFields(shapes, m.Target, seen, out)
		}
	}
}
