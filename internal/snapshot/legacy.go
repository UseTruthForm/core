package snapshot

import "strings"

// Truthform was called StackDNA until format 2, and a format 1 snapshot
// carries that name in places a reader acts on. They are translated as the
// snapshot is read, so everything past Read sees one spelling. The digest
// is unaffected: it is over the files as written.
//
// Without this a format 1 snapshot would load and quietly lose what the
// names carry: an annotation under the old domain is not found, so a restore
// sends an object with no API version or dependency order, and a placeholder
// under the old name is sent to the platform as a literal string.
//
// What is translated is what the build that wrote format 1 put there, and
// nothing else. That differs by platform, so the translation does too:
// anything wider rewrites what belongs to the captured system (a label key
// under the old domain became another label, and with it a Deployment's
// selector).
const (
	legacyFormat = 1

	legacyDomain = "stackdna.org"
	domain       = "truthform.org"

	legacyToken = "{{stackdna|"
	token       = "{{truthform|"
)

// legacyGroups are the API groups Truthform itself writes objects under on
// a cloud or SaaS platform.
var legacyGroups = []string{"aws", "azure", "gcp", "saas"}

// legacyKubeAnnotations are the only names a Kubernetes capture ever added
// to an object: both on its own metadata, never deeper. Everything else in a
// Kubernetes snapshot is the cluster's, whatever it is called.
var legacyKubeAnnotations = []string{"withheld-keys", "withheld-env"}

// legacyNamesDiffer lists the platforms whose format 1 snapshots are refused
// instead of translated. A resource with no name of its own is named there
// from a hash of its spec, and the spec holds placeholders, so the same
// resource captured after the rename gets another name. Translating the
// snapshot would leave it holding names no capture produces any more.
var legacyNamesDiffer = map[string]bool{"aws": true, "gcp": true}

func fromLegacy(s *Snapshot) {
	if s.Platform == "kubernetes" {
		for _, o := range s.Objects {
			ann, _ := meta(o.Body)["annotations"].(map[string]any)
			for _, n := range legacyKubeAnnotations {
				if v, ok := ann[legacyDomain+"/"+n]; ok {
					delete(ann, legacyDomain+"/"+n)
					ann[domain+"/"+n] = v
				}
			}
		}
		return
	}
	// A cloud or SaaS object. Its apiVersion and its metadata.annotations
	// are Truthform's own, and the capture put placeholders anywhere an ID
	// stood, in values and in map keys alike (a user-assigned identity is
	// a key). User data keeps its names: a tag key under the old domain is
	// a key in spec, not an annotation.
	for i := range s.Objects {
		b := legacyTokens(s.Objects[i].Body).(map[string]any)
		if v, ok := b["apiVersion"].(string); ok {
			b["apiVersion"] = legacyAPIVersion(v)
		}
		if ann, ok := meta(b)["annotations"].(map[string]any); ok {
			for k, v := range ann {
				if rest, ok := strings.CutPrefix(k, legacyDomain+"/"); ok {
					delete(ann, k)
					ann[domain+"/"+rest] = v
				}
			}
		}
		s.Objects[i].Body = b
	}
	for i := range s.Schemas {
		s.Schemas[i].APIVersion = legacyAPIVersion(s.Schemas[i].APIVersion)
	}
	// Reasons and names in the coverage report quote IDs, placeholders
	// included. Nothing acts on them; a report would show the old name.
	tok := func(v string) string { return strings.ReplaceAll(v, legacyToken, token) }
	for i := range s.Skips {
		s.Skips[i].Name, s.Skips[i].Reason = tok(s.Skips[i].Name), tok(s.Skips[i].Reason)
	}
	for i := range s.Coverage {
		c := &s.Coverage[i]
		c.NotCaptured = tok(c.NotCaptured)
		for k, n := range c.Skipped {
			if nk := tok(k); nk != k {
				delete(c.Skipped, k)
				c.Skipped[nk] = n
			}
		}
	}
}

func legacyAPIVersion(v string) string {
	for _, g := range legacyGroups {
		if rest, ok := strings.CutPrefix(v, g+"."+legacyDomain+"/"); ok {
			return g + "." + domain + "/" + rest
		}
	}
	return v
}

// legacyTokens renames placeholders under the old name wherever one opens:
// in string values and in map keys, at any depth, lists included.
func legacyTokens(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[strings.ReplaceAll(k, legacyToken, token)] = legacyTokens(e)
		}
		return out
	case []any:
		for i := range t {
			t[i] = legacyTokens(t[i])
		}
		return t
	case string:
		return strings.ReplaceAll(t, legacyToken, token)
	}
	return v
}
