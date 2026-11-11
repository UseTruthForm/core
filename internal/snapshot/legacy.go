package snapshot

import "strings"

// Truthform was called StackDNA until format 2, and a format 1 snapshot
// carries that name in three places a reader acts on. They are translated as
// the snapshot is read, after its digest is checked against the files as
// written, so everything past Read sees one spelling.
//
// Without this a format 1 snapshot would load and quietly lose what the
// names carry: an annotation under the old domain is not found, so a restore
// sends an object with no API version or dependency order, and a placeholder
// under the old name is sent to the platform as a literal string.
const (
	legacyFormat = 1

	legacyDomain = "stackdna.org"
	domain       = "truthform.org"

	legacyToken = "{{stackdna|"
	token       = "{{truthform|"
)

// legacyGroups are the API groups Truthform itself writes objects under.
// Only these are renamed: any other group under the old domain belongs to
// the cluster that was captured (a CRD's group), and renaming it would make
// a restore ask for a type that does not exist.
var legacyGroups = []string{"aws", "azure", "gcp", "saas"}

// legacyNamesDiffer lists the platforms whose format 1 snapshots are refused
// instead of translated. A resource with no name of its own is named there
// from a hash of its spec, and the spec holds placeholders, so the same
// resource captured after the rename gets another name. Translating the
// snapshot would leave it holding names no capture produces any more.
var legacyNamesDiffer = map[string]bool{"aws": true, "gcp": true}

func fromLegacy(s *Snapshot) {
	for i := range s.Objects {
		b := s.Objects[i].Body
		if v, ok := b["apiVersion"].(string); ok {
			b["apiVersion"] = legacyAPIVersion(v)
		}
		s.Objects[i].Body = legacyValue(b).(map[string]any)
	}
	for i := range s.Schemas {
		s.Schemas[i].APIVersion = legacyAPIVersion(s.Schemas[i].APIVersion)
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

// legacyValue renames annotation keys under the old domain and placeholders
// under the old name, at any depth. A key is renamed only when the domain is
// its whole prefix, and a value only where the placeholder opens, so the old
// name inside a tag, a label or a description is left as captured.
func legacyValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			if rest, ok := strings.CutPrefix(k, legacyDomain+"/"); ok {
				k = domain + "/" + rest
			}
			out[k] = legacyValue(e)
		}
		return out
	case []any:
		for i := range t {
			t[i] = legacyValue(t[i])
		}
		return t
	case string:
		return strings.ReplaceAll(t, legacyToken, token)
	}
	return v
}
