package kube

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// What is withheld from an object that is not a Secret, beyond the rule
// for variables (credential): generously, and failing closed.
//
// A value withheld that was no credential used to make its object one a
// restore refused without the cluster it came from. It no longer does: a
// secret sources file supplies what was withheld, a line for each (plan
// secrets writes them). So the cost of withholding too much is a line a
// person answers with the value, and the cost of withholding too little
// is a credential in a snapshot. The rules lean accordingly:
//
//   - a value whose name says a credential: any name with pass, token,
//     secret, key, cred, auth or dsn in it
//   - a value whose shape says one, whatever its name: a private key, a
//     URL that signs in, an Authorization header's, a long run of letters
//     and digits with nothing to read in it
//   - text that holds either, withheld whole; text that cannot be read as
//     YAML is read line by line, and withheld whole if a line reads so
//
// and the exemptions are few and certain: what names a thing (a Secret's
// name, the name and key of a reference, a toleration's key), a boolean,
// a small number.

// --- names ---

var (
	saysRE = regexp.MustCompile(`(?i)pass|token|secret|key|cred|auth|dsn`)
	// namesRE are names that name a thing, and hold none: a Secret's name
	// (secretName, existingSecret and what follows it), a public key.
	namesRE = regexp.MustCompile(`(?i)(secret|key|token|password|credentials?|auth)_?(name|names|ref|refs)$|^existing_?secret|public_?key`)
	// refRE is a key under which a thing is named and not held
	// (secretKeyRef, valueFrom, passwordFrom).
	refRE = regexp.MustCompile(`(Ref|Refs|From)$`)
)

// underRE is a name under which everything is a credential, whatever its
// own name: password: {value: x}. Narrower than saysRE: under "auth" and
// "key" are hosts and names as well.
var underRE = regexp.MustCompile(`(?i)pass|token|secret|cred|dsn`)

// saysCredential reports a name that says its value is a credential. A
// dotted name is read by its last part (auth.existingSecret is
// existingSecret); a last part that says nothing takes the word of the
// part before it (password.value).
func saysCredential(name string) bool {
	parts := strings.FieldsFunc(name, func(r rune) bool { return r == '.' || r == '/' })
	if len(parts) == 0 {
		return false
	}
	last := parts[len(parts)-1]
	if namesRE.MatchString(last) {
		return false
	}
	if saysRE.MatchString(last) {
		return true
	}
	return len(parts) > 1 && underRE.MatchString(parts[len(parts)-2]) && !namesRE.MatchString(parts[len(parts)-2])
}

// --- values ---

var (
	privateKeyRE = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)
	// urlAtRE is a URL and what follows it up to a space.
	urlAtRE = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*)://(\S+)`)
	// queryRE is a credential asked as a parameter. Not "secret=", which
	// names one as often as it holds one (?secret=app-config).
	queryRE = regexp.MustCompile(`(?i)[?&#;](access_token|private_token|client_secret|token|api_?key|password|passwd|pwd|sig|signature)=(\{\{[^{}]*\}\}|[^&;\s"'#]+)`)
	// placeholderRE is a value that stands for one to be put there.
	placeholderRE = regexp.MustCompile(`^(<[^<>]*>|\{\{[^{}]*\}\}|\$\{[^{}]*\}|\$\([^()]*\)|%[A-Za-z_]+%|x{3,}|\*{3,})$`)
	tokenPrefixRE = regexp.MustCompile(`^(gh[pousr]_|github_pat_|glpat-|xox[abps]-|pat-|sk-|AKIA)`)
	webhookRE     = regexp.MustCompile(`(?i)^https://(hooks\.slack\.com/services/|discord(app)?\.com/api/webhooks/|[a-z0-9.-]*webhook\.office\.com/|outlook\.office\.com/webhook/)\S+`)
	authRE        = regexp.MustCompile(`(?i)^\s*(bearer|basic|token)\s+(\S+)\s*$`)
	versionRE     = regexp.MustCompile(`(?i)^v?\d+\.\d+`)
	opaqueRE      = regexp.MustCompile(`^[A-Za-z0-9+/_=.-]{32,}$`)
	numberRE      = regexp.MustCompile(`^-?\d+(\.\d+)?$`)
)

// tokenShaped reports a name in a URL that reads as a token and not as an
// account: long with letters and digits, or starting as a known token
// does. "git", "deploy" and an organisation's name are accounts.
func tokenShaped(name string) bool {
	if tokenPrefixRE.MatchString(name) {
		return true
	}
	return len(name) >= 20 && strings.ContainsAny(name, "0123456789") && strings.ContainsAny(strings.ToLower(name), "abcdefghijklmnopqrstuvwxyz")
}

// signs reports a URL that signs in, anywhere in the value: a password
// (though it has a slash in it), a token as the name, a credential asked
// as a parameter, a chat webhook, which is its own credential. A short
// name with no password is an account, and an "@" in a path or in what is
// asked is no sign-in at all.
func signs(value string) bool {
	for _, at := range urlAtRE.FindAllStringSubmatchIndex(value, -1) {
		whole, rest := value[at[0]:at[1]], value[at[4]:at[5]]
		if webhookRE.MatchString(whole) {
			return true
		}
		// What is asked is read to the end of the value: a placeholder
		// may have a space in it ({{ token }}).
		for _, q := range queryRE.FindAllStringSubmatch(value[at[4]:], -1) {
			if !placeholderRE.MatchString(q[2]) {
				return true
			}
		}
		// Several addresses with commas between them: each is read.
		if i := strings.Index(rest, ","); i >= 0 && strings.Contains(rest[i:], "://") && signs(rest[i+1:]) {
			return true
		}
		authority := rest
		if i := strings.IndexAny(rest, "/?#"); i >= 0 {
			authority = rest[:i]
		}
		// Several hosts in one address (http://a:9200,http://b@c:9200):
		// each is read when the search comes to it.
		if i := strings.Index(authority, ","); i >= 0 {
			authority = authority[:i]
		}
		if at := strings.LastIndex(authority, "@"); at >= 0 {
			user, pass, hasPass := strings.Cut(authority[:at], ":")
			if (hasPass && pass != "") || tokenShaped(user) {
				return true
			}
			continue
		}
		// No "@" before the first slash. A password with a slash, a "?"
		// or a "#" in it puts the "@" after one (scheme://user:pa/ss@host).
		// A port and a path with an "@" in it look the same
		// (http://cdn:8080/img/logo@2x.png), so what follows the colon has
		// to be something a port is not.
		if strings.HasPrefix(authority, "[") {
			continue
		}
		_, first, ok := strings.Cut(authority, ":")
		if !ok || first == "" || numberRE.MatchString(first) || !strings.Contains(rest[len(authority):], "@") {
			continue
		}
		return true
	}
	return false
}

// authorization reports the value of an Authorization header: Basic with
// a name and password encoded, or Bearer or Token with a token after it
// ("Basic production" and "token v1.2.3-build" are neither).
func authorization(value string) bool {
	m := authRE.FindStringSubmatch(value)
	if m == nil {
		return false
	}
	kind, cred := strings.ToLower(m[1]), m[2]
	if kind == "basic" {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if b, err := enc.DecodeString(cred); err == nil && bytes.ContainsRune(b, ':') {
				return true
			}
		}
		return false
	}
	return len(cred) >= 16 && !versionRE.MatchString(cred) && strings.ContainsAny(cred, "0123456789") && strings.ContainsAny(strings.ToLower(cred), "abcdefghijklmnopqrstuvwxyz")
}

// opaque reports a long run of letters and digits with nothing to read in
// it: upper case, lower case and digits together, no spaces. A hash in
// one case, a UUID and an image's digest are not that.
func opaque(value string) bool {
	if !opaqueRE.MatchString(value) || strings.Contains(value, "://") {
		return false
	}
	var upper, lower, digit bool
	for _, r := range value {
		switch {
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= '0' && r <= '9':
			digit = true
		}
	}
	// Words joined by dots or dashes (a host's name, a version) read.
	return upper && lower && digit && strings.Count(value, ".")+strings.Count(value, "-") < 4
}

// shaped reports a value whose shape says a credential, whatever it is
// called.
func shaped(value string) bool {
	return privateKeyRE.MatchString(value) || signs(value) || authorization(value) || opaque(strings.TrimSpace(value))
}

// certainlyNot reports a value that is no credential whatever its name
// says: nothing, a boolean, a small number, a reference to a variable.
func certainlyNot(value string) bool {
	v := strings.TrimSpace(value)
	switch strings.ToLower(v) {
	case "", "true", "false", "yes", "no", "on", "off", "null", "none", "enabled", "disabled":
		return true
	}
	if numberRE.MatchString(v) && len(strings.TrimLeft(v, "-")) <= 6 {
		return true
	}
	return envRefRE.MatchString(v)
}

// --- free-form values ---

// named reports whether a free-form value is withheld, by its name and
// its value.
func named(name, value string) bool {
	if certainlyNot(value) {
		return false
	}
	return saysCredential(name) || shaped(value)
}

// textHolds reports a credential in a document written as text (Helm
// values, a patch). Every YAML document of it is read. Text that does
// not read as YAML, a template most often, is read line by line, and a
// line that sets a name that says a credential is enough: such text is
// never kept for want of a parse.
func textHolds(text string) bool {
	if shaped(text) {
		return true
	}
	dec := yaml.NewDecoder(strings.NewReader(text))
	var docs []any
	for {
		var doc any
		err := dec.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			return linesHold(text)
		}
		docs = append(docs, doc)
	}
	return holds(docs, "")
}

// holds reports a credential anywhere in a decoded document, by the rule
// for free-form values.
func holds(v any, name string) bool {
	switch x := v.(type) {
	case map[string]any:
		if nameValue(x) && named(strOf(x["name"]), scalarText(x["value"])) {
			return true
		}
		for k, c := range x {
			if exemptUnder(x, k, name) {
				continue
			}
			if holds(c, k) {
				return true
			}
		}
	case map[any]any:
		for k, c := range x {
			if holds(c, fmt.Sprint(k)) {
				return true
			}
		}
	case []any:
		for _, c := range x {
			if holds(c, name) {
				return true
			}
		}
	case string:
		if strings.Contains(x, "\n") {
			return textHolds(x)
		}
		return named(name, x)
	case int, int64, uint64, float64:
		return named(name, fmt.Sprint(x)) && saysCredential(name)
	}
	return false
}

// nameValue reports a map that is a name and its value, as a variable or
// a parameter is written.
func nameValue(m map[string]any) bool {
	_, hasName := m["name"].(string)
	_, hasValue := m["value"]
	return hasName && hasValue
}

// exemptUnder reports a key whose value names a thing, by where it is:
// the name and key of a reference (secretKeyRef: {name, key}), and the
// key of a toleration or a match expression, which has an operator or an
// effect beside it.
func exemptUnder(m map[string]any, k, parent string) bool {
	switch k {
	case "name", "key", "namespace", "kind":
		if refRE.MatchString(parent) {
			return true
		}
	}
	if k == "key" || k == "value" {
		_, operator := m["operator"]
		_, effect := m["effect"]
		return operator || effect
	}
	return false
}

func scalarText(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case int, int64, uint64, float64:
		return fmt.Sprint(x)
	}
	return ""
}

// lineRE is a line that sets a key, with or without a value on the line.
var lineRE = regexp.MustCompile(`^\s*(?:-\s+)?["']?([^"':#\s][^"':]*?)["']?\s*:\s*(.*?)\s*$`)

// linesHold reads text that is not YAML line by line. A key whose name
// says a credential is one whatever follows it: its value may be on the
// line, on the next, or a block.
func linesHold(text string) bool {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if shaped(line) {
			return true
		}
		m := lineRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key, v := m[1], strings.Trim(m[2], `"'`)
		// A variable written as a name and a value on two lines.
		if key == "name" && i+1 < len(lines) {
			if next := lineRE.FindStringSubmatch(lines[i+1]); next != nil && next[1] == "value" && named(v, strings.Trim(next[2], `"'`)) {
				return true
			}
		}
		if !saysCredential(key) {
			continue
		}
		if v == "" || v == "|" || v == ">" || strings.HasPrefix(v, "{") || strings.HasPrefix(v, "[") {
			// What it holds is below, or in braces. Taken as a credential
			// where everything under the name is one ("password:"), not
			// where the name opens a section ("auth:", "key:").
			if underRE.MatchString(key) && !namesRE.MatchString(key) {
				return true
			}
			if strings.HasPrefix(v, "{") && holdsInline(v) {
				return true
			}
			continue
		}
		if !certainlyNot(v) {
			return true
		}
	}
	return false
}

// holdsInline reads what is in braces on a line ({password: x}) as the
// YAML it is, if it is.
func holdsInline(v string) bool {
	var doc any
	if yaml.Unmarshal([]byte(v), &doc) != nil {
		return saysRE.MatchString(v) // not YAML either: a name in it that says one is enough
	}
	return holds(doc, "")
}

// --- numbers ---

// numberMark ends the path of a value that was a number: filled, it is
// written as one again.
const numberMark = "#number"

// asNumber is text as the number it was.
func asNumber(s string) (any, error) {
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i, nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil, fmt.Errorf("it was a number in the object, and what is given is not one")
	}
	return f, nil
}
