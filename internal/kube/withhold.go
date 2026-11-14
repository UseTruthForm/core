package kube

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"

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
//   - a value whose name says a credential, in what a GitOps source
//     installs with (saysCredential), and all that is under such a name
//   - a value whose shape says one, whatever its name (shaped): a private
//     key, a URL that signs in, an Authorization header's value, a
//     connection string with a password in it, a long run of letters and
//     digits with nothing to read in it
//   - text that holds either, withheld whole; text that is no document
//     (a script, a properties file) is read line by line, and text that
//     should be a document and cannot be read as one is withheld whole
//
// and the exemptions are few and certain: what names a thing (a Secret's
// name, the name and key of a reference, an image), what is a setting
// about a credential (its length, its lifetime, the file it is in), what
// describes where a pod runs (labels, selectors, tolerations), a boolean,
// a small number, a value that only points at another.
//
// One rule for names, everywhere: a variable, a ConfigMap's key and a
// value of a chart are read by the same one (saysCredential). Nothing
// here withholds less than the rule for variables did: a slot that rule
// read is judged by it as well.

// --- names ---

var (
	camelRE = regexp.MustCompile(`([a-z0-9])([A-Z])`)
	partsRE = regexp.MustCompile(`[^A-Za-z0-9]+`)
)

// nameParts are a name's words, lower case: adminPassword, admin_password
// and admin-password are admin and password.
func nameParts(name string) []string {
	var out []string
	for _, p := range partsRE.Split(camelRE.ReplaceAllString(name, "${1}_${2}"), -1) {
		if p != "" {
			out = append(out, strings.ToLower(p))
		}
	}
	// A number at the end counts one of several: SECRET_ID_2 is SECRET_ID.
	for len(out) > 1 && allDigits(out[len(out)-1]) {
		out = out[:len(out)-1]
	}
	return out
}

// wordSays are words that say a credential on their own; a word with one
// of holdSays in it says one too (apitoken, dbpassword), as does one that
// ends as endSays do (dbpass, apikey). "key" has to be the word: monkey
// and turkey are not keys.
var (
	wordSays = map[string]bool{"pass": true, "pwd": true, "pw": true, "key": true, "keys": true, "cred": true, "creds": true, "auth": true,
		"dsn": true, "sas": true, "jwt": true, "salt": true, "signature": true, "license": true, "licence": true, "htpasswd": true}
	holdSays = []string{"password", "passwd", "passphrase", "passcode", "token", "secret", "credential"}
	endSays  = []string{"apikey", "secretkey", "privatekey", "accesskey", "authkey", "sshkey", "masterkey", "signingkey", "encryptionkey"}
	notPass  = map[string]bool{"bypass": true, "compass": true, "encompass": true, "trespass": true, "overpass": true, "underpass": true}
)

func wordSaysCredential(w string) bool {
	if wordSays[w] {
		return true
	}
	for _, h := range holdSays {
		if strings.Contains(w, h) {
			return true
		}
	}
	for _, e := range endSays {
		if strings.HasSuffix(w, e) {
			return true
		}
	}
	return len(w) > 4 && strings.HasSuffix(w, "pass") && !notPass[w]
}

// secretNamed are the words that, before "secret" at a name's end, say
// the Secret is named and not held: existingSecret, apiKeyExistingSecret,
// envFromSecret, pullSecret, tlsSecret. clientSecret and appSecret hold
// one.
var secretNamed = map[string]bool{"existing": true, "from": true, "pull": true, "tls": true}

// namesAThing reports a name that names a thing and holds none: a
// Secret's name (secretName, existingSecret and what it is followed by,
// pullSecret, envFromSecret), a reference, a public key.
func namesAThing(name string) bool {
	parts := nameParts(name)
	n := len(parts)
	if n == 0 {
		return false
	}
	joined := strings.Join(parts, "_")
	last := parts[n-1]
	switch {
	case last == "name" || last == "names" || last == "ref" || last == "refs":
		return true
	case strings.HasSuffix(joined, "public_key") || strings.HasSuffix(joined, "publickey"):
		return true
	}
	for _, p := range parts[:n-1] {
		// existingSecret, existingPasswordSecret, existingSecretKey: not
		// existingPassword, which holds one.
		if (last == "secret" || last == "secrets") && secretNamed[p] || last == "key" && p == "existing" {
			return true
		}
	}
	return false
}

// aboutIt are the words that, at a name's end, say a setting about a
// credential and not the credential: how long it is or lives, where it is
// (a file, an address: one that signs in is withheld by its shape), what
// it is made with. The rule for variables has always read names so.
var aboutIt = map[string]bool{"id": true, "ids": true, "url": true, "uri": true, "endpoint": true, "host": true, "port": true, "path": true,
	"file": true, "filename": true, "dir": true, "type": true, "enabled": true, "disabled": true, "ttl": true, "expiry": true, "expires": true,
	"expiration": true, "lifetime": true, "duration": true, "issuer": true, "audience": true, "audiences": true, "scope": true, "scopes": true,
	"version": true, "length": true, "seconds": true, "minutes": true, "hours": true, "days": true, "size": true, "count": true, "max": true,
	"min": true, "timeout": true, "interval": true, "format": true, "algorithm": true, "serializer": true, "deserializer": true, "prefix": true,
	"suffix": true, "mode": true, "policy": true, "level": true, "rotation": true, "encoder": true}

// about reports a name of several words that ends as a setting does.
func about(parts []string) bool {
	return len(parts) > 1 && aboutIt[parts[len(parts)-1]]
}

// saysCredential reports a name that says its value is a credential. A
// dotted name is read by its last part (auth.existingSecret is
// existingSecret, db.password is password).
func saysCredential(name string) bool {
	if i := strings.LastIndexAny(name, "./"); i >= 0 && i < len(name)-1 {
		name = name[i+1:]
	}
	if namesAThing(name) || about(nameParts(name)) {
		return false
	}
	lower := strings.ToLower(partsRE.ReplaceAllString(name, ""))
	if strings.Contains(lower, "connectionstring") || strings.Contains(lower, "connstr") {
		return true
	}
	for _, w := range nameParts(name) {
		if wordSaysCredential(w) {
			return true
		}
	}
	return false
}

// underSays reports a key under which everything is a credential,
// whatever its own name: password: {value: x}, tokens: [a, b]. Narrower
// than saysCredential: under "auth" and "key" are hosts and names too.
func underSays(key string) bool {
	if namesAThing(key) || about(nameParts(key)) {
		return false
	}
	for _, w := range nameParts(key) {
		for _, h := range holdSays {
			if strings.Contains(w, h) {
				return true
			}
		}
		if w == "pass" || w == "pwd" || w == "pw" || w == "dsn" || w == "htpasswd" || w == "license" || w == "licence" {
			return true
		}
	}
	// apiKey: {value: x}, privateKey: {pem: x}. Not "key" alone.
	joined := strings.Join(nameParts(key), "")
	for _, e := range endSays {
		if strings.HasSuffix(joined, e) {
			return true
		}
	}
	return false
}

// placement are keys under which a pod's placement and labelling are
// described: nothing under them is a credential, though a toleration has
// a key and a label may be called auth.
var placement = map[string]bool{"tolerations": true, "affinity": true, "nodeSelector": true, "matchLabels": true, "matchExpressions": true,
	"labels": true, "annotations": true, "podLabels": true, "podAnnotations": true, "commonLabels": true, "commonAnnotations": true,
	"topologySpreadConstraints": true, "selector": true, "selectorLabels": true, "imagePullSecrets": true}

// refRE is a key under which a thing is named and not held
// (secretKeyRef, valueFrom, passwordFrom).
var refRE = regexp.MustCompile(`(Ref|Refs|From)$`)

// naming are the keys by which a thing is named, under a reference or
// under a name that says a credential (secrets: [{name: x}]).
var naming = map[string]bool{"name": true, "names": true, "key": true, "keys": true, "kind": true, "namespace": true, "ref": true}

// componentKeys are keys a chart's or a component's settings have, and a
// credential's parts do not: which image runs and what it is called, how
// many, where. A map with one of them is settings, though the key it is
// under says a credential (sealed-secrets, external-secrets, tokenReview):
// what is in it is read by its own names.
var componentKeys = map[string]bool{"image": true, "repository": true, "registry": true, "tag": true, "digest": true, "pullPolicy": true,
	"fullnameOverride": true, "nameOverride": true, "namespaceOverride": true,
	"replicaCount": true, "replicas": true, "resources": true, "nodeSelector": true, "tolerations": true, "affinity": true, "serviceAccount": true,
	"rbac": true, "installCRDs": true, "crds": true, "podAnnotations": true, "podLabels": true, "securityContext": true, "podSecurityContext": true,
	"service": true, "ingress": true, "serviceMonitor": true, "livenessProbe": true, "readinessProbe": true, "command": true, "args": true,
	"extraArgs": true, "volumes": true, "volumeMounts": true, "priorityClassName": true}

func component(m map[string]any) bool {
	for k := range m {
		if componentKeys[k] {
			return true
		}
	}
	return false
}

// keyNamed are the keys beside which "key" is the name of a key and not a
// key: a reference ({name, key}), an item of a volume ({key, path}), a
// toleration.
var keyNamed = []string{"name", "secretName", "path", "operator", "effect", "optional"}

func keyNames(m map[string]any) bool {
	for _, k := range keyNamed {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

// dnsNameRE is what an object may be called. Under "secrets", a list of
// such is a list of Secrets' names.
var dnsNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)

func lastWord(name string) string {
	parts := nameParts(name)
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

// --- values ---

var (
	privateKeyRE = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)
	// schemeRE finds where a URL begins.
	schemeRE = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://`)
	// queryRE is a credential asked as a parameter. Not "secret=", "key="
	// or "code=", which name things as often as they hold one.
	queryRE = regexp.MustCompile(`(?i)[?&#;](access_token|private_token|client_secret|refresh_token|id_token|auth_token|api_?token|secret_key|access_key|subscription-key|ocp-apim-subscription-key|x-amz-signature|x-api-key|sslpassword|token|api_?key|password|passwd|pwd|sig|signature|jwt|auth)=(\{\{[^{}]*\}\}|[^&;\s"'#]+)`)
	// placeholderRE is a value that stands for one to be put there.
	placeholderRE = regexp.MustCompile(`^(<[^<>]*>|\{\{[^{}]*\}\}|\$\{[^{}]*\}|\$\([^()]*\)|%[A-Za-z_]+%|x{3,}|\*{3,})$`)
	// pointerRE is a value that only points at another: {{ .Values.x }},
	// ${VAR}, $(VAR). One with a default written into it is not that.
	pointerRE     = regexp.MustCompile(`^\s*(\{\{-?\s*[A-Za-z0-9_.$]+\s*-?\}\}|\$\{[A-Za-z0-9_.]+\}|\$\([A-Za-z0-9_.]+\))\s*$`)
	tokenPrefixRE = regexp.MustCompile(`^(gh[pousr]_|github_pat_|glpat-|xox[abps]-|pat-|sk-|AKIA)`)
	webhookRE     = regexp.MustCompile(`(?i)^https://(hooks\.slack\.com/(services|workflows|triggers)/|((ptb|canary)\.)?discord(app)?\.com/api/webhooks/|[a-z0-9.-]*webhook\.office\.com/|outlook\.office\.com/webhook/|api\.telegram\.org/bot|events\.pagerduty\.com/integration/)\S+`)
	// knownTokenRE is a token of a kind that says what it is.
	knownTokenRE = regexp.MustCompile(`^(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{16,}|xox[abps]-[A-Za-z0-9-]{10,}|AKIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,})$`)
	authRE       = regexp.MustCompile(`(?i)^\s*(?:(?:proxy-)?authorization:\s*)?(bearer|basic|token)\s+(\S+)\s*$`)
	versionRE    = regexp.MustCompile(`(?i)^v?\d+\.\d+`)
	opaqueRE     = regexp.MustCompile(`^[A-Za-z0-9+/_=-]{32,}$`)
	numberRE     = regexp.MustCompile(`^-?\d+(\.\d+)?$`)
	// connRE is a password in a connection string that is no URL:
	// Server=db;Password=x, host=db password=x, AccountKey=x.
	// host:6380,password=x. A Go DSN (user:pw@tcp(host)/db) and Oracle's
	// (jdbc:oracle:thin:user/pw@host) have one with no "://" before it.
	connRE = regexp.MustCompile(`(?i)(^|[;,\s])(password|pwd|accountkey|sharedaccesskey|sharedaccesssignature)\s*=\s*[^;,\s]+|^[^:@/\s]+:[^@\s]+@(tcp|unix)\(|jdbc:oracle:thin:[^/@\s]+/[^@\s]+@`)
	// publicBase64 are how a certificate and a public key begin when
	// written as base64 of their PEM text: long and unreadable, and public.
	publicBase64 = []string{"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS", "LS0tLS1CRUdJTiBQVUJMSUMgS0VZ"}
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

// hostLike reports text that reads as a host: it has a dot or a port, or
// is localhost.
func hostLike(s string) bool {
	return s == "localhost" || strings.ContainsAny(s, ".:")
}

// signs reports a URL that signs in, anywhere in the value: a password
// (though it has a slash in it), a token as the name, a credential asked
// as a parameter, a chat webhook, which is its own credential. A short
// name with no password is an account, and an "@" in a path or in what is
// asked is no sign-in at all. One pass over the value, however long.
func signs(value string) bool {
	starts := schemeRE.FindAllStringIndex(value, -1)
	if len(starts) == 0 {
		return false
	}
	for _, q := range queryRE.FindAllStringSubmatch(value, -1) {
		if !placeholderRE.MatchString(q[2]) {
			return true
		}
	}
	for i, at := range starts {
		// A URL runs to a space, or to the next one where several are
		// written with commas between them.
		end := len(value)
		if i+1 < len(starts) {
			end = starts[i+1][0]
		}
		whole := value[at[0]:end]
		if j := strings.IndexFunc(whole, unicode.IsSpace); j >= 0 {
			whole = whole[:j]
		}
		whole = strings.TrimRight(whole, ",")
		if webhookRE.MatchString(whole) {
			return true
		}
		rest := whole[at[1]-at[0]:]
		authority := rest
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			authority = rest[:j]
		}
		if j := strings.LastIndex(authority, "@"); j >= 0 {
			user, pass, hasPass := strings.Cut(authority[:j], ":")
			if (hasPass && pass != "") || tokenShaped(user) {
				return true
			}
			continue
		}
		// No "@" before the first slash. A password with a slash in it
		// puts the "@" after one (scheme://user:pa/ss@host). A port and a
		// path with an "@" in it look the same (http://cdn:8080/logo@2x),
		// so it takes a name with no dot before the colon, something a
		// port is not after it, and something that reads as a host after
		// the "@".
		if strings.HasPrefix(authority, "[") {
			continue
		}
		user, first, ok := strings.Cut(authority, ":")
		// A password with a "?" or a "#" in it: the "@" is before the
		// first slash all the same. Digits before the "?" are a port, and
		// what follows is what is asked (http://host:8080?x=a@b).
		if ok && first != "" && !numberRE.MatchString(first) && !strings.Contains(user, ".") {
			upTo := rest
			if j := strings.Index(rest, "/"); j >= 0 {
				upTo = rest[:j]
			}
			if strings.Contains(upTo[len(authority):], "@") {
				return true
			}
		}
		path := rest[len(authority):]
		if j := strings.IndexAny(path, "?#"); j >= 0 {
			path = path[:j]
		}
		j := strings.LastIndex(path, "@")
		if !ok || first == "" || numberRE.MatchString(first) || strings.Contains(user, ".") || j < 0 {
			continue
		}
		after := path[j+1:]
		if k := strings.Index(after, "/"); k >= 0 {
			after = after[:k]
		}
		if hostLike(after) {
			return true
		}
	}
	return false
}

// wordy reports text made of words: two or more parts of four or more
// lower-case letters ("production-release-build").
func wordy(s string) bool {
	n := 0
	for _, p := range partsRE.Split(s, -1) {
		if len(p) >= 4 && strings.ToLower(p) == p && strings.Trim(p, "abcdefghijklmnopqrstuvwxyz") == "" {
			n++
		}
	}
	return n >= 2
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
	return len(cred) >= 16 && !versionRE.MatchString(cred) && !wordy(cred)
}

// opaque reports a long run of letters and digits with nothing to read in
// it: the kind of character (upper, lower, digit) changes at nearly every
// other step, as it does in a key and does not in a path, a class's name
// or a bucket's. A hash in one case, a UUID and an image's digest are not
// that, nor is a certificate written as base64.
func opaque(value string) bool {
	if !opaqueRE.MatchString(value) {
		return false
	}
	for _, p := range publicBase64 {
		if strings.HasPrefix(value, p) {
			return false
		}
	}
	kind := func(r byte) int {
		switch {
		case r >= 'A' && r <= 'Z':
			return 1
		case r >= 'a' && r <= 'z':
			return 2
		case r >= '0' && r <= '9':
			return 3
		}
		return 0
	}
	seen := map[int]bool{}
	changes := 0
	for i := 0; i < len(value); i++ {
		seen[kind(value[i])] = true
		if i > 0 && kind(value[i]) != kind(value[i-1]) {
			changes++
		}
	}
	return seen[1] && seen[2] && seen[3] && changes*100 >= len(value)*45
}

// shaped reports a value whose shape says a credential, whatever it is
// called.
func shaped(value string) bool {
	v := strings.TrimSpace(value)
	return privateKeyRE.MatchString(value) || signs(value) || authorization(value) || connRE.MatchString(value) || knownTokenRE.MatchString(v) || opaque(v)
}

// certainlyNot reports a value that is no credential whatever its name
// says: nothing, a boolean, a value that only points at another, and,
// where it is a number in the object and not text, a small one.
func certainlyNot(value string, number bool) bool {
	v := strings.TrimSpace(value)
	switch strings.ToLower(v) {
	case "", "true", "false", "yes", "no", "on", "off": // the booleans, as YAML has had them
		return true
	}
	if number && numberRE.MatchString(v) && len(strings.TrimLeft(v, "-")) <= 6 {
		return true
	}
	return envRefRE.MatchString(v) || pointerRE.MatchString(v)
}

// --- free-form values ---

// filesPathRE is a value that names a file by its path, of two parts or
// more (/var/run/key.json): where a credential is, and not one.
var filesPathRE = regexp.MustCompile(`^(/[\w.@+-]+(/[\w.@+-]+)+|[A-Za-z]:\\\S*)$`)

// named reports whether a value is withheld, by its name and its value:
// the one rule for a variable, a ConfigMap's key and a value of a chart.
func named(name, value string) bool {
	if certainlyNot(value, false) {
		return false
	}
	return saysCredential(name) && !filesPathRE.MatchString(value) || shaped(value)
}

// textHolds reports a credential in a document written as text (Helm
// values, a patch, a value of several lines). Every YAML document of it
// is read. Text that reads as no document at all (a script, a properties
// file: to YAML one long scalar) is read line by line. Text that cannot
// be read, a template most often, or that sets a key twice, is withheld
// whole: where a value is in it cannot be told, and it is never kept for
// want of a parse.
func textHolds(text string) bool {
	if shaped(text) {
		return true
	}
	// Read as nodes, and not into maps: the reader checks a map's keys
	// against each other, which takes the square of their number, and a
	// document may have thousands.
	dec := yaml.NewDecoder(strings.NewReader(text))
	var docs []any
	lines := false
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			return true
		}
		root := &doc
		if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
			root = doc.Content[0]
		}
		if root.Kind == yaml.ScalarNode {
			lines = true
			continue
		}
		if repeats(root, 0) {
			return true
		}
		docs = append(docs, nodeValue(root, 0))
	}
	return lines && linesHold(text) || holds(docs)
}

// repeats reports a map that sets a key twice: the reader keeps the last,
// and the first may be the credential.
func repeats(n *yaml.Node, depth int) bool {
	if n == nil || depth > 200 {
		return false
	}
	if n.Kind == yaml.MappingNode {
		seen := make(map[string]bool, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			if k := n.Content[i]; k.Kind == yaml.ScalarNode {
				if seen[k.Value] {
					return true
				}
				seen[k.Value] = true
			}
		}
	}
	if n.Kind == yaml.AliasNode {
		return false
	}
	for _, c := range n.Content {
		if repeats(c, depth+1) {
			return true
		}
	}
	return false
}

// nodeValue is a YAML node as holds reads values: maps, lists, text,
// numbers, booleans. What is neither (a date) is its text under a type of
// its own, so that it is judged by its name.
func nodeValue(n *yaml.Node, depth int) any {
	if n == nil || depth > 200 {
		return nil
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) > 0 {
			return nodeValue(n.Content[0], depth+1)
		}
	case yaml.AliasNode:
		return nodeValue(n.Alias, depth+1)
	case yaml.MappingNode:
		m := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			m[n.Content[i].Value] = nodeValue(n.Content[i+1], depth+1)
		}
		return m
	case yaml.SequenceNode:
		l := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			l = append(l, nodeValue(c, depth+1))
		}
		return l
	case yaml.ScalarNode:
		switch n.ShortTag() {
		case "!!str":
			return n.Value
		case "!!int", "!!float":
			if f, err := strconv.ParseFloat(n.Value, 64); err == nil {
				return f
			}
			return n.Value
		case "!!bool":
			return strings.EqualFold(n.Value, "true")
		case "!!null":
			return nil
		}
		return otherScalar(n.Value)
	}
	return nil
}

// otherScalar is a value YAML reads as neither text nor a number.
type otherScalar string

// holds reports a credential anywhere in a decoded document: it is read
// as free-form values are, by the same walk, so that text and an object
// are never read two ways.
func holds(v any) bool {
	w := &walker{}
	if !w.leaf(v, "", "", false, func(any) {}) {
		w.values(v, "", "", "", false)
	}
	for _, sl := range w.out {
		if sl.withheld() {
			return true
		}
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

// lineRE is a line that sets a key with a colon or an equals sign, with
// or without a value on the line.
var lineRE = regexp.MustCompile(`^\s*(?:-\s+)?["']?([^"':=#\s][^"':=]*?)["']?\s*[:=]\s*(.*?)\s*$`)

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
		bare := v == m[2] // not in quotes: digits are a number
		// A variable written as a name and a value on two lines.
		if key == "name" && i+1 < len(lines) {
			if next := lineRE.FindStringSubmatch(lines[i+1]); next != nil && next[1] == "value" && named(v, strings.Trim(next[2], `"'`)) {
				return true
			}
		}
		if !saysCredential(key) {
			continue
		}
		if v == "" || v == "|" || v == ">" || v == "|-" || v == ">-" || strings.HasPrefix(v, "{") || strings.HasPrefix(v, "[") {
			// What it holds is below, or in braces. Taken as a credential
			// where everything under the name is one ("password:"), not
			// where the name opens a section ("auth:", "key:").
			if underSays(key) {
				return true
			}
			if strings.HasPrefix(v, "{") && !pointerRE.MatchString(v) && holdsInline(v) {
				return true
			}
			continue
		}
		if !certainlyNot(v, bare) {
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
		for _, w := range nameParts(v) {
			if wordSaysCredential(w) {
				return true // not YAML either: a word in it that says one is enough
			}
		}
		return false
	}
	return holds(doc)
}

// --- numbers ---

// numberMark ends the path of a value that was a number: filled, it is
// written as one again.
const numberMark = "#number"

// ownMark begins a path that is the slot's own and no other's: written
// where another slot of the object had this path by the rule before (a
// key with a dot in it beside the same keys nested), so that a restore
// does not have to ask which of the two a snapshot means.
const ownMark = "="

// pathOf is a path as the snapshot lists it, without its marks.
func pathOf(listed string) (path string, own bool) {
	path, own = strings.CutPrefix(strings.TrimSuffix(listed, numberMark), ownMark)
	return path, own
}

// numberText is a number as text: a whole one as it is written, however
// it was read (987654321, and not 9.87654321e+08).
func numberText(v any) string {
	if f, ok := v.(float64); ok {
		if f == math.Trunc(f) && math.Abs(f) < 1<<53 {
			return strconv.FormatInt(int64(f), 10)
		}
		return strconv.FormatFloat(f, 'g', -1, 64)
	}
	return fmt.Sprint(v)
}

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
