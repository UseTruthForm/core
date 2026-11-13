package kube

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func releaseWith(values map[string]any) map[string]any {
	return map[string]any{"apiVersion": "helm.toolkit.fluxcd.io/v2", "kind": "HelmRelease", "metadata": map[string]any{"name": "r", "namespace": "x"}, "spec": map[string]any{"values": values}}
}

// One rule for names, everywhere: a name that says a credential in a
// chart's values says one as a variable, as a ConfigMap's key and as a
// variable written in values; and a name that says none says none.
func TestOneRuleForNamesEverywhere(t *testing.T) {
	says := []string{"apiToken", "authToken", "bearerToken", "sasToken", "SASToken", "clientSecretValue", "appKey", "fernetKey", "hmacKey", "jwtKey",
		"secretAccessKey", "cloudflareAPIToken", "openAIAPIKey", "APITOKEN", "api-key", "client-secret", "DB_PASSWORD", "dbPass", "license"}
	not := []string{"LOG_LEVEL", "PASSWORD_MIN_LENGTH", "TOKEN_TTL", "KEY_PREFIX", "SECRET_NAME", "PUBLIC_KEY", "AWS_REGION", "tokenExpiration", "tokenLifetime",
		"PASSWORD_POLICY", "tokenUrl", "certKeyFilename", "SECRET_ID_2", "existingSecret", "apiKeyExistingSecret", "envFromSecret", "PASSWORD_SECRET_NAME", "AUTH_MODE"}
	env := func() []any {
		var out []any
		for _, n := range says {
			out = append(out, map[string]any{"name": n, "value": "s3cr3t-" + n})
		}
		for _, n := range not {
			out = append(out, map[string]any{"name": n, "value": "kept-" + n})
		}
		// A file's path is where a credential is, under any name.
		return append(out, map[string]any{"name": "GOOGLE_APPLICATION_CREDENTIALS", "value": "/var/run/kept-path/key.json"})
	}
	flat := func() map[string]any {
		out := map[string]any{"GOOGLE_APPLICATION_CREDENTIALS": "/var/run/kept-path/key.json"}
		for _, n := range says {
			out[n] = "s3cr3t-" + n
		}
		for _, n := range not {
			out[n] = "kept-" + n
		}
		return out
	}
	md := func() map[string]any { return map[string]any{"name": "o", "namespace": "x"} }
	for where, o := range map[string]map[string]any{
		"a variable":             {"apiVersion": "v1", "kind": "Pod", "metadata": md(), "spec": map[string]any{"containers": []any{map[string]any{"name": "c", "env": env()}}}},
		"a ConfigMap's key":      {"apiVersion": "v1", "kind": "ConfigMap", "metadata": md(), "data": flat()},
		"a variable in values":   releaseWith(map[string]any{"env": env()}),
		"a pair in values":       releaseWith(map[string]any{"extraEnv": env()}),
		"a value of a chart":     releaseWith(flat()),
		"a substitution":         {"apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization", "metadata": md(), "spec": map[string]any{"postBuild": map[string]any{"substitute": flat()}}},
		"an application's value": {"apiVersion": "argoproj.io/v1alpha1", "kind": "Application", "metadata": md(), "spec": map[string]any{"source": map[string]any{"helm": map[string]any{"valuesObject": flat(), "parameters": env()}}}},
	} {
		paths, out := withheldOf("", "", o)
		want := len(says)
		if where == "an application's value" {
			want *= 2
		}
		if strings.Contains(out, "s3cr3t") || len(paths) != want {
			t.Errorf("%s: %d withheld, want %d: %v\n%s", where, len(paths), want, paths, out)
		}
		for _, n := range not {
			if !strings.Contains(out, "kept-"+n) {
				t.Errorf("%s: %s was withheld", where, n)
			}
		}
		if !strings.Contains(out, "kept-path") {
			t.Errorf("%s: a file's path was withheld", where)
		}
	}
	// One part is no path to a file: a password may begin with a slash.
	if !named("DB_PASSWORD", "/hunter2") || named("DB_PASSWORD", "/run/secrets/db") || named("DB_PASSWORD", `C:\keys\db.txt`) {
		t.Error("a file's path under a name that says a credential")
	}
}

// A chart or a component whose name says a credential is not one: what
// is under it is read by its own names. What names a thing is kept under
// any name.
func TestAComponentsNameWithholdsNothing(t *testing.T) {
	image := func(tag string) map[string]any {
		return map[string]any{"repository": "kept-repo-" + tag, "tag": "kept-tag-" + tag, "registry": "kept-registry-" + tag, "pullPolicy": "kept-policy-" + tag}
	}
	values := map[string]any{
		"sealed-secrets":           map[string]any{"image": image("a"), "fullnameOverride": "kept-fullname", "nameOverride": "kept-nameover", "logLevel": "kept-loglevel"},
		"secrets-store-csi-driver": map[string]any{"linux": map[string]any{"image": image("b")}, "windows": map[string]any{"image": image("c")}},
		"external-secrets":         map[string]any{"image": image("d"), "replicaCount": 2, "webhook": map[string]any{"image": image("e")}},
		// A component with nothing but an image's parts under it.
		"tokenReview": map[string]any{"image": image("f")},
		"passwords":   map[string]any{"image": map[string]any{"repository": "kept-under-image"}},
		"tokenProxy":  map[string]any{"digest": "kept-digest"},
		"secretsSync": map[string]any{"pullPolicy": "kept-pull"},
		"authToken":   map[string]any{"namespaceOverride": "kept-ns-override"},
		// A credential in a component is one still, by its own name.
		"vault-secrets": map[string]any{"image": image("g"), "token": "s3cr3t-1", "auth": map[string]any{"password": "s3cr3t-2"}, "secrets": map[string]any{"db": "s3cr3t-3"}},
		// What only names a thing.
		"apiKeyExistingSecret": "kept-existing", "envFromSecret": "kept-envfrom", "existingSecretName": "kept-existing-name",
		"grafana":         map[string]any{"admin": map[string]any{"existingSecret": "kept-admin-secret", "passwordKey": "s3cr3t-4"}, "tokenUrl": "https://kept.example.com/token"},
		"alertmanager":    map[string]any{"secrets": []any{"kept-tls-secret", "kept-other.secret"}},
		"configMap":       map[string]any{"items": []any{map[string]any{"key": "kept-item-key", "path": "kept-item-path"}}},
		"basicAuth":       map[string]any{"username": map[string]any{"name": "kept-ref-name", "key": "kept-ref-key"}, "password": map[string]any{"name": "kept-ref-name2", "key": "kept-ref-key2"}},
		"authSecretName":  "kept-auth-secret-name",
		"tlsCertificates": map[string]any{"secretName": "kept-cert-secret", "key": "-----BEGIN PRIVATE KEY-----\ns3cr3t-5\n-----END PRIVATE KEY-----"},
		// A list under "secrets" that is no list of names, and a credential's
		// parts under a name that says one.
		"secrets":  []any{"s3cr3t-6 with a space", "S3cr3t-7Upper"},
		"password": map[string]any{"value": "s3cr3t-8"},
		"tokens":   map[string]any{"admin": "s3cr3t-9", "nested": map[string]any{"reader": "s3cr3t-10"}},
		"registry": map[string]any{"image": "kept-image-name", "repository": "https://u:s3cr3t-11@example.com/charts"},
		"encrypt":  map[string]any{"key": "s3cr3t-12"},
	}
	r := releaseWith(values)
	original := deepCopy(r)
	paths, out := withheldOf("helm.toolkit.fluxcd.io", "helmreleases", r)
	if strings.Contains(out, "s3cr3t") || len(paths) != 12 {
		t.Errorf("%d withheld, want 12: %v\n%s", len(paths), paths, out)
	}
	for _, kept := range []string{"kept-repo-", "kept-tag-", "kept-registry-", "kept-policy-"} {
		for _, tag := range "abcdefg" {
			if !strings.Contains(out, kept+string(tag)) {
				t.Errorf("%s%c was withheld: %v", kept, tag, paths)
			}
		}
	}
	for _, kept := range []string{"kept-fullname", "kept-nameover", "kept-loglevel", "kept-under-image", "kept-existing", "kept-envfrom", "kept-existing-name", "kept-admin-secret",
		"kept.example.com/token", "kept-tls-secret", "kept-other.secret", "kept-item-key", "kept-item-path", "kept-ref-name", "kept-ref-key", "kept-ref-name2", "kept-ref-key2",
		"kept-auth-secret-name", "kept-cert-secret", "kept-image-name", "kept-digest", "kept-pull", "kept-ns-override"} {
		if !strings.Contains(out, kept) {
			t.Errorf("%s was withheld: %v", kept, paths)
		}
	}
	body := deepCopy(r)
	if err := fillFrom(deepCopy(original), body, withheldEnv(body)); err != nil || !reflect.DeepEqual(body["spec"], original["spec"]) {
		t.Errorf("filled back: %v\n got %v\nwant %v", err, body["spec"], original["spec"])
	}

	// As text it is read the same way: by the same walk.
	for text, want := range map[string]bool{
		"sealed-secrets:\n  image:\n    repository: r\n    tag: v1\n  fullnameOverride: x\n": false,
		"external-secrets:\n  image:\n    tag: v1\n  token: s3cr3t\n":                        true,
		"apiKeyExistingSecret: db\nenvFromSecret: app\nalertmanager:\n  secrets: [tls]\n":    false,
		"configMap:\n  items:\n    - key: tls.crt\n      path: tls.crt\n":                    false,
		"tokens:\n  admin: s3cr3t\n":                                       true,
		"- op: add\n  path: /spec/password\n  value: s3cr3t\n":             true,
		"- op: add\n  path: /spec/replicas\n  value: three\n":              false,
		"- op: add\n  path: /data/password\n  value:\n    plain: s3cr3t\n": true,
		"config: '{\"db\": {\"password\": \"s3cr3t\"}}'\n":                 true,
		"config: '{\"db\": {\"host\": \"db\"}}'\n":                         false,
		"when: 2024-05-17\n":                                               false,
	} {
		if got := textHolds(text); got != want {
			t.Errorf("textHolds(%q) = %v, want %v", text, got, want)
		}
	}
}

// Text in values: a value of several lines that is no document is read
// line by line; a document that cannot be read is withheld whole, and is
// a slot like any other, named and filled back.
func TestTextInValues(t *testing.T) {
	values := map[string]any{
		"envFile":    "DB_PASSWORD=s3cr3t-1\nPORT=80",
		"properties": "spring.datasource.password=s3cr3t-2\nserver.port=80",
		"script":     "#!/bin/sh\nexport API_TOKEN=s3cr3t-3\nexec app",
		"broken":     "{{- if .x }}\nlogin: s3cr3t-4\n{{- end }}\n",
		"twice":      "password: s3cr3t-5\npassword: true\n",
		"inline":     `{"db": {"password": "s3cr3t-6"}}`,
		"notes":      "kept-notes\nof two lines",
		"plain":      "PORT=80\nMODE=kept-mode",
		"document":   "replicas: 2\nimage:\n  tag: kept-doc\n",
		"json":       `{"db": {"host": "kept-json"}}`,
		"template":   "{{ .Values.keptPointer }}",
	}
	r := releaseWith(values)
	original := deepCopy(r)
	paths, out := withheldOf("helm.toolkit.fluxcd.io", "helmreleases", r)
	want := "spec.values.broken spec.values.envFile spec.values.inline spec.values.properties spec.values.script spec.values.twice"
	if strings.Join(paths, " ") != want || strings.Contains(out, "s3cr3t") {
		t.Errorf("withheld %v\n   want %s\n%s", paths, want, out)
	}
	for _, kept := range []string{"kept-notes", "kept-mode", "kept-doc", "kept-json", "keptPointer"} {
		if !strings.Contains(out, kept) {
			t.Errorf("%s was withheld", kept)
		}
	}
	body := deepCopy(r)
	if err := fillFrom(deepCopy(original), body, withheldEnv(body)); err != nil || !reflect.DeepEqual(body["spec"], original["spec"]) {
		t.Errorf("filled back: %v", err)
	}
	// An application's values written as text that cannot be read.
	app := map[string]any{"apiVersion": "argoproj.io/v1alpha1", "kind": "Application", "metadata": map[string]any{"name": "a", "namespace": "argocd"},
		"spec": map[string]any{"source": map[string]any{"helm": map[string]any{"values": "replicas: {{ .n }}-x\nimage: app\n"}}}}
	if paths, _ := withheldOf("argoproj.io", "applications", app); strings.Join(paths, " ") != "spec.source.helm.values" {
		t.Errorf("values that cannot be read: withheld %v", paths)
	}
}

// What is no text is withheld under a name that says a credential, and
// comes back as what it was; a ConfigMap's binary keys are read.
func TestWhatIsNoTextIsWithheld(t *testing.T) {
	pod := map[string]any{"apiVersion": "example.com/v1", "kind": "Thing", "metadata": map[string]any{"name": "p", "namespace": "x"},
		"spec": map[string]any{"env": []any{
			map[string]any{"name": "DB_PASSWORD", "value": int64(987654321)},
			map[string]any{"name": "API_KEY", "value": 1.5e+22},
			map[string]any{"name": "TOKEN_TTL", "value": int64(987654321)},
			map[string]any{"name": "PIN_PASSWORD", "value": int64(1234)}, // small: a setting
			map[string]any{"name": "USE_PASSWORD", "value": true},
			map[string]any{"name": "PORT", "value": int64(80808080)},
		}}}
	original := deepCopy(pod)
	paths, _ := withheldOf("example.com", "things", pod)
	if strings.Join(paths, " ") != "spec.env[API_KEY]#number spec.env[DB_PASSWORD]#number" {
		t.Errorf("numbers under names: withheld %v", paths)
	}
	body := deepCopy(pod)
	if err := fillFrom(deepCopy(original), body, withheldEnv(body)); err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(body["spec"])
	b, _ := json.Marshal(original["spec"])
	if string(a) != string(b) {
		t.Errorf("filled back:\n got %s\nwant %s", a, b)
	}
	if v := body["spec"].(map[string]any)["env"].([]any)[0].(map[string]any)["value"]; !reflect.DeepEqual(v, int64(987654321)) {
		t.Errorf("a number came back as %T %v", v, v)
	}

	cm := map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "c", "namespace": "x"},
		"binaryData": map[string]any{
			"api-token":   "czNjcjN0LTE=",                                 // by its name
			"blob":        "cG9zdGdyZXM6Ly9hcHA6czNjcjN0QGRiL2FwcA==",     // postgres://app:s3cr3t@db/app
			"logo.png":    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ", // kept
			"notes":       "a2VwdCBub3Rlcw==",                             // kept
			"empty-token": "",
		}}
	paths, out := withheldOf("", "configmaps", cm)
	if strings.Join(paths, " ") != "binaryData[api-token] binaryData[blob]" || !strings.Contains(out, "iVBORw0KGgo") || !strings.Contains(out, "a2VwdCBub3Rlcw==") {
		t.Errorf("binary keys: withheld %v\n%s", paths, out)
	}
	if err := setSlots(cm, withheldEnv(cm), map[string]string{"binaryData[api-token]": "czNjcjN0LTE=", "binaryData[blob]": "eA=="}); err != nil || cm["binaryData"].(map[string]any)["blob"] != "eA==" {
		t.Errorf("a binary key filled: %v", err)
	}
}

// What a live object says was withheld from it is not this capture's
// word: a person who can write to the source would otherwise choose
// which of its values a restore takes from a file.
func TestALiveObjectsOwnMarksAreStripped(t *testing.T) {
	pod := map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "p", "namespace": "x",
		"annotations": map[string]any{WithheldEnvAnnotation: "spec.containers[c].env[REGION]", "kept": "yes"}},
		"spec": map[string]any{"containers": []any{map[string]any{"name": "c", "env": []any{map[string]any{"name": "REGION", "value": "east"}}}}}}
	if paths, out := withheldOf("", "pods", pod); paths != nil || strings.Contains(out, "withheld-env") || !strings.Contains(out, `"kept":"yes"`) {
		t.Errorf("a mark the live object carried: %v\n%s", paths, out)
	}
	pod["metadata"].(map[string]any)["annotations"] = map[string]any{WithheldEnvAnnotation: "spec.containers[c].env[REGION]"}
	pod["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["env"] = []any{map[string]any{"name": "REGION", "value": "east"}, map[string]any{"name": "DB_PASSWORD", "value": "s3cr3t"}}
	if paths, _ := withheldOf("", "pods", pod); strings.Join(paths, " ") != "spec.containers[c].env[DB_PASSWORD]" {
		t.Errorf("only what this capture withheld is marked: %v", paths)
	}
	secret := map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"name": "s", "namespace": "x", "annotations": map[string]any{WithheldAnnotation: "made-up"}}}
	normalize("", "secrets", secret)
	if b, _ := json.Marshal(secret); strings.Contains(string(b), "made-up") || strings.Contains(string(b), "annotations") {
		t.Errorf("a Secret's mark the live object carried: %s", b)
	}
}

// A key with a dot in it beside the same keys nested: two slots, two
// paths, both filled. The rule before gave both one path; its snapshot
// is restored where only one of the two was withheld, and refused where
// which is which cannot be told.
func TestADottedKeyBesideTheSameKeysNested(t *testing.T) {
	env := func(name, value string) map[string]any {
		return map[string]any{"env": []any{map[string]any{"name": name, "value": value}}}
	}
	make := func(dotted, nested string) map[string]any {
		return releaseWith(map[string]any{"a.b": env("DB_PASSWORD", dotted), "a": map[string]any{"b": env("DB_PASSWORD", nested)}})
	}
	// Outside values as well: a custom resource keyed by files' names.
	custom := map[string]any{"apiVersion": "example.com/v1", "kind": "Thing", "metadata": map[string]any{"name": "t", "namespace": "x"},
		"spec": map[string]any{"values": map[string]any{"a.b": env("DB_PASSWORD", "s3cr3t-dotted"), "a": map[string]any{"b": env("DB_PASSWORD", "s3cr3t-nested")}}}}
	wasCustom := deepCopy(custom)
	paths, _ := withheldOf("example.com", "things", custom)
	if strings.Join(paths, " ") != "=spec.values.a.b.env[DB_PASSWORD] spec.values.a%2Eb.env[DB_PASSWORD]" {
		t.Errorf("a custom resource: withheld %v", paths)
	} else if err := fillFrom(deepCopy(wasCustom), custom, withheldEnv(custom)); err != nil || !reflect.DeepEqual(custom["spec"], wasCustom["spec"]) {
		t.Errorf("a custom resource, filled back: %v", err)
	}

	r := make("s3cr3t-dotted", "s3cr3t-nested")
	original := deepCopy(r)
	paths, out := withheldOf("helm.toolkit.fluxcd.io", "helmreleases", r)
	if strings.Join(paths, " ") != "=spec.values.a.b.env[DB_PASSWORD] spec.values.a%2Eb.env[DB_PASSWORD]" || strings.Contains(out, "s3cr3t") {
		t.Fatalf("withheld %v\n%s", paths, out)
	}
	for how, fill := range map[string]func(body map[string]any, paths []string) error{
		"from a file": func(body map[string]any, paths []string) error {
			return setSlots(body, paths, map[string]string{"spec.values.a%2Eb.env[DB_PASSWORD]": "s3cr3t-dotted", "=spec.values.a.b.env[DB_PASSWORD]": "s3cr3t-nested"})
		},
		"from its cluster": func(body map[string]any, paths []string) error { return fillFrom(deepCopy(original), body, paths) },
	} {
		body := deepCopy(r)
		if err := fill(body, withheldEnv(body)); err != nil || !reflect.DeepEqual(body["spec"], original["spec"]) {
			t.Errorf("%s: %v\n got %v\nwant %v", how, err, body["spec"], original["spec"])
		}
	}

	// The rule before, where it withheld one of the two: the path is the
	// nested one's own, and the dotted one's as it was.
	old := "spec.values.a.b.env[DB_PASSWORD]"
	for which, live := range map[string]map[string]any{"the dotted one": make("s3cr3t", "$(OTHER)"), "the nested one": make("$(OTHER)", "s3cr3t")} {
		snap := deepCopy(live)
		for _, sl := range slotsBefore(snap) {
			if credential(sl.name, sl.value) {
				sl.set("")
			}
		}
		for how, fill := range map[string]func(body map[string]any) error{
			"from a file": func(body map[string]any) error {
				return setSlots(body, []string{old}, map[string]string{old: "s3cr3t"})
			},
			"from its cluster": func(body map[string]any) error { return fillFrom(deepCopy(live), body, []string{old}) },
		} {
			body := deepCopy(snap)
			if err := fill(body); err != nil || !reflect.DeepEqual(body["spec"], live["spec"]) {
				t.Errorf("%s withheld by the rule before, %s: %v\n got %v\nwant %v", which, how, err, body["spec"], live["spec"])
			}
		}
	}
	// This build's snapshot where one of the two was empty in the cluster
	// and never withheld: the path is marked as the slot's own, and is
	// filled though both are empty in the snapshot. Either may be the one.
	for which, live := range map[string]map[string]any{"the nested one": make("", "s3cr3t"), "the dotted one": make("s3cr3t", "")} {
		snap := deepCopy(live)
		paths, _ := withheldOf("helm.toolkit.fluxcd.io", "helmreleases", snap)
		if len(paths) != 1 || (which == "the nested one") != strings.HasPrefix(paths[0], "=") {
			t.Errorf("%s withheld beside an empty twin: listed as %v", which, paths)
		}
		for how, fill := range map[string]func(body map[string]any, paths []string) error{
			"from a file": func(body map[string]any, paths []string) error {
				return setSlots(body, paths, map[string]string{paths[0]: "s3cr3t"})
			},
			"from its cluster": func(body map[string]any, paths []string) error { return fillFrom(deepCopy(live), body, paths) },
		} {
			body := deepCopy(snap)
			if err := fill(body, withheldEnv(body)); err != nil || !reflect.DeepEqual(body["spec"], live["spec"]) {
				t.Errorf("%s withheld beside an empty twin, %s: %v\n got %v\nwant %v", which, how, err, body["spec"], live["spec"])
			}
		}
	}
	if got := WithheldDisplay("=data[API_KEY]"); got != "data/API_KEY" {
		t.Errorf("a marked path is shown as %q", got)
	}
	// Both withheld by it, under one path written twice; and both empty in
	// the snapshot with one path asked for.
	both := make("", "")
	if err := setSlots(deepCopy(both), []string{old, old}, map[string]string{old: "x"}); err == nil || !strings.Contains(err.Error(), "which is which cannot be told") {
		t.Errorf("one path twice: %v", err)
	}
	if err := setSlots(deepCopy(both), []string{old}, map[string]string{old: "x"}); err == nil || !strings.Contains(err.Error(), "could be at") {
		t.Errorf("two empty slots one path could name: %v", err)
	}
	if err := setSlots(deepCopy(both), []string{"spec.values.gone.env[X]"}, map[string]string{}); err == nil || !strings.Contains(err.Error(), "the snapshot has no slot") {
		t.Errorf("a path that names nothing: %v", err)
	}
	if err := fillFrom(make("x", "y"), deepCopy(both), []string{"spec.values.gone.env[X]"}); err == nil || !strings.Contains(err.Error(), "the source: the snapshot has no slot") {
		t.Errorf("a path that names nothing, from the cluster: %v", err)
	}
	// A line for a slot the source no longer has.
	if err := fillFrom(releaseWith(map[string]any{}), deepCopy(r), paths); err == nil || !strings.Contains(err.Error(), "no value for") {
		t.Errorf("a slot the source does not have: %v", err)
	}
}
