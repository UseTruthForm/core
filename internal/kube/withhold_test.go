package kube

import (
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The cases four rounds of review ran through this rule and through the
// one before it. What the rule for variables withholds is still withheld
// (slot.withheld is that rule, or a shape); these are what is added, and
// what has to be kept.

func TestURLsThatSignIn(t *testing.T) {
	for url, want := range map[string]bool{
		"postgres://app:pw@db:5432/app":                                            true,
		"postgres://app:p<w@db:5432/app":                                           true,
		"postgres://app:p>w@db:5432/app":                                           true,
		"postgres://app:p'w@db:5432/app":                                           true,
		`postgres://app:p"w@db:5432/app`:                                           true,
		"postgres://app:p/w@db:5432/app":                                           true,
		"postgres://app:p?w@db:5432/app":                                           true,
		"postgres://app:p#w@db:5432/app":                                           true,
		"postgres://app:p@w@db:5432/app":                                           true,
		"postgres://app:p%40w@db:5432/app":                                         true,
		"https://user:pw@host/path":                                                true,
		"https://ghp_0123456789abcdefghijABCDEFGHIJ0123456789@github.com/org/repo": true,
		"redis://:pw@host":                                                         true,
		"mongodb+srv://u:p@h/db?retryWrites=true":                                  true,
		"amqp://u:p@h":                                                             true,
		"jdbc:postgresql://h/db?user=u&password=p":                                 true,
		"jdbc:sqlserver://h;user=u;password=p":                                     true,
		"https://example.com/hook?token=abc123":                                    true,
		"https://example.com/x?a=1&access_token=abc":                               true,
		"https://example.com/x?api_key=abc":                                        true,
		"https://example.com/x?sig=abc":                                            true,
		"https://example.com/cb?client_secret=abc":                                 true,
		"https://example.com/cb#access_token=abc":                                  true,
		"https://hooks.slack.com/services/T000/B000/XXXXXXXX":                      true,
		"https://discord.com/api/webhooks/123/abc":                                 true,
		"https://corp.webhook.office.com/webhookb2/abc":                            true,
		"see https://user:pw@host/path for the mirror":                             true, // inside a sentence
		"https://example.com https://user:pw@host/x":                               true, // the second of two
		"https://user:pw@[::1]:8443/x":                                             true,
		"https://user:pw@host/path\n":                                              true,
		"HTTPS://user:pw@host/path":                                                true,
		"http://es-0:9200,http://u:pw@es-1:9200":                                   true,
		// Accounts, and an "@" that signs nothing in.
		"https://git@host/org/repo":                         false,
		"https://org@dev.example.com/org/p/_git/r":          false,
		"ssh://git@host/x":                                  false,
		"sftp://deploy@host":                                false,
		"http://grafana:3000/d/a?mail=ops@example.com":      false,
		"http://localhost:8080/users/bob@example.com":       false,
		"http://cdn:8080/img/logo@2x.png":                   false,
		"http://registry:4873/@my.org/pkg":                  false,
		"http://es-0:9200,http://elastic@es-1:9200":         false,
		"https://example.com/reset?token=<your-token>":      false,
		"https://example.com/reset?token={{ token }}":       false,
		"https://vault.example.com/v1/kv?secret=app-config": false,
		"http://host:8080?x=a@b":                            false,
		"https://[::1]/o/a@b":                               false,
		"https://example.com/o/fleet.git":                   false,
		"git@example.com:o/fleet.git":                       false,
		"oci://registry.example.com/charts":                 false,
	} {
		if got := signs(url); got != want {
			t.Errorf("signs(%q) = %v, want %v", url, got, want)
		}
	}
}

func TestValueShapes(t *testing.T) {
	for value, want := range map[string]bool{
		"Bearer abcdefghijklmnop1234": true,
		"Basic dXNlcjpwYXNz":          true, // user:pass
		"Token 0123456789abcdef0":     true,
		"-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----": true,
		"-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl":                            true,
		"Zm9vQmFyQmF6MTIzNDU2Nzg5MGFiY2RlZkdISUpLTE1OTw==":                     true, // nothing to read in it
		"xoxb0A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6":                                true,
		// Words, settings, public things.
		"Basic production":                  false,
		"basic authentication":              false,
		"token exchange":                    false,
		"Bearer":                            false,
		"token v1.2.3-production-build":     false,
		"basic authentication-2fa-required": false,
		"-----BEGIN CERTIFICATE-----\nMIID\n-----END CERTIFICATE-----":            false,
		"-----BEGIN PUBLIC KEY-----\nMIIB":                                        false,
		"sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08": false,
		"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b":                                false, // a commit: one case
		"123e4567-e89b-12d3-a456-426614174000":                                    false,
		"my-service.my-namespace.svc.cluster.local.Example1":                      false,
		"registry.example.com/team/app:v1.2.3":                                    false,
		"info":                                                                    false,
	} {
		if got := shaped(value); got != want {
			t.Errorf("shaped(%q) = %v, want %v", value, got, want)
		}
	}
}

func TestNamesThatSayACredential(t *testing.T) {
	for name, want := range map[string]bool{
		"password": true, "adminPassword": true, "pass": true, "dbPass": true, "adminPass": true, "smtp.pass": true,
		"appKey": true, "fernetKey": true, "hmacKey": true, "jwtKey": true, "secretKeyBase": true, "clientSecretValue": true,
		"tls.key": true, "sshKey": true, "cloudflareAPIToken": true, "openAIAPIKey": true, "SASToken": true, "APITOKEN": true,
		"DB_PASS": true, "SMTP_PASS": true, "APP_KEY": true, "auth.token": true, "db.password": true, "existingPassword": true,
		"sentry.dsn": true, "pwd": true, "connectionString": true, "storageSAS": true, "jwtSigningSalt": true, "license": true,
		"publicKeyPassword": true, "existingSecretPassword": true, "htpasswd": true, "slack-token": true, "secretKey": true,
		// What names a thing.
		"secretName": false, "ingress.tls.secretName": false, "existingSecret": false, "auth.existingSecret": false,
		"existingSecretKey": false, "aws.credentials.secretName": false, "tokenSecretRef": false, "passwordSecretName": false,
		"publicKey": false, "public_key": false, "keyName": false, "pullSecret": false, "imagePullSecrets": false, "tlsSecret": false,
		"existingPasswordSecret": false, "monkey": false, "author": false, "authority": false, "bypass": false,
		// What says nothing.
		"replicas": false, "image.tag": false, "host": false, "auth.host": false, "logLevel": false,
	} {
		if got := saysCredential(name); got != want {
			t.Errorf("saysCredential(%q) = %v, want %v", name, got, want)
		}
	}
	// Under these, everything is one; under those, there are hosts and
	// names as well.
	for key, want := range map[string]bool{"password": true, "passwords": true, "tokens": true, "credentials": true, "secret": true, "dsn": true,
		"auth": false, "key": false, "keys": false, "existingSecret": false, "secretName": false, "replicas": false} {
		if got := underSays(key); got != want {
			t.Errorf("underSays(%q) = %v, want %v", key, got, want)
		}
	}
	// A boolean, a value that only points at another, and a small number
	// where it is a number: text that is digits may be a password.
	for value, want := range map[string]bool{
		"": true, "true": true, "False": true, "no": true, "off": true, "$(OTHER)": true, "${cluster_token}": true, "{{ .Values.password }}": true, "{{password}}": true,
		"none": false, "enabled": false, "null": false, "123456": false, "hunter2": false, "${DB_PASSWORD:=literal}": false, `{{ default "literal" .x }}`: false,
	} {
		if got := certainlyNot(value, false); got != want {
			t.Errorf("certainlyNot(%q) = %v, want %v", value, got, want)
		}
	}
	for value, want := range map[string]bool{"3600": true, "4096": true, "-1": true, "123456": true, "1234567": false} {
		if got := certainlyNot(value, true); got != want {
			t.Errorf("certainlyNot(%q) as a number = %v, want %v", value, got, want)
		}
	}
}

// withheldOf captures an object and gives what was withheld from it, and
// the object as the snapshot holds it.
func withheldOf(group, resource string, o map[string]any) ([]string, string) {
	normalize(group, resource, o)
	v := annotation(o["metadata"].(map[string]any), WithheldEnvAnnotation)
	b, _ := json.Marshal(o)
	if v == "" {
		return nil, string(b)
	}
	return strings.Split(v, ","), string(b)
}

func TestHelmValuesAreWithheldGenerously(t *testing.T) {
	values := map[string]any{
		// Withheld: each has s3cr3t in it, or is listed below.
		"password": "s3cr3t-1", "adminPassword": "s3cr3t-2", "dbPass": "s3cr3t-3", "appKey": "s3cr3t-4", "fernetKey": "s3cr3t-5",
		"smtp":               map[string]any{"pass": "s3cr3t-6", "host": "kept-smtp-host"},
		"cloudflareAPIToken": "s3cr3t-7", "SASToken": "s3cr3t-8",
		"existingPassword": "s3cr3t-9",
		"credentials":      map[string]any{"existingSecret": "kept-cloud-credentials", "token": "s3cr3t-10"},
		"db":               map[string]any{"password": map[string]any{"value": "s3cr3t-11", "secretKeyRef": map[string]any{"name": "kept-ref", "key": "kept-ref-key"}}},
		"tls":              map[string]any{"key": "-----BEGIN PRIVATE KEY-----\ns3cr3t-12\n-----END PRIVATE KEY-----", "secretName": "kept-tls"},
		"externalDatabase": map[string]any{"url": "postgres://app:s3cr3t-13@db/app"},
		"extraEnv":         []any{map[string]any{"name": "DB_PASSWORD", "value": "s3cr3t-14"}, map[string]any{"name": "LOG_LEVEL", "value": "kept-info"}},
		"pin":              map[string]any{"token": 31415926},
		"with,comma":       map[string]any{"password": "s3cr3t-15"},
		"auth.token":       "s3cr3t-16",
		"auth":             map[string]any{"token": "s3cr3t-17", "host": "kept-auth-host", "existingSecret": "kept-auth-secret", "usePasswordFiles": true},
		"opaque":           "Zm9vQmFyQmF6MTIzNDU2Nzg5MGFiY2RlZkdISUpLTE1OTw==",
		// Kept.
		"tolerations":    []any{map[string]any{"key": "kept-dedicated", "operator": "Equal", "value": "kept-gpu", "effect": "NoSchedule"}},
		"affinity":       map[string]any{"matchExpressions": []any{map[string]any{"key": "kept-zone", "operator": "In", "values": []any{"kept-a"}}}},
		"bootstrapToken": map[string]any{"secretName": "kept-bootstrap"},
		"maxTokens":      4096, "tokenExpiration": 3600, "passwordAuthentication": "no", "tokenAuthEnabled": true,
		"replicas": 3, "image": map[string]any{"tag": "kept-v1"},
		"pullSecretName": "kept-registry-login",
	}
	release := map[string]any{"apiVersion": "helm.toolkit.fluxcd.io/v2", "kind": "HelmRelease", "metadata": map[string]any{"name": "shop", "namespace": "shop"},
		"spec": map[string]any{"values": values}}
	paths, out := withheldOf("helm.toolkit.fluxcd.io", "helmreleases", release)
	for _, leak := range []string{"s3cr3t", "31415926", "Zm9vQmFy"} {
		if strings.Contains(out, leak) {
			t.Errorf("a credential (%s) is in the snapshot:\n%s", leak, out)
		}
	}
	for _, kept := range []string{"kept-smtp-host", "kept-cloud-credentials", "kept-ref", "kept-ref-key", "kept-tls", "kept-info", "kept-auth-host", "kept-auth-secret",
		"kept-dedicated", "kept-gpu", "kept-zone", "kept-a", "kept-bootstrap", "4096", "3600", `"passwordAuthentication":"no"`, "kept-v1", "kept-registry-login"} {
		if !strings.Contains(out, kept) {
			t.Errorf("%s was withheld: %v", kept, paths)
		}
	}
	// Each has a path of its own: a comma in a key, a dot in a key beside
	// the same two keys nested, and a number is marked as one.
	seen := map[string]bool{}
	for _, p := range paths {
		if seen[p] {
			t.Errorf("the path %q is given twice", p)
		}
		seen[p] = true
	}
	for _, want := range []string{"spec.values.with%2Ccomma.password", "spec.values.auth%2Etoken", "spec.values.auth.token", "spec.values.pin.token" + numberMark, "spec.values.extraEnv[0].value"} {
		if !seen[want] {
			t.Errorf("no path %q among %v", want, paths)
		}
	}
	// Filled, every value is back where it was and as what it was.
	given := map[string]string{}
	for _, p := range paths {
		given[p] = "back:" + p
	}
	given["spec.values.pin.token"+numberMark] = "31415926"
	body := deepCopy(release)
	if err := setSlots(body, withheldEnv(body), given); err != nil {
		t.Fatal(err)
	}
	got := body["spec"].(map[string]any)["values"].(map[string]any)
	if got["auth.token"] != "back:spec.values.auth%2Etoken" || got["auth"].(map[string]any)["token"] != "back:spec.values.auth.token" {
		t.Errorf("a dotted key and the same keys nested: %v, %v", got["auth.token"], got["auth"])
	}
	if n := got["pin"].(map[string]any)["token"]; !reflect.DeepEqual(n, int64(31415926)) {
		t.Errorf("a number came back as %T %v", n, n)
	}
	given["spec.values.pin.token"+numberMark] = "not a number"
	if err := setSlots(deepCopy(release), paths, given); err == nil || !strings.Contains(err.Error(), "it was a number") {
		t.Errorf("text given for a number: %v", err)
	}
}

func TestArgoValuesAreWithheldGenerously(t *testing.T) {
	set := map[string]any{"apiVersion": "argoproj.io/v1alpha1", "kind": "ApplicationSet", "metadata": map[string]any{"name": "fleet", "namespace": "argocd"},
		"spec": map[string]any{
			"generators": []any{
				map[string]any{"list": map[string]any{"elements": []any{map[string]any{"cluster": "kept-east", "token": "s3cr3t-1", "url": "https://kept.example.com"}}}},
				map[string]any{"plugin": map[string]any{"input": map[string]any{"parameters": map[string]any{"apiKey": "s3cr3t-2", "region": "kept-region"}}, "values": map[string]any{"password": "s3cr3t-3"}}},
			},
			"templatePatch": "spec:\n  source:\n    helm:\n      values: |\n        {{- if .x }}\n        password: s3cr3t-4\n        {{- end }}\n",
			"template": map[string]any{"spec": map[string]any{"source": map[string]any{
				"repoURL": "https://kept.example.com/o/apps.git",
				"helm": map[string]any{
					"parameters": []any{
						map[string]any{"name": "auth.token", "value": "s3cr3t-5"},
						map[string]any{"name": "db.password", "value": "s3cr3t-6"},
						map[string]any{"name": "replicaCount", "value": "3"},
						map[string]any{"name": "image.tag", "value": "kept-v2"},
						map[string]any{"name": "ingress.tls.secretName", "value": "kept-tls-name"},
						map[string]any{"name": "auth.usePasswordFiles", "value": "true"},
						map[string]any{"name": "redis.usePassword", "value": "false"},
					},
					"values":       "db:\n  password: s3cr3t-7\n",
					"valuesObject": map[string]any{"db": map[string]any{"password": "s3cr3t-8", "host": "kept-db-host"}},
				},
				"directory": map[string]any{"jsonnet": map[string]any{
					"extVars": []any{map[string]any{"name": "dbPassword", "value": "s3cr3t-9"}, map[string]any{"name": "region", "value": "kept-jsonnet"}},
					"tlas":    []any{map[string]any{"name": "apiToken", "value": "s3cr3t-10"}},
				}},
				"plugin": map[string]any{"parameters": []any{
					map[string]any{"name": "db_password", "string": "s3cr3t-11"},
					map[string]any{"name": "tokens", "array": []any{"s3cr3t-12"}},
					map[string]any{"name": "password", "map": map[string]any{"primary": "s3cr3t-13"}},
					map[string]any{"name": "settings", "map": map[string]any{"client-secret": "s3cr3t-14", "region": "kept-plugin-region"}},
					map[string]any{"name": "hosts", "array": []any{"kept-host"}},
				}},
			}}},
		}}
	paths, out := withheldOf("argoproj.io", "applicationsets", set)
	if strings.Contains(out, "s3cr3t") {
		t.Errorf("a credential is in the snapshot: %v\n%s", paths, out)
	}
	for _, kept := range []string{"kept-east", "https://kept.example.com", "kept-region", "kept-v2", "kept-tls-name", `"value":"3"`, `"value":"true"`, `"value":"false"`, "kept-db-host", "kept-jsonnet", "kept-plugin-region", "kept-host"} {
		if !strings.Contains(out, kept) {
			t.Errorf("%s was withheld: %v", kept, paths)
		}
	}

	ks := map[string]any{"apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization", "metadata": map[string]any{"name": "apps", "namespace": "flux-system"},
		"spec": map[string]any{"postBuild": map[string]any{"substitute": map[string]any{"DB_PASS": "s3cr3t-1", "SMTP_PASS": "s3cr3t-2", "APP_KEY": "s3cr3t-3", "cluster_name": "kept-cluster"}}}}
	paths, out = withheldOf("kustomize.toolkit.fluxcd.io", "kustomizations", ks)
	if len(paths) != 3 || strings.Contains(out, "s3cr3t") || !strings.Contains(out, "kept-cluster") {
		t.Errorf("substitutions: %v\n%s", paths, out)
	}

	wf := map[string]any{"apiVersion": "argoproj.io/v1alpha1", "kind": "WorkflowTemplate", "metadata": map[string]any{"name": "w", "namespace": "x"},
		"spec": map[string]any{"arguments": map[string]any{"parameters": []any{
			map[string]any{"name": "db_password", "value": "s3cr3t-1"}, map[string]any{"name": "region", "value": "kept-wf"}}}}}
	paths, out = withheldOf("argoproj.io", "workflowtemplates", wf)
	if len(paths) != 1 || strings.Contains(out, "s3cr3t") || !strings.Contains(out, "kept-wf") {
		t.Errorf("a workflow's parameters: %v\n%s", paths, out)
	}

	repo := map[string]any{"apiVersion": "source.toolkit.fluxcd.io/v1", "kind": "GitRepository", "metadata": map[string]any{"name": "fleet", "namespace": "flux-system"},
		"spec": map[string]any{"url": "https://git:s3cr3t@example.com/o/fleet.git", "sourceRepos": []any{"https://kept.example.com", "https://u:s3cr3t@example.com/x"}}}
	paths, out = withheldOf("source.toolkit.fluxcd.io", "gitrepositories", repo)
	if strings.Join(paths, " ") != "spec.sourceRepos[1] spec.url" || strings.Contains(out, "s3cr3t") {
		t.Errorf("where a repository is read from: %v\n%s", paths, out)
	}
}

// Text is never kept for want of a parse, and text with no credential in
// it is kept, template or not.
func TestTextIsReadThoughItDoesNotParse(t *testing.T) {
	for text, want := range map[string]bool{
		"db:\n  password: s3cr3t\n":                                               true,
		"replicas: 2\n---\ndb:\n  password: s3cr3t\n":                             true,
		"db:\n  password: s3cr3t\n---\nreplicas: 2\n":                             true,
		"1: x\n2:\n  token: s3cr3t\n":                                             true,
		"cluster: {{cluster}}\ndb:\n  password: s3cr3t\n":                         true,
		"a: 1\na: 2\ntoken: s3cr3t\n":                                             true,
		"\tindented: with a tab\napiKey: s3cr3t\n":                                true,
		"{{ broken\npassword:\n  s3cr3t\n":                                        true, // the value on the next line
		"{{ broken\npassword:\n  value: s3cr3t\n":                                 true,
		"{{ broken\ntokens:\n  - s3cr3t\n":                                        true,
		"{{ broken\nauth: {password: s3cr3t}\n":                                   true,
		"{{ broken\nenv:\n  - name: DB_PASSWORD\n    value: s3cr3t\n":             true,
		"{{ broken\nsecret: |\n  s3cr3t\n":                                        true,
		"{{ broken\n{{name}}_password: s3cr3t\n":                                  true,
		"{{ broken\n\"db password\": s3cr3t\n":                                    true,
		"repo: https://git:s3cr3t@example.com/o\n{{ broken":                       true,
		"extraEnv:\n  - name: DB_PASSWORD\n    value: s3cr3t\n":                   true,
		"cluster: {{cluster}}\nreplicas: 2\n":                                     false,
		"tolerations:\n  - key: dedicated\n    operator: Equal\n    value: gpu\n": false,
		// What cannot be read is withheld whole, whatever is in it.
		"{{ broken\nauth:\n  existingSecret: db\n  usePasswordFiles: true\n": true,
		"{{ broken\nsecretName: registry-login\nmaxTokens: 4096\n":           true,
		"replicas: {{ .Values.replicas }}-x\n":                               true,
		"password: real\npassword: true\n":                                   true, // a key set twice
		// What is no document is read line by line.
		"DB_PASSWORD=s3cr3t\nPORT=80":               true,
		"admin_password = s3cr3t\nport = 80":        true,
		"spring.datasource.password=s3cr3t\na=b":    true,
		"#!/bin/sh\nexport API_TOKEN=s3cr3t\nrun":   true,
		"PORT=80\nMODE=fast":                        false,
		"#!/bin/sh\nexport REGION=east\nrun --fast": false,
		"a note\nof two lines":                      false,
		"replicas: 2\nimage:\n  tag: v1\n":          false,
	} {
		if got := textHolds(text); got != want {
			t.Errorf("textHolds(%q) = %v, want %v", text, got, want)
		}
	}
}

// What the rule for variables withheld, it still withholds, and the
// shapes are read in a variable and a ConfigMap as anywhere; what was kept
// for good reason is kept.
func TestVariablesKeepTheirRuleAndGainTheShapes(t *testing.T) {
	env := func(pairs ...string) []any {
		var out []any
		for i := 0; i < len(pairs); i += 2 {
			out = append(out, map[string]any{"name": pairs[i], "value": pairs[i+1]})
		}
		return out
	}
	pod := map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "p", "namespace": "x"},
		"spec": map[string]any{"containers": []any{map[string]any{"name": "c",
			"envFrom": []any{map[string]any{"secretRef": map[string]any{"name": "kept-envfrom"}}},
			"env": append(env(
				"DB_PASSWORD", "s3cr3t-1", "PGPASSWORD", "s3cr3t-2", "API_TOKEN", "s3cr3t-3", "CLIENT_SECRET", "s3cr3t-4", "API_KEY", "s3cr3t-5",
				"SIGNING_KEY", "s3cr3t-6", "SENTRY_DSN", "s3cr3t-7", "DATABASE_URL", "postgres://app:s3cr3t-8@db/app", "REDIS_URL", "redis://:s3cr3t-9@cache",
				"MIRROR", "see https://u:s3cr3t-10@host/x", "UPSTREAM_AUTH", "Bearer s3cr3t10abcdefghijk", "HOOK", "https://hooks.slack.com/services/T0/B0/s3cr3t-11",
				"DSN_WITH_QUERY", "https://example.com/x?token=s3cr3t-12", "BLOB", "s3cr3tQmFyQmF6MTIzNDU2Nzg5MGFiY2RlZkdISUpLTE1OTw",
				"LOG_LEVEL", "kept-info", "PASSWORD_MIN_LENGTH", "12", "TOKEN_TTL", "3600", "KEY_PREFIX", "kept-prefix", "SECRET_NAME", "kept-secret-name",
				"PUBLIC_KEY", "kept-public", "AWS_REGION", "kept-region", "AUTH_MODE", "Basic authentication", "DOCS", "http://localhost:8080/users/bob@example.com",
			), map[string]any{"name": "FROM_SECRET", "valueFrom": map[string]any{"secretKeyRef": map[string]any{"name": "kept-ref", "key": "kept-key"}}}),
		}}}}
	paths, out := withheldOf("", "pods", pod)
	if strings.Contains(out, "s3cr3t") || len(paths) != 14 {
		t.Errorf("%d withheld: %v\n%s", len(paths), paths, out)
	}
	for _, kept := range []string{"kept-envfrom", "kept-info", `"value":"12"`, `"value":"3600"`, "kept-prefix", "kept-secret-name", "kept-public", "kept-region", "Basic authentication", "bob@example.com", "kept-ref", "kept-key"} {
		if !strings.Contains(out, kept) {
			t.Errorf("%s was withheld: %v", kept, paths)
		}
	}
	cm := map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "c", "namespace": "x"},
		"data": map[string]any{"app.conf": "db = postgres://app:s3cr3t@db/app\nmode = fast\n", "ca.crt": "-----BEGIN CERTIFICATE-----\nkept-ca\n-----END CERTIFICATE-----", "id_rsa": "-----BEGIN RSA PRIVATE KEY-----\ns3cr3t\n", "mode": "kept-mode"}}
	paths, out = withheldOf("", "configmaps", cm)
	if strings.Join(paths, " ") != "data[app.conf] data[id_rsa]" || strings.Contains(out, "s3cr3t") || !strings.Contains(out, "kept-ca") {
		t.Errorf("a ConfigMap: %v\n%s", paths, out)
	}
}

// What a second review's comparison with the rule before found.

// A value however long is read in one pass: a dashboard of some
// megabytes with an address on every line is a ConfigMap like any other.
func TestShapesAreReadInOnePass(t *testing.T) {
	for name, unit := range map[string]string{
		"an address a line":    "  \"url\": \"http://grafana:3000/d/abc?orgId=1\",\n",
		"addresses and commas": "http://host:8080,",
		"a setting a line":     "scrape_interval: 15s\n",
	} {
		big := strings.Repeat(unit, 2<<20/len(unit))
		start := time.Now()
		// Its shape says nothing. As a document it is withheld whole where
		// it cannot be read or sets a key twice: only the time is held to.
		if shaped(big) {
			t.Errorf("%s: read as a credential", name)
		}
		textHolds(big)
		// A pass takes a second or two, and five on a slow machine with
		// other tests running; read once over for each part of itself, a
		// text this long takes minutes. The limit is between the two, far
		// from both: nearer the first, it failed on a busy machine.
		if d := time.Since(start); d > 45*time.Second {
			t.Errorf("%s: 2 MB took %s", name, d)
		}
	}
}

// What the rule before withheld is withheld, at the path it had: a
// snapshot taken before restores now, and a line written for it holds.
func TestNothingTheRuleBeforeWithheldIsKept(t *testing.T) {
	env := []any{}
	for _, pair := range [][2]string{
		{"DB_PASSWORD", "s3cr3t-1"}, {"DB_PWD", "s3cr3t-2"}, {"CONNECTION_STRING", "s3cr3t-3"}, {"STORAGE_SAS", "s3cr3t-4"},
		{"ADMIN_PASSWORD", "123456"}, {"ROOT_PASSWORD", "none"}, {"APP_PASSWORD", "enabled"},
		{"DATABASE_URL", "postgres://app:12,s3cr3t@db/app"}, {"REDIS_URL", "postgres://app:123?s3cr3t@db/app"},
		{"LOG_LEVEL", "kept-info"},
	} {
		env = append(env, map[string]any{"name": pair[0], "value": pair[1]})
	}
	for name, o := range map[string]map[string]any{
		"a HelmRelease's values": {"apiVersion": "helm.toolkit.fluxcd.io/v2", "kind": "HelmRelease", "metadata": map[string]any{"name": "r", "namespace": "x"},
			"spec": map[string]any{"values": map[string]any{"env": deepCopy(map[string]any{"l": env})["l"]}}},
		"an application's valuesObject": {"apiVersion": "argoproj.io/v1alpha1", "kind": "Application", "metadata": map[string]any{"name": "a", "namespace": "argocd"},
			"spec": map[string]any{"source": map[string]any{"helm": map[string]any{"valuesObject": map[string]any{"env": deepCopy(map[string]any{"l": env})["l"]}}}}},
	} {
		paths, out := withheldOf("", "", o)
		if len(paths) != 9 || strings.Contains(out, "s3cr3t") || strings.Contains(out, `"value":"123456"`) || !strings.Contains(out, "kept-info") {
			t.Errorf("%s: %d withheld %v\n%s", name, len(paths), paths, out)
		}
		for _, p := range paths {
			if !strings.HasSuffix(p, ".env[DB_PASSWORD]") && !strings.Contains(p, ".env[") {
				t.Errorf("%s: the path %q is not a variable's, as it was", name, p)
			}
		}
		if !strings.Contains(strings.Join(paths, " "), ".env[DB_PASSWORD]") {
			t.Errorf("%s: no path by the variable's name: %v", name, paths)
		}
	}

	// Where GitOps starts was left out when a credential was written into
	// it. It is captured now, and none of what kept it out is kept in it.
	for name, url := range map[string]string{"a short token": "https://shorttoken1@example.com/o/r", "digits and a comma": "https://app:12,ab@example.com/o/r", "digits and a question": "https://app:123?456@example.com/o/r", "a password": "https://u:s3cr3t@example.com/o/r"} {
		repo := map[string]any{"apiVersion": "source.toolkit.fluxcd.io/v1", "kind": "GitRepository", "metadata": map[string]any{"name": "fleet", "namespace": "flux-system"}, "spec": map[string]any{"url": url}}
		if paths, _ := withheldOf("source.toolkit.fluxcd.io", "gitrepositories", repo); strings.Join(paths, " ") != "spec.url" {
			t.Errorf("%s in a repository's address: withheld %v", name, paths)
		}
	}
	for _, url := range []string{"ssh://git@example.com/o/r", "https://example.com/o/r", "oci://registry.example.com/charts"} {
		repo := map[string]any{"apiVersion": "source.toolkit.fluxcd.io/v1", "kind": "GitRepository", "metadata": map[string]any{"name": "fleet", "namespace": "flux-system"}, "spec": map[string]any{"url": url}}
		if paths, _ := withheldOf("source.toolkit.fluxcd.io", "gitrepositories", repo); paths != nil {
			t.Errorf("%s: withheld %v", url, paths)
		}
	}
	app := map[string]any{"apiVersion": "argoproj.io/v1alpha1", "kind": "Application", "metadata": map[string]any{"name": "root", "namespace": "argocd"},
		"spec": map[string]any{"source": map[string]any{"helm": map[string]any{"parameters": []any{
			map[string]any{"name": "DB_PWD", "value": "s3cr3t-1"}, map[string]any{"name": "db.password", "value": "123456"},
			map[string]any{"name": "db.password2", "value": "{{password}}"}, map[string]any{"name": "auth.usePasswordFiles", "value": "true"},
			map[string]any{"name": "replicaCount", "value": "3"},
		}}}}}
	paths, out := withheldOf("argoproj.io", "applications", app)
	if strings.Join(paths, " ") != "spec.source.helm.parameters[DB_PWD] spec.source.helm.parameters[db.password]" || !strings.Contains(out, "{{password}}") {
		t.Errorf("an application's parameters: %v\n%s", paths, out)
	}
}

// All that is under a name that says a credential is one, however deep
// and however written; what names a thing there is kept.
func TestEverythingUnderANameThatSaysOne(t *testing.T) {
	values := map[string]any{
		"passwords":        map[string]any{"admin": "s3cr3t-1", "deep": map[string]any{"er": "s3cr3t-2"}},
		"tokens":           []any{map[string]any{"name": "kept-ci", "value": "s3cr3t-3"}, []any{"s3cr3t-4", "s3cr3t-5"}},
		"extraEnv":         []any{map[string]any{"name": "DB_PASSWORD", "value": 31415926}},
		"password":         "123456",
		"htpasswd":         "admin:$2y$05$s3cr3t\nother:$2y$05$s3cr3t\n",
		"secrets":          []any{map[string]any{"name": "kept-secret-name", "key": "kept-secret-key"}},
		"imagePullSecrets": []any{map[string]any{"name": "kept-registry"}},
		"tolerations":      []any{map[string]any{"key": "kept-toleration", "value": "kept-toleration-value"}},
		"podAnnotations":   map[string]any{"example.com/auth-url": "kept-annotation"},
		"topologyKey":      "kept-not-under-affinity", // by its name: a line
		"token#number":     "s3cr3t-6",
		"a[0]":             map[string]any{"token": "s3cr3t-7"},
		"a":                []any{map[string]any{"token": "s3cr3t-8"}},
	}
	release := map[string]any{"apiVersion": "helm.toolkit.fluxcd.io/v2", "kind": "HelmRelease", "metadata": map[string]any{"name": "r", "namespace": "x"}, "spec": map[string]any{"values": values}}
	original := deepCopy(release)
	paths, out := withheldOf("helm.toolkit.fluxcd.io", "helmreleases", release)
	for _, leak := range []string{"s3cr3t", "31415926", `"password":"123456"`} {
		if strings.Contains(out, leak) {
			t.Errorf("%s is in the snapshot: %v\n%s", leak, paths, out)
		}
	}
	for _, kept := range []string{"kept-ci", "kept-secret-name", "kept-secret-key", "kept-registry", "kept-toleration", "kept-toleration-value", "kept-annotation"} {
		if !strings.Contains(out, kept) {
			t.Errorf("%s was withheld: %v", kept, paths)
		}
	}
	// Each at a path of its own, found again in the snapshot, and filled
	// back to the object it was.
	live := map[string]string{}
	for _, sl := range slots(original) {
		live[sl.path] = sl.value
	}
	body := deepCopy(release)
	if err := setSlots(body, withheldEnv(body), live); err != nil {
		t.Fatal(err)
	}
	// As JSON: a whole number is one, however it was read.
	if got, want := deepCopy(body)["spec"], original["spec"]; !reflect.DeepEqual(got, want) {
		t.Errorf("filled back:\n got %v\nwant %v", got, want)
	}
}

func TestMoreShapesAndWhatIsNoShape(t *testing.T) {
	for value, want := range map[string]bool{
		"Server=db;Database=app;User Id=sa;Password=s3cr3t;":             true,
		"host=db user=app password=s3cr3t dbname=app":                    true,
		"DefaultEndpointsProtocol=https;AccountName=a;AccountKey=s3cr3t": true,
		"https://ptb.discord.com/api/webhooks/1/abc":                     true,
		"https://hooks.slack.com/workflows/T0/A0/1/abc":                  true,
		"https://api.telegram.org/bot123:abc/sendMessage":                true,
		"https://bucket.s3.amazonaws.com/k?X-Amz-Signature=abc":          true,
		"https://example.com/x?refresh_token=abc":                        true,
		// Long, and read: a path, a class, a bucket, a public certificate.
		"/opt/app/config/Production/appsettings2.json":                                                             false,
		"/var/lib/AppData/cache_directory_v2/store":                                                                false,
		"org/springframework/boot/loader/JarLauncher2":                                                             false,
		"com.example.handlers.MyHandler2Implementation":                                                            false,
		"projects/my-proj/secrets/DbPassword/versions/latest1":                                                     false,
		"MyCompanyProductionArtifactsBucket2024eu":                                                                 false,
		"my_Service_Account_Name_For_Production_2":                                                                 false,
		"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURkekNDQWwrZ0F3SUJBZ0lFQWdBQXVUQU5CZ2txaGtpRzl3MEJBUVVGQURCYQ==": false,
		"token 2024-production-release-build":                                                                      false,
		"bearer token-for-service-account-1":                                                                       false,
		"http://host:port/a@b":                                                                                     false,
		"http://my-svc:http/a@b":                                                                                   false,
	} {
		if got := shaped(value); got != want {
			t.Errorf("shaped(%q) = %v, want %v", value, got, want)
		}
	}
	for text, want := range map[string]bool{
		"password: |\n  hunter2\n":                    true,
		"token: |-\n  line1\n  line2":                 true,
		"htpasswd: |\n  admin:$2y$05$abc\n":           true,
		"password: \"hunter2\\n\"":                    true,
		"password:\n  value: hunter2\n":               true,
		"passwords:\n  admin: hunter2\n":              true,
		"password: 2024-05-17\n":                      true,
		"password: \"123456\"\n":                      true,
		"{{ broken\nPASSWORD=abc\n":                   true,
		"{{ broken\npassword = abc\n":                 true,
		"imagePullSecrets:\n  - name: registry\n":     false,
		"secrets:\n  - name: db\n    key: password\n": false,
		"{{ broken\nreplicas = 3\n":                   true, // not read: withheld whole
		"replicas = 3\nmode = fast":                   false,
	} {
		if got := textHolds(text); got != want {
			t.Errorf("textHolds(%q) = %v, want %v", text, got, want)
		}
	}
}

// More places a credential is written in what a GitOps source installs
// with.
func TestMorePlacesAreRead(t *testing.T) {
	set := map[string]any{"apiVersion": "argoproj.io/v1alpha1", "kind": "ApplicationSet", "metadata": map[string]any{"name": "s", "namespace": "argocd"},
		"spec": map[string]any{
			"generators": []any{map[string]any{"list": map[string]any{"elementsYaml": "- cluster: east\n  token: s3cr3t-1\n"}}},
			"template": map[string]any{"spec": map[string]any{"source": map[string]any{
				"helm":      map[string]any{"valueFiles": []any{"https://kept.example.com/values.yaml", "https://u:s3cr3t-2@example.com/values.yaml"}},
				"kustomize": map[string]any{"patches": []any{map[string]any{"patch": "- op: add\n  path: /data/password\n  value: s3cr3t-3\n"}}},
			}}},
		}}
	paths, out := withheldOf("argoproj.io", "applicationsets", set)
	if len(paths) != 3 || strings.Contains(out, "s3cr3t") || !strings.Contains(out, "kept.example.com") {
		t.Errorf("an application set: %v\n%s", paths, out)
	}
	wf := map[string]any{"apiVersion": "argoproj.io/v1alpha1", "kind": "WorkflowTemplate", "metadata": map[string]any{"name": "w", "namespace": "x"},
		"spec": map[string]any{"templates": []any{map[string]any{"name": "t", "inputs": map[string]any{"parameters": []any{
			map[string]any{"name": "db_password", "default": "s3cr3t-1"}, map[string]any{"name": "slack-token", "value": "s3cr3t-2"},
			map[string]any{"name": "auth.usePasswordFiles", "value": "true"}, map[string]any{"name": "region", "default": "kept-region"},
		}}}}}}
	paths, out = withheldOf("argoproj.io", "workflowtemplates", wf)
	if len(paths) != 2 || strings.Contains(out, "s3cr3t") || !strings.Contains(out, "kept-region") || !strings.Contains(out, `"value":"true"`) {
		t.Errorf("a workflow's parameters: %v\n%s", paths, out)
	}
	ks := map[string]any{"apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization", "metadata": map[string]any{"name": "k", "namespace": "flux-system"},
		"spec": map[string]any{"patches": []any{map[string]any{"patch": "apiVersion: v1\nkind: Secret\nstringData:\n  password: s3cr3t\n"}}}}
	if paths, out := withheldOf("kustomize.toolkit.fluxcd.io", "kustomizations", ks); len(paths) != 1 || strings.Contains(out, "s3cr3t") {
		t.Errorf("a Kustomization's patch: %v\n%s", paths, out)
	}
}

// The rule before, kept here as it was: every variable with a literal
// value and every ConfigMap key, judged by credential().
func ruleBefore(obj map[string]any) map[string]string {
	out := map[string]string{}
	if strOf(obj["kind"]) == "ConfigMap" {
		d, _ := obj["data"].(map[string]any)
		for k, v := range d {
			if s, ok := v.(string); ok && credential(k, s) {
				out["data["+k+"]"] = s
			}
		}
	}
	var walk func(v any, path string)
	walk = func(v any, path string) {
		switch x := v.(type) {
		case map[string]any:
			for k, c := range x {
				p := join(path, pathPart(k))
				if k == "env" {
					for i, e := range list(c) {
						m, ok := e.(map[string]any)
						s, isStr := m["value"].(string)
						if ok && isStr && credential(strOf(m["name"]), s) {
							out[p+"["+item(list(c), i)+"]"] = s
						}
					}
					continue
				}
				walk(c, p)
			}
		case []any:
			for i, c := range x {
				walk(c, path+"["+item(x, i)+"]")
			}
		}
	}
	walk(obj, "")
	return out
}

// The comparison that gated the earlier attempts, as a test: the same
// objects through the rule before and through this one. Whatever the rule
// before withheld is withheld, at the same path. Every kind that carries
// variables, every name and every value the reviews used.
func TestComparedWithTheRuleBefore(t *testing.T) {
	names := []string{"DB_PASSWORD", "PGPASSWORD", "API_TOKEN", "CLIENT_SECRET", "API_KEY", "SIGNING_KEY", "SENTRY_DSN", "DATABASE_URL", "REDIS_URL", "DB_PWD",
		"CONNECTION_STRING", "STORAGE_SAS", "LOG_LEVEL", "PASSWORD_MIN_LENGTH", "TOKEN_TTL", "KEY_PREFIX", "SECRET_NAME", "PUBLIC_KEY", "CACHE_KEY", "AWS_REGION", "FEATURE_TOKEN_AUTH", "GOOGLE_APPLICATION_CREDENTIALS"}
	values := []string{"hunter2", "true", "123456", "none", "enabled", "3600", "/var/run/key.json", "$(OTHER)", "",
		"postgres://app:pw@db:5432/app", "postgres://app:p<w@db/app", "postgres://app:p>w@db/app", "postgres://app:p'w@db/app", `postgres://app:p"w@db/app`,
		"postgres://app:p/w@db:5432/app", "postgres://app:p?w@db/app", "postgres://app:p#w@db/app", "postgres://app:p@w@db/app", "postgres://app:p%40w@db/app",
		"postgres://app:p w@db/app", "postgres://app:12,ab@db/app", "postgres://app:123?456@db/app", "https://user:pw@host/path",
		"https://ghp_0123456789abcdefghijABCDEFGHIJ0123456789@github.com/org/repo", "https://git@host/org/repo", "https://org@dev.example.com/org/p/_git/r",
		"ssh://git@host/x", "sftp://deploy@host", "redis://:pw@host", "mongodb+srv://u:p@h/db?retryWrites=true", "amqp://u:p@h",
		"jdbc:postgresql://h/db?user=u&password=p", "jdbc:sqlserver://h;user=u;password=p", "https://example.com/x?token=abc", "https://example.com/x#access_token=abc",
		"http://grafana:3000/d/a?mail=ops@example.com", "http://localhost:8080/users/bob@example.com", "http://cdn:8080/img/logo@2x.png", "http://registry:4873/@my.org/pkg",
		"http://es-0:9200,http://elastic@es-1:9200", "https://example.com/reset?token=<your-token>", "https://vault.example.com/v1/kv?secret=app-config", "http://host:8080?x=a@b",
		"see https://user:pw@host/path here", "https://a.example.com https://user:pw@host/x", "https://user:pw@[::1]:8443/x", "https://user:pw@host/path\n", "HTTPS://user:pw@host/path",
		"Bearer abcdefghijklmnop1234", "Basic dXNlcjpwYXNz", "Token 0123456789abcdef0", "Basic production", "basic authentication", "token exchange", "Bearer", "token v1.2.3-production-build"}
	var env []any
	n := 0
	for _, name := range names {
		for _, v := range values {
			n++
			env = append(env, map[string]any{"name": name + "_" + string(rune('A'+n%26)) + strings.Repeat("X", n/26), "value": v}, map[string]any{"name": name, "value": v})
		}
	}
	e := func() any { return deepCopy(map[string]any{"e": env})["e"] }
	pod := func(lists ...string) map[string]any {
		spec := map[string]any{}
		for _, l := range lists {
			spec[l] = []any{map[string]any{"name": "c", "env": deepCopy(map[string]any{"e": env})["e"]}}
		}
		return spec
	}
	data := map[string]any{}
	for i, name := range names {
		for j, v := range values {
			data[name+"."+string(rune('a'+i%26))+string(rune('a'+j%26))+strings.Repeat("x", j/26)] = v
			data[name] = v
		}
	}
	md := func() map[string]any { return map[string]any{"name": "o", "namespace": "x"} }
	objects := map[string]map[string]any{
		"Deployment":  {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": md(), "spec": map[string]any{"template": map[string]any{"spec": pod("containers")}}},
		"StatefulSet": {"apiVersion": "apps/v1", "kind": "StatefulSet", "metadata": md(), "spec": map[string]any{"template": map[string]any{"spec": pod("containers", "initContainers")}}},
		"DaemonSet":   {"apiVersion": "apps/v1", "kind": "DaemonSet", "metadata": md(), "spec": map[string]any{"template": map[string]any{"spec": pod("containers")}}},
		"Job":         {"apiVersion": "batch/v1", "kind": "Job", "metadata": md(), "spec": map[string]any{"template": map[string]any{"spec": pod("containers")}}},
		"CronJob":     {"apiVersion": "batch/v1", "kind": "CronJob", "metadata": md(), "spec": map[string]any{"jobTemplate": map[string]any{"spec": map[string]any{"template": map[string]any{"spec": pod("containers")}}}}},
		"Pod":         {"apiVersion": "v1", "kind": "Pod", "metadata": md(), "spec": pod("containers", "initContainers", "ephemeralContainers")},
		"Workflow":    {"apiVersion": "argoproj.io/v1alpha1", "kind": "Workflow", "metadata": md(), "spec": map[string]any{"templates": []any{map[string]any{"name": "t", "container": map[string]any{"env": deepCopy(map[string]any{"e": env})["e"]}}}}},
		"Task":        {"apiVersion": "tekton.dev/v1", "kind": "Task", "metadata": md(), "spec": map[string]any{"steps": []any{map[string]any{"name": "s", "env": deepCopy(map[string]any{"e": env})["e"]}}}},
		// Variables in values, as charts have them: under a key with a dot in
		// it, under an item of a list that has a name, under a key that says
		// where a pod runs, and the same keys nested beside the dotted one.
		"HelmRelease": {"apiVersion": "helm.toolkit.fluxcd.io/v2", "kind": "HelmRelease", "metadata": md(), "spec": map[string]any{"values": map[string]any{
			"env":             e(),
			"sub":             map[string]any{"chart.x": map[string]any{"env": e()}, "chart": map[string]any{"y": map[string]any{"env": e()}}},
			"extraContainers": []any{map[string]any{"name": "sidecar", "env": e()}, map[string]any{"name": "other", "image": "x"}},
			"selector":        map[string]any{"env": e()},
			"password":        map[string]any{"env": e()},
		}}},
		"Application": {"apiVersion": "argoproj.io/v1alpha1", "kind": "Application", "metadata": md(), "spec": map[string]any{"source": map[string]any{"helm": map[string]any{"valuesObject": map[string]any{
			"env": e(), "my.sub": map[string]any{"env": e()}, "sidecars": []any{map[string]any{"name": "proxy", "env": e()}}}}}}},
		// A key with a dot in it outside values, as a custom resource may have.
		"Custom":    {"apiVersion": "example.com/v1", "kind": "Thing", "metadata": md(), "spec": map[string]any{"files": map[string]any{"app.yaml": map[string]any{"env": e()}}}},
		"ConfigMap": {"apiVersion": "v1", "kind": "ConfigMap", "metadata": md(), "data": data},
	}
	total := 0
	for kind, o := range objects {
		before := ruleBefore(o)
		total += len(before)
		original := deepCopy(o)
		var oldPaths []string
		for path := range before {
			oldPaths = append(oldPaths, path)
		}
		sort.Strings(oldPaths)
		// The rule kept in the product to find those slots is the rule as
		// it was.
		var productPaths []string
		for _, sl := range slotsBefore(deepCopy(original)) {
			if credential(sl.name, sl.value) {
				productPaths = append(productPaths, sl.path)
			}
		}
		sort.Strings(productPaths)
		if !reflect.DeepEqual(productPaths, oldPaths) {
			t.Errorf("%s: slotsBefore finds %d slots, the rule before %d", kind, len(productPaths), len(oldPaths))
		}

		// 1. Whatever the rule before withheld is withheld: found by the
		// path it had, its value gone.
		withholdEnv(o)
		found, err := findSlots(o, oldPaths)
		if err != nil {
			t.Errorf("%s: what the rule before withheld is not found in this snapshot: %v", kind, err)
			continue
		}
		kept := 0
		for path, sl := range found {
			if sl.value != "" {
				kept++
				if kept <= 5 {
					t.Errorf("%s: the rule before withheld %s (%q), and it is kept", kind, path, before[path])
				}
			}
		}
		same := func(what string, body map[string]any, err error) {
			t.Helper()
			if err != nil {
				t.Errorf("%s: %s: %v", kind, what, err)
			} else if !reflect.DeepEqual(body["spec"], original["spec"]) || !reflect.DeepEqual(body["data"], original["data"]) {
				t.Errorf("%s: %s: filled back, it is not the object it was", kind, what)
			}
		}
		// 2. This snapshot is filled back, from a file (a line for each
		// path it names) and from the cluster it came from.
		live := map[string]string{}
		for _, sl := range slots(deepCopy(original)) {
			live[sl.path] = sl.value
		}
		body := deepCopy(o)
		same("this snapshot, from a file", body, setSlots(body, withheldEnv(body), live))
		body = deepCopy(o)
		same("this snapshot, from its cluster", body, fillFrom(deepCopy(original), body, withheldEnv(body)))

		// 3. A snapshot the rule before took, with the paths it wrote, is
		// filled back the same two ways.
		old := func() map[string]any {
			snap := deepCopy(original)
			for _, sl := range slotsBefore(snap) {
				if credential(sl.name, sl.value) {
					sl.set("")
				}
			}
			return snap
		}
		body = old()
		same("a snapshot of the rule before, from a file", body, setSlots(body, oldPaths, before))
		body = old()
		same("a snapshot of the rule before, from its cluster", body, fillFrom(deepCopy(original), body, oldPaths))
	}
	if total < 4000 {
		t.Errorf("the rule before withheld only %d values of the corpus: it is not the corpus it was", total)
	}
}

// item names a list's element as the rule before did, kept here as it
// was: by its "name" where no other element shares it, else by its index.
func item(l []any, i int) string {
	m, _ := l[i].(map[string]any)
	n := strOf(m["name"])
	if n == "" || allDigits(n) {
		return strconv.Itoa(i)
	}
	for j, o := range l {
		if om, _ := o.(map[string]any); j != i && strOf(om["name"]) == n {
			return strconv.Itoa(i)
		}
	}
	return pathPart(n)
}
