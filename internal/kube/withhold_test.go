package kube

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
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
		"password.value": true, "credentials.id": true, "sentry.dsn": true, "slack-token": true, "secretKey": true,
		// What names a thing.
		"secretName": false, "ingress.tls.secretName": false, "existingSecret": false, "auth.existingSecret": false,
		"existingSecretKey": false, "aws.credentials.secretName": false, "tokenSecretRef": false, "passwordSecretName": false,
		"publicKey": false, "public_key": false, "keyName": false,
		// What says nothing.
		"replicas": false, "image.tag": false, "host": false, "auth.host": false, "logLevel": false,
	} {
		if got := saysCredential(name); got != want {
			t.Errorf("saysCredential(%q) = %v, want %v", name, got, want)
		}
	}
	for value, want := range map[string]bool{
		"": true, "true": true, "False": true, "no": true, "3600": true, "4096": true, "-1": true, "$(OTHER)": true,
		"1234567": false, "hunter2": false, "0.5.1-rc": false,
	} {
		if got := certainlyNot(value); got != want {
			t.Errorf("certainlyNot(%q) = %v, want %v", value, got, want)
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
		"{{ broken\nauth:\n  existingSecret: db\n  usePasswordFiles: true\n":      false,
		"{{ broken\nsecretName: registry-login\nmaxTokens: 4096\n":                false,
		"replicas: 2\nimage:\n  tag: v1\n":                                        false,
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
