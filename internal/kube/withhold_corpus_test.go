package kube

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// The corpus the reviews of this rule were made with, as a test: each
// credential below is planted in every place it may be written, the
// object is captured, and what is still in the snapshot is counted.
//
// No rule catches every credential under every name, and the count is
// not zero. It is written here so that it can only go down: a change
// that lets one more through fails, and a change that catches more has to
// lower the number. What survives is listed in docs/guide.md, under what
// is not caught.
const (
	corpusPlanted   = 1396
	corpusSurvivors = 190
)

// plant is one credential put in one place.
type plant struct {
	what   string         // the kind of credential, and the place
	object map[string]any // the object as the cluster has it
	marker string         // text that is in the snapshot only if the credential is
}

// corpus builds every plant. mark gives a credential its marker; each
// builder is given a value with the marker in it.
func corpus() []plant {
	var out []plant
	n := 0
	md := func() map[string]any { return map[string]any{"name": "o", "namespace": "x"} }
	pod := func(env []any) map[string]any {
		return map[string]any{"containers": []any{map[string]any{"name": "c", "image": "app", "env": env}}}
	}
	variable := func(name string, v any) []any {
		return []any{map[string]any{"name": "LOG_LEVEL", "value": "info"}, map[string]any{"name": name, "value": v}}
	}
	release := func(values map[string]any) map[string]any {
		return map[string]any{"apiVersion": "helm.toolkit.fluxcd.io/v2", "kind": "HelmRelease", "metadata": md(), "spec": map[string]any{"values": values}}
	}
	application := func(helm map[string]any) map[string]any {
		return map[string]any{"apiVersion": "argoproj.io/v1alpha1", "kind": "Application", "metadata": md(), "spec": map[string]any{"source": map[string]any{"repoURL": "https://example.com/o/r", "helm": helm}}}
	}
	// Where a name and its value may be written.
	places := map[string]func(name string, v any) map[string]any{
		"a Deployment's variable": func(name string, v any) map[string]any {
			return map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": md(), "spec": map[string]any{"template": map[string]any{"spec": pod(variable(name, v))}}}
		},
		"a CronJob's variable": func(name string, v any) map[string]any {
			return map[string]any{"apiVersion": "batch/v1", "kind": "CronJob", "metadata": md(), "spec": map[string]any{"jobTemplate": map[string]any{"spec": map[string]any{"template": map[string]any{"spec": pod(variable(name, v))}}}}}
		},
		"a workflow step's variable": func(name string, v any) map[string]any {
			return map[string]any{"apiVersion": "argoproj.io/v1alpha1", "kind": "Workflow", "metadata": md(), "spec": map[string]any{"templates": []any{map[string]any{"name": "t", "container": map[string]any{"env": variable(name, v)}}}}}
		},
		"a ConfigMap's key": func(name string, v any) map[string]any {
			return map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": md(), "data": map[string]any{"mode": "fast", name: fmt.Sprint(v)}}
		},
		"a chart's value": func(name string, v any) map[string]any { return release(map[string]any{"replicas": 2, name: v}) },
		"a chart's value, nested": func(name string, v any) map[string]any {
			return release(map[string]any{"app": map[string]any{"config": map[string]any{name: v}}})
		},
		"a variable in values": func(name string, v any) map[string]any { return release(map[string]any{"env": variable(name, v)}) },
		"a pair in values":     func(name string, v any) map[string]any { return release(map[string]any{"extraEnv": variable(name, v)}) },
		"an application's value": func(name string, v any) map[string]any {
			return application(map[string]any{"valuesObject": map[string]any{name: v}})
		},
		"an application's parameter": func(name string, v any) map[string]any {
			return application(map[string]any{"parameters": variable("app."+name, fmt.Sprint(v))})
		},
		"an application's values as text": func(name string, v any) map[string]any {
			b, _ := json.Marshal(v)
			return application(map[string]any{"values": "replicas: 2\n" + name + ": " + string(b) + "\n"})
		},
		"a substitution": func(name string, v any) map[string]any {
			return map[string]any{"apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization", "metadata": md(), "spec": map[string]any{"postBuild": map[string]any{"substitute": map[string]any{name: fmt.Sprint(v)}}}}
		},
	}
	placeNames := make([]string, 0, len(places))
	for p := range places {
		placeNames = append(placeNames, p)
	}
	sort.Strings(placeNames)
	everywhere := func(what, name string, value func(marker string) any) {
		for _, p := range placeNames {
			n++
			m := fmt.Sprintf("zq%dzq", n)
			out = append(out, plant{what: what + " in " + p, object: places[p](name, value(m)), marker: m})
		}
	}
	one := func(what string, object func(marker string) map[string]any) {
		n++
		m := fmt.Sprintf("zq%dzq", n)
		out = append(out, plant{what: what, object: object(m), marker: m})
	}

	// 1. A plain value under a name. The names the reviews used: what the
	// rule for variables read, what charts call a credential, and what
	// says too little to be read (the last line).
	for _, name := range []string{
		"DB_PASSWORD", "PGPASSWORD", "API_TOKEN", "CLIENT_SECRET", "API_KEY", "SIGNING_KEY", "SENTRY_DSN", "DB_PWD", "CONNECTION_STRING", "STORAGE_SAS",
		"password", "adminPassword", "pass", "dbPass", "adminPass", "appKey", "fernetKey", "hmacKey", "jwtKey", "secretKeyBase", "clientSecretValue", "sshKey",
		"cloudflareAPIToken", "openAIAPIKey", "SASToken", "APITOKEN", "DB_PASS", "SMTP_PASS", "APP_KEY", "apiToken", "authToken", "bearerToken", "sasToken",
		"secretAccessKey", "api-key", "client-secret", "license", "htpasswd", "connectionString", "jwtSigningSalt",
		"bindPW", "pw", "masterkey", "passcode", "pin", "seed", "cookie", "session", "webhook", "login",
	} {
		everywhere("a value named "+name, name, func(m string) any { return "plain-" + m })
	}

	// 2. A value whose shape says a credential, under a name that says
	// nothing. The last lines are shapes that are not read.
	for what, shape := range map[string]string{
		"a URL with a password":                "postgres://app:%s@db:5432/app",
		"a URL with a password and a slash":    "postgres://app:p/%s@db:5432/app",
		"a URL with a password and a question": "postgres://app:p?%s@db.example.com/app",
		"a URL with a password and an at":      "postgres://app:p@%s@db/app",
		"a URL with a password and a space":    "postgres://app:p %s@db/app",
		"an https URL with a password":         "https://user:%s@host.example.com/path",
		"a token as a URL's name":              "https://ghp_0123456789abcdef%s@github.com/org/repo",
		"a redis URL":                          "redis://:%s@cache",
		"a mongodb URL":                        "mongodb+srv://u:%s@h.example.com/db?retryWrites=true",
		"an amqp URL":                          "amqp://u:%s@h",
		"a JDBC URL with a password asked":     "jdbc:postgresql://h/db?user=u&password=%s",
		"a JDBC URL with semicolons":           "jdbc:sqlserver://h;user=u;password=%s",
		"a token asked in a URL":               "https://example.com/x?token=%s",
		"an access token asked in a URL":       "https://example.com/x?access_token=%s",
		"an API key asked in a URL":            "https://example.com/x?api_key=%s",
		"a signature asked in a URL":           "https://example.com/x?sig=%s",
		"a client secret asked in a URL":       "https://example.com/x?client_secret=%s",
		"a token after a hash":                 "https://example.com/x#access_token=%s",
		"a Slack webhook":                      "https://hooks.slack.com/services/T0/B0/%s",
		"a Discord webhook":                    "https://discord.com/api/webhooks/1/%s",
		"a Teams webhook":                      "https://example.webhook.office.com/webhookb2/%s",
		"a URL in a sentence":                  "see https://user:%s@host.example.com/path here",
		"two URLs":                             "https://a.example.com https://user:%s@host.example.com/x",
		"a URL to an IPv6 host":                "https://user:%s@[::1]:8443/x",
		"a URL with a scheme in capitals":      "HTTPS://user:%s@host.example.com/path",
		"a Bearer value":                       "Bearer abcdefghijklmnop%s",
		"a Token value":                        "Token 0123456789abcdef%s",
		"an ADO.NET connection string":         "Server=db;Database=app;User Id=sa;Password=%s;",
		"a libpq connection string":            "host=db user=app password=%s dbname=app",
		"a storage account's connection":       "DefaultEndpointsProtocol=https;AccountName=a;AccountKey=%s",
		"a private key":                        "-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----",
		"a GitHub token":                       "ghp_x7Kp2mQ9vR4tLw8ZbN3cJ6hYfD1sGa5eU0%s",
		"a long key of mixed characters":       "wJa1rXUtnFEMI7K7MDENGbPxRfiCY9qL2%s",
		// Not read.
		"a URL whose password has a slash, to a bare host": "postgres://app:PW/%s@db/app",
		"an auth_token asked in a URL":                     "https://example.com/x?auth_token=%s",
		"an api_token asked in a URL":                      "https://example.com/x?api_token=%s",
		"an apiToken asked in a URL":                       "https://example.com/x?apiToken=%s",
		"an access_key asked in a URL":                     "https://example.com/x?access_key=%s",
		"a subscription-key asked in a URL":                "https://example.com/x?subscription-key=%s",
		"a key asked in a URL":                             "https://example.com/x?key=%s",
		"a code asked in a URL":                            "https://example.com/x?code=%s",
		"a Redis connection with a password":               "cache:6380,password=%s,ssl=True",
		"a Go DSN":                                         "app:%s@tcp(db:3306)/app",
		"an Oracle thin URL":                               "jdbc:oracle:thin:app/%s@db:1521/x",
		"a JWT":                                            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.%sSflKxwRJSMeKKF2QT4fwpMeJf36",
		"a GitLab token":                                   "glpat-%s-abcdefghij",
		"a Slack token":                                    "xoxb-1234-5678-%s",
		"a key of lower-case letters and digits":           "0123456789abcdef0123456789abcdef%s",
		"a short key":                                      "Ab3%s",
		"a whole Authorization header":                     "Authorization: Bearer abcdefghijklmnop%s",
		"a password with a space":                          "correct horse %s",
	} {
		everywhere(what, "setting", func(m string) any { return fmt.Sprintf(shape, m) })
	}

	// 3. A credential that is no text: a number, under a name that says
	// one. A number of six digits or fewer is taken as a setting.
	for _, number := range []int64{987654321, 123456789012, 123456, 1234} {
		everywhere(fmt.Sprintf("a number of %d digits named password", len(fmt.Sprint(number))), "password", func(string) any { return number })
	}

	// 4. A credential written under a name, deeper: as charts nest them.
	for what, shape := range map[string]func(v string) map[string]any{
		"password: {value}": func(v string) map[string]any { return map[string]any{"password": map[string]any{"value": v}} },
		"tokens: [x]":       func(v string) map[string]any { return map[string]any{"tokens": []any{v}} },
		"secrets: {db: x}":  func(v string) map[string]any { return map[string]any{"secrets": map[string]any{"db": v}} },
		"auth: {password}": func(v string) map[string]any {
			return map[string]any{"auth": map[string]any{"username": "u", "password": v}}
		},
		"secret: {stringData: {k: x}}": func(v string) map[string]any {
			return map[string]any{"secret": map[string]any{"create": true, "stringData": map[string]any{"k": v}}}
		},
		"extraEnvVars pair": func(v string) map[string]any {
			return map[string]any{"extraEnvVars": []any{map[string]any{"name": "DB_PASSWORD", "value": v}}}
		},
		"a component's own password": func(v string) map[string]any {
			return map[string]any{"external-secrets": map[string]any{"image": map[string]any{"tag": "v1"}, "adminPassword": v}}
		},
		"license: {content}": func(v string) map[string]any { return map[string]any{"license": map[string]any{"content": v}} },
		"dex: {bindPW}": func(v string) map[string]any {
			return map[string]any{"dex": map[string]any{"config": map[string]any{"bindPW": v}}}
		},
		"apiKey: {value}": func(v string) map[string]any { return map[string]any{"apiKey": map[string]any{"value": v}} },
		"jwt: {secret: {key}}": func(v string) map[string]any {
			return map[string]any{"jwt": map[string]any{"secret": map[string]any{"key": v}}}
		},
		"credentials: {name, key}": func(v string) map[string]any {
			return map[string]any{"credentials": map[string]any{"name": "admin", "key": v}}
		},
		"a JSON config on one line": func(v string) map[string]any { return map[string]any{"config": `{"db":{"password":"` + v + `"}}`} },
		"a properties file": func(v string) map[string]any {
			return map[string]any{"config": "server.port=80\nspring.datasource.password=" + v + "\n"}
		},
		"an env file": func(v string) map[string]any { return map[string]any{"envFile": "PORT=80\nDB_PASSWORD=" + v} },
		"a script": func(v string) map[string]any {
			return map[string]any{"init": "#!/bin/sh\nexport API_TOKEN=" + v + "\nexec app\n"}
		},
		"a redis.conf": func(v string) map[string]any {
			return map[string]any{"configuration": "maxmemory 1gb\nrequirepass " + v + "\n"}
		},
		"an argument": func(v string) map[string]any {
			return map[string]any{"extraArgs": []any{"--log=info", "--password=" + v}}
		},
		"a document in a value, unreadable": func(v string) map[string]any {
			return map[string]any{"overrides": "{{- if .x }}\nlogin: " + v + "\n{{- end }}\n"}
		},
	} {
		for where, wrap := range map[string]func(values map[string]any) map[string]any{
			"a release's values": release,
			"an application's valuesObject": func(values map[string]any) map[string]any {
				return application(map[string]any{"valuesObject": values})
			},
			"an application's values as text": func(values map[string]any) map[string]any {
				b, _ := json.Marshal(values) // JSON is YAML
				return application(map[string]any{"values": string(b)})
			},
		} {
			one(what+" in "+where, func(m string) map[string]any { return wrap(shape("plain-" + m)) })
		}
	}

	// 5. A document written as text, as people and templates lay it out:
	// once as it is, and once in a template that cannot be read.
	for what, text := range map[string]string{
		"a value on its line":         "db:\n  password: %s\n",
		"a value on the next line":    "password:\n  %s\n",
		"a value under value":         "password:\n  value: %s\n",
		"a list under tokens":         "tokens:\n  - %s\n",
		"a value in braces":           "auth: {password: %s}\n",
		"a name and a value":          "env:\n  - name: DB_PASSWORD\n    value: %s\n",
		"a block":                     "secret: |\n  %s\n",
		"a quoted key":                "\"db password\": %s\n",
		"apiKey with the value next":  "apiKey:\n  %s\n",
		"apiKey as a block":           "apiKey: |-\n  %s\n",
		"a licence as a block":        "license: |\n  %s\n",
		"a key in brackets":           "accessKey: [%s]\n",
		"a name, a comment, a value":  "env:\n  - name: DB_PASSWORD\n    # the password\n    value: %s\n",
		"a value before its name":     "env:\n  - value: %s\n    name: DB_PASSWORD\n",
		"a variable in flow style":    "env: [{name: DB_PASSWORD, value: %s}]\n",
		"a key set twice":             "password: %s\npassword: true\n",
		"a second document":           "replicas: 2\n---\ndb:\n  password: %s\n",
		"under a name that says none": "notes:\n  remember: %s\n",
	} {
		for how, around := range map[string]string{"as it is": "%s", "in a template": "{{- if .Values.x }}\n%s{{- end }}\n"} {
			one(what+" "+how+", an application's values", func(m string) map[string]any {
				return application(map[string]any{"values": fmt.Sprintf(around, fmt.Sprintf(text, "plain-"+m))})
			})
			one(what+" "+how+", a patch", func(m string) map[string]any {
				return map[string]any{"apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization", "metadata": md(),
					"spec": map[string]any{"patches": []any{map[string]any{"patch": fmt.Sprintf(around, fmt.Sprintf(text, "plain-"+m))}}}}
			})
		}
	}

	// 6. Places that are not read at all.
	one("a ConfigMap that is a file", func(m string) map[string]any {
		return map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": md(), "data": map[string]any{"application.properties": "server.port=80\nspring.datasource.password=plain-" + m + "\n"}}
	})
	one("a container's argument", func(m string) map[string]any {
		return map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": md(), "spec": map[string]any{"containers": []any{map[string]any{"name": "c", "args": []any{"--password=plain-" + m}}}}}
	})
	one("a notification provider's address", func(m string) map[string]any {
		return map[string]any{"apiVersion": "notification.toolkit.fluxcd.io/v1beta3", "kind": "Provider", "metadata": md(), "spec": map[string]any{"type": "slack", "address": "https://hooks.slack.com/services/T0/B0/" + m}}
	})
	one("a field called dsn that is no URL", func(m string) map[string]any {
		return map[string]any{"apiVersion": "example.com/v1", "kind": "Database", "metadata": md(), "spec": map[string]any{"dsn": "app/" + m + "@db"}}
	})
	one("a custom resource's own field", func(m string) map[string]any {
		return map[string]any{"apiVersion": "example.com/v1", "kind": "Database", "metadata": md(), "spec": map[string]any{"adminPassword": "plain-" + m}}
	})
	one("a custom resource's address field", func(m string) map[string]any {
		return map[string]any{"apiVersion": "example.com/v1", "kind": "Database", "metadata": md(), "spec": map[string]any{"dsn": "postgres://app:" + m + "@db.example.com/app"}}
	})
	one("an annotation", func(m string) map[string]any {
		o := map[string]any{"apiVersion": "v1", "kind": "Service", "metadata": md(), "spec": map[string]any{}}
		o["metadata"].(map[string]any)["annotations"] = map[string]any{"example.com/api-token": "plain-" + m}
		return o
	})
	return out
}

func TestCorpusSurvivors(t *testing.T) {
	plants := corpus()
	var survivors []string
	for _, p := range plants {
		number := strings.HasPrefix(p.what, "a number of")
		if original, _ := json.Marshal(p.object); !number && !strings.Contains(string(original), p.marker) {
			t.Fatalf("%s: the credential is not in the object as built", p.what)
		}
		withholdEnv(p.object)
		b, _ := json.Marshal(p.object)
		// Text is found by its marker. A number has none: it is the one
		// credential of its object, and is there unless something was
		// withheld.
		found := strings.Contains(string(b), p.marker)
		if number {
			found = !strings.Contains(string(b), WithheldEnvAnnotation)
		}
		if found {
			survivors = append(survivors, p.what)
		}
	}
	sort.Strings(survivors)
	if len(plants) != corpusPlanted {
		t.Errorf("%d credentials are planted, and corpusPlanted says %d: a corpus that shrinks hides what survives", len(plants), corpusPlanted)
	}
	switch {
	case len(survivors) > corpusSurvivors:
		t.Errorf("%d of %d planted credentials are in the snapshot, and it was %d: this change lets more through\n%s", len(survivors), len(plants), corpusSurvivors, strings.Join(survivors, "\n"))
	case len(survivors) < corpusSurvivors:
		t.Errorf("%d of %d planted credentials are in the snapshot, fewer than the %d before: lower corpusSurvivors to %d, and take what is now caught out of the guide's list", len(survivors), len(plants), corpusSurvivors, len(survivors))
	}
	if testing.Verbose() {
		// What survives, by kind: the list the guide gives.
		kinds := map[string]int{}
		for _, s := range survivors {
			kind, _, _ := strings.Cut(s, " in ")
			kinds[kind]++
		}
		var lines []string
		for k, c := range kinds {
			lines = append(lines, fmt.Sprintf("%4d  %s", c, k))
		}
		sort.Strings(lines)
		t.Logf("survivors by kind:\n%s", strings.Join(lines, "\n"))
	}
}
