package access

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJWTClaimsReadsWithoutTrusting(t *testing.T) {
	body := base64.RawURLEncoding.EncodeToString([]byte(`{"oid":"o-1","idtyp":"app","appid":"a-1"}`))
	c := jwtClaims("h." + body + ".sig")
	if claim(c, "oid") != "o-1" || claim(c, "upn", "appid") != "a-1" {
		t.Errorf("claims %v", c)
	}
	if jwtClaims("not-a-jwt") != nil || jwtClaims("a.!!!.c") != nil {
		t.Error("garbage read as claims")
	}
}

func TestScopeName(t *testing.T) {
	sub := "00000000-0000-4000-8000-000000000001"
	for scope, want := range map[string]string{
		"/":                                      "the tenant root",
		"/subscriptions/" + sub:                  "the subscription",
		"/subscriptions/" + strings.ToUpper(sub): "the subscription",
		"/providers/Microsoft.Management/managementGroups/corp":        "management group corp",
		"/subscriptions/" + sub + "/resourceGroups/rg-1/providers/x/y": "resource group rg-1",
	} {
		if got := scopeName(scope, sub); got != want {
			t.Errorf("%s: %q, want %q", scope, got, want)
		}
	}
}

// What the kubeconfig cannot say is reported as not checked, never left
// out: an empty warnings list must not read as "the cluster agrees".
func TestKubernetesSaysWhatItCannotSee(t *testing.T) {
	kc := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(kc, []byte(`apiVersion: v1
kind: Config
current-context: prod
contexts:
- name: prod
  context: {cluster: c, user: robot}
clusters:
- name: c
  cluster: {server: "https://127.0.0.1:1"}
users:
- name: robot
  user: {token: abc}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := Kubernetes(kc, "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Who != "robot" || r.Kind != "bearer token" || len(r.Warnings) == 0 {
		t.Errorf("%+v", r)
	}
	if len(r.Unchecked) == 0 || !strings.Contains(r.Unchecked[0], "read-only guard") {
		t.Errorf("must say the cluster's view was not checked: %v", r.Unchecked)
	}
	if strings.Contains(strings.Join(r.Facts, " "), "abc") {
		t.Error("printed the token")
	}
	if _, err := Kubernetes(kc, "nope"); err == nil {
		t.Error("an unknown context was accepted")
	}
}
