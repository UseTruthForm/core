package onboard

import (
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// Unquoted, YAML read User:0123 as 83 and Group:yes as true, and the
// binding named someone else (review of #23).
func TestKubernetesSubjectIsBoundExactlyAsGiven(t *testing.T) {
	for _, subj := range []string{"User:0123", "User:1e3", "User:0x1F", "Group:yes", "Group:null", "User:@ops", "User:a:", "User:-"} {
		p, err := Build(Request{Platform: "kubernetes", Context: "prod", Subject: subj})
		if err != nil {
			t.Fatalf("%s: %v", subj, err)
		}
		docs := strings.Split(string(p.Files["stackdna-kubernetes.yaml"]), "\n---\n")
		var binding map[string]any
		if err := yaml.Unmarshal([]byte(docs[len(docs)-1]), &binding); err != nil {
			t.Fatalf("%s: %v", subj, err)
		}
		got := binding["subjects"].([]any)[0].(map[string]any)["name"]
		if want := strings.SplitN(subj, ":", 2)[1]; got != want {
			t.Errorf("%s bound %#v", subj, got)
		}
	}
}

// Restore is cluster-admin, said plainly: a narrower role cannot restore
// RBAC, and the one before could mint any service account's token while
// its text said "get, list, create, patch and update" (review of #23).
func TestKubernetesRestoreIsClusterAdminAndSaysSo(t *testing.T) {
	p, err := Build(Request{Platform: "kubernetes", Access: "restore", Context: "prod", Subject: "User:ops"})
	if err != nil {
		t.Fatal(err)
	}
	var binding map[string]any
	if err := yaml.Unmarshal(p.Files["stackdna-kubernetes.yaml"], &binding); err != nil {
		t.Fatal(err)
	}
	if binding["kind"] != "ClusterRoleBinding" || binding["roleRef"].(map[string]any)["name"] != "cluster-admin" {
		t.Errorf("restore: %v", binding)
	}
	if !strings.Contains(p.Grants[0], "cluster-admin") || !strings.Contains(strings.Join(p.Warnings, " "), "cluster-admin") {
		t.Errorf("the plan must say it grants cluster-admin: %v %v", p.Grants, p.Warnings)
	}
}

// A directory is named in the commands; cmd.exe (az is a batch file on
// Windows) ran whoami from one named x&whoami, and PowerShell ends a
// single-quoted string at a typographic quote (review of #23).
func TestWriteDirectoryCannotBecomeSyntax(t *testing.T) {
	r := full()["azure"]
	for _, d := range []string{"x&whoami", "R&D", "grants(1)", "it\u2019s; Write-Output x; \u2019", "a%PATH%b", "a^b", "a!b", "a|b", "a$b", "a\nb"} {
		r.Dir = d
		if _, err := Build(r); err == nil {
			t.Errorf("accepted --write %q", d)
		}
	}
	// Forward slashes: a backslash separates paths only on Windows, and CI
	// runs on Linux, where the first version of this test failed.
	r.Dir = `C:/Users/me/stackdna grants`
	p, err := Build(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Grant[0].Command, `--template-file 'C:/Users/me/stackdna grants/stackdna-azure.json'`) {
		t.Errorf("a directory with a space must be quoted whole: %s", p.Grant[0].Command)
	}
}

// Windows PowerShell 5.1 has no Read-Host -MaskInput, takes it as prompt
// text and echoes the token (review of #23).
func TestTokenPromptMasksOnWindowsPowerShell(t *testing.T) {
	n := tokenNote("GITHUB_TOKEN")
	if strings.Contains(n, "MaskInput") || !strings.Contains(n, "-AsSecureString") {
		t.Errorf("%s", n)
	}
}
