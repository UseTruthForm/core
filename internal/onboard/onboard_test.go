package onboard

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

func full() map[string]Request {
	return map[string]Request{
		"aws": {Platform: "aws", Account: "111122223333", Principal: "arn:aws:iam::111122223333:user/truthform-runner",
			SourceProfile: "runner", AdminProfile: "admin", Region: "us-east-2"},
		"aws-cross": {Platform: "aws", Account: "111122223333", Principal: "arn:aws:iam::444455556666:role/consultant",
			ExternalID: "acme.2026-10", SourceProfile: "consult"},
		"azure": {Platform: "azure", Subscription: "00000000-0000-4000-8000-000000000001",
			PrincipalID: "0b0e3c3e-1111-4222-8333-944445555666", PrincipalType: "ServicePrincipal"},
		"gcp":        {Platform: "gcp", Project: "acme-prod-1", Member: "serviceAccount:truthform@acme-prod-1.iam.gserviceaccount.com"},
		"kubernetes": {Platform: "kubernetes", Context: "arn:aws:eks:us-east-1:111122223333:cluster/prod", Subject: "ServiceAccount:truthform/reader"},
		"github":     {Platform: "github", Account: "acme-corp"},
		"cloudflare": {Platform: "cloudflare", Account: "0123456789abcdef0123456789abcdef"},
	}
}

var shellSafe = regexp.MustCompile(`^[A-Za-z0-9_/:=+-]+$`)

// args splits a command line the way both shells would: single quotes
// group, nothing else does.
func args(t *testing.T, line string) []string {
	var out []string
	for line != "" {
		line = strings.TrimLeft(line, " ")
		if line == "" {
			break
		}
		if line[0] == '\'' {
			end := strings.IndexByte(line[1:], '\'')
			if end < 0 {
				t.Fatalf("unterminated quote in %q", line)
			}
			out = append(out, line[1:end+1])
			line = line[end+2:]
			continue
		}
		tok, rest, _ := strings.Cut(line, " ")
		// Its own copy of what is safe unquoted, not safeArg: checking
		// safeArg against itself let a widened safeArg pass (review of
		// #23).
		if !shellSafe.MatchString(tok) {
			t.Errorf("unquoted %q is not safe in both shells (in %q)", tok, line)
		}
		out = append(out, tok)
		line = rest
	}
	return out
}

// The drill grant was handed over as "--profile <admin-profile>" and
// PowerShell refused it: "The '<' operator is reserved for future use"
// (2026-10-23). Every command a plan prints must run as pasted.
func TestCommandsHaveNoPlaceholdersAndSurviveBothShells(t *testing.T) {
	for name, r := range full() {
		for _, access := range []string{"capture", "restore"} {
			r.Access = access
			// And with a directory that needs quoting.
			if access == "restore" {
				r.Dir = "my grants"
			}
			p, err := Build(r)
			if err != nil {
				t.Fatalf("%s %s: %v", name, access, err)
			}
			steps := append(append(append(append([]Step{}, p.Before...), p.Grant...), p.Verify...), p.Undo...)
			if len(p.Grant) == 0 || len(p.Undo) == 0 || len(p.Verify) == 0 {
				t.Errorf("%s %s: a plan needs a grant, a way to verify it and a way to undo it", name, access)
			}
			for _, s := range steps {
				if strings.ContainsAny(s.Command, "<>|;&$`\"\n") {
					t.Errorf("%s %s: %q holds a character one of the shells reads as syntax", name, access, s.Command)
				}
				for _, word := range []string{"YOUR", "EXAMPLE", "REPLACE", "xxx"} {
					if strings.Contains(strings.ToUpper(s.Command), strings.ToUpper(word)) {
						t.Errorf("%s %s: %q looks like it holds a placeholder", name, access, s.Command)
					}
				}
				if s.Command != "" {
					args(t, s.Command)
				}
			}
			if p.Status == "" || len(p.Grants) == 0 {
				t.Errorf("%s %s: a plan says what it grants and what has been verified", name, access)
			}
		}
	}
}

func TestMissingValuesAreNamedNotPlaceholdered(t *testing.T) {
	for _, plat := range []string{"aws", "azure", "gcp", "kubernetes", "github", "cloudflare"} {
		_, err := Build(Request{Platform: plat})
		var m MissingError
		if !errors.As(err, &m) || len(m) == 0 {
			t.Fatalf("%s: want the missing values listed, got %v", plat, err)
		}
		for _, x := range m {
			if x.Flag == "" || x.What == "" {
				t.Errorf("%s: %+v says neither which flag nor what it is", plat, x)
			}
		}
	}
	_, err := Build(Request{Platform: "aws"})
	if !strings.Contains(err.Error(), "--account") || !strings.Contains(err.Error(), "--principal") {
		t.Errorf("every missing value at once, not one per run: %v", err)
	}
}

// A value is put in a command only if the platform would accept it, which
// is also what keeps a hostile one from becoming shell syntax.
func TestRefusesValuesThatCouldBecomeSyntax(t *testing.T) {
	bad := []Request{
		{Platform: "aws", Account: "1111222233; rm", Principal: "arn:aws:iam::111122223333:user/x"},
		{Platform: "aws", Account: "111122223333", Principal: "arn:aws:iam::111122223333:user/x $(id)"},
		{Platform: "aws", Account: "111122223333", Principal: "arn:aws:iam::111122223333:user/x", ExternalID: "a'b"},
		{Platform: "aws", Account: "111122223333", Principal: "arn:aws:iam::111122223333:user/x", AdminProfile: "<admin-profile>"},
		{Platform: "aws", Account: "111122223333", Principal: "arn:aws:iam::111122223333:user/x", Region: "us-east-1 --debug"},
		{Platform: "azure", Subscription: "not-a-guid", PrincipalID: "0b0e3c3e-1111-4222-8333-944445555666", PrincipalType: "User"},
		{Platform: "azure", Subscription: "00000000-0000-4000-8000-000000000001", PrincipalID: "0b0e3c3e-1111-4222-8333-944445555666", PrincipalType: "Owner"},
		{Platform: "gcp", Project: "acme-prod-1", Member: "user:a@b.com,user:evil@x.com"},
		{Platform: "gcp", Project: "acme-prod-1", Member: "allUsers"},
		{Platform: "kubernetes", Context: "prod", Subject: "ServiceAccount:noslash"},
		{Platform: "kubernetes", Context: "prod", Subject: "User:a\nkind: ClusterRole"},
		{Platform: "github", Account: "acme/../x"},
		{Platform: "cloudflare", Account: "ABC"},
		{Platform: "aws", Account: "111122223333", Principal: "arn:aws:iam::111122223333:user/x", Dir: "it's"},
	}
	for _, r := range bad {
		if _, err := Build(r); err == nil {
			t.Errorf("accepted %+v", r)
		}
	}
}

func TestAWSTrustNamesTheRoleNotTheSession(t *testing.T) {
	p, err := Build(Request{Platform: "aws", Account: "111122223333", Principal: "arn:aws:sts::111122223333:assumed-role/Admin/alex"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Grant[0].Command, "TrustedPrincipalArn=arn:aws:iam::111122223333:role/Admin ") {
		t.Errorf("a session ARN cannot be trusted; want the role: %s", p.Grant[0].Command)
	}
	if !strings.Contains(strings.Join(p.Warnings, " "), "path") {
		t.Errorf("a session ARN loses the role's path; the plan must say so: %v", p.Warnings)
	}
}

func TestAWSWarnsOnWideOrUnguardedTrust(t *testing.T) {
	p, _ := Build(Request{Platform: "aws", Account: "111122223333", Principal: "arn:aws:iam::444455556666:role/consultant"})
	if !strings.Contains(strings.Join(p.Warnings, " "), "external ID") {
		t.Errorf("another account's role without an external ID must be warned about: %v", p.Warnings)
	}
	p, _ = Build(Request{Platform: "aws", Account: "111122223333", Principal: "arn:aws:iam::111122223333:root"})
	if !strings.Contains(strings.Join(p.Warnings, " "), "whole account") {
		t.Errorf("trusting a whole account must be warned about: %v", p.Warnings)
	}
	p, _ = Build(full()["aws-cross"])
	if !strings.Contains(p.Grant[0].Command, "'ExternalId=acme.2026-10'") {
		t.Errorf("an external ID with a dot must be quoted (PowerShell splits -x.y): %s", p.Grant[0].Command)
	}
}

func TestKubernetesManifest(t *testing.T) {
	p, err := Build(full()["kubernetes"])
	if err != nil {
		t.Fatal(err)
	}
	docs := strings.Split(string(p.Files["truthform-kubernetes.yaml"]), "\n---\n")
	if len(docs) != 2 {
		t.Fatalf("want a ClusterRole and a ClusterRoleBinding, got %d documents", len(docs))
	}
	var role, binding map[string]any
	if err := yaml.Unmarshal([]byte(docs[0]), &role); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal([]byte(docs[1]), &binding); err != nil {
		t.Fatal(err)
	}
	// list only: get on "*" covered pods/exec and nodes/proxy (review
	// of #23).
	verbs := role["rules"].([]any)[0].(map[string]any)["verbs"].([]any)
	if len(verbs) != 1 || verbs[0] != "list" || len(role["rules"].([]any)) != 1 {
		t.Errorf("capture is list only, got %v", role["rules"])
	}
	sub := binding["subjects"].([]any)[0].(map[string]any)
	if sub["kind"] != "ServiceAccount" || sub["name"] != "reader" || sub["namespace"] != "truthform" || sub["apiGroup"] != nil {
		t.Errorf("subject: %v", sub)
	}
}

func TestTerraformGetsItsOwnDirectoryAndVariables(t *testing.T) {
	p, err := Build(full()["gcp"])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Grant[1].Command, "-chdir=truthform-gcp apply") {
		t.Errorf("Terraform must run in a directory of its own: %s", p.Grant[1].Command)
	}
	vars := string(p.Files["terraform.tfvars"])
	if !strings.Contains(vars, `member  = "serviceAccount:truthform@acme-prod-1.iam.gserviceaccount.com"`) || !strings.Contains(vars, `access  = "capture"`) {
		t.Errorf("tfvars: %s", vars)
	}
}

func TestWriteRefusesToReplaceADifferentFile(t *testing.T) {
	dir := t.TempDir()
	p, _ := Build(full()["aws"])
	if _, err := p.Write(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Write(dir); err != nil {
		t.Errorf("rewriting the same content is fine: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "truthform-aws.yaml"), []byte("edited"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Write(dir); err == nil {
		t.Error("replaced a file with different content")
	}
}

func TestPlanTellsHowToWriteTheFilesUnlessWritten(t *testing.T) {
	r := full()["aws"]
	p, _ := Build(r)
	last := p.Before[len(p.Before)-1].Command
	if !strings.HasPrefix(last, "truthform permissions --platform aws --access capture --account 111122223333 ") || !strings.HasSuffix(last, "--write '.'") {
		t.Errorf("write step: %s", last)
	}
	r.Written = true
	p, _ = Build(r)
	for _, s := range p.Before {
		if strings.Contains(s.Command, "--write") {
			t.Errorf("files already written, yet: %s", s.Command)
		}
	}
}
