package onboard

import (
	"fmt"
	"strings"
)

func buildKubernetes(r Request) (Plan, error) {
	var miss MissingError
	if r.Context == "" {
		miss = append(miss, Missing{"context", "the kubeconfig context of the cluster, as the administrator", "kubectl config get-contexts"})
	}
	if r.Subject == "" {
		miss = append(miss, Missing{"subject", "who will run Truthform: User:NAME, Group:NAME or ServiceAccount:NAMESPACE/NAME", ""})
	}
	if len(miss) > 0 {
		return Plan{}, miss
	}
	if !contextRE.MatchString(r.Context) {
		return Plan{}, fmt.Errorf("--context: %q cannot be named safely in a command", r.Context)
	}
	kind, name, ok := strings.Cut(r.Subject, ":")
	ns := ""
	switch {
	case !ok:
	case kind == "ServiceAccount":
		ns, name, ok = strings.Cut(name, "/")
		ok = ok && dnsLabelRE.MatchString(ns) && dnsLabelRE.MatchString(name)
	case kind == "User", kind == "Group":
		ok = k8sNameRE.MatchString(name)
	default:
		ok = false
	}
	if !ok {
		return Plan{}, fmt.Errorf("--subject: %q is not User:NAME, Group:NAME or ServiceAccount:NAMESPACE/NAME", r.Subject)
	}
	role := "truthform-reader"
	if r.Access == "restore" {
		role = "truthform-restorer"
	}
	b, err := render("truthform-kubernetes.yaml.tmpl", map[string]any{
		"Name": role, "Restore": r.Access == "restore", "SubjectKind": kind, "SubjectName": name, "SubjectNamespace": ns})
	if err != nil {
		return Plan{}, err
	}
	f := file(r, "truthform-kubernetes.yaml")
	kc := func(a ...string) string { return cmd(append([]string{"kubectl", "--context", r.Context}, a...)...) }
	p := Plan{Files: map[string][]byte{"truthform-kubernetes.yaml": b}}
	if r.Access == "restore" {
		p.Grants = []string{"The built-in ClusterRole cluster-admin, bound to " + r.Subject + " as " + role}
		p.Warnings = []string{"This is cluster-admin: everything in the cluster. A restore recreates Roles and bindings, and Kubernetes lets an identity grant only what it holds, so nothing narrower can restore RBAC. Grant it for the restore and remove it afterwards."}
		p.Status = "Expected. Restores have run as cluster-admin, on kind clusters and test API servers."
	} else {
		p.Grants = []string{"ClusterRole " + role + ": list on every resource, cluster-wide, and nothing else (no get, so no subresources such as pods/exec or nodes/proxy), bound to " + r.Subject,
			"list returns Secret values. A snapshot never holds them, but the subject can read them."}
		p.Status = "Verified on every test run (TestKubernetesGrantLetsACaptureReadAndNothingElse): on a real API server with RBAC, a service account bound by exactly this file captured every type, Secrets included, was refused a write, get on pods/exec and nodes/proxy, and a service account token, and was refused reads again once the file was deleted. Not yet run on a managed cluster (EKS, AKS, GKE)."
	}
	p.Before = []Step{
		{Title: "Check nothing of this name is there already (expect NotFound for both)", Command: kc("get", "clusterrole,clusterrolebinding", role)},
	}
	p.Grant = []Step{{Title: "Apply the role and its binding", Command: kc("apply", "-f", f)}}
	as := ""
	switch kind {
	case "User":
		as = name
	case "ServiceAccount":
		as = "system:serviceaccount:" + ns + ":" + name
	}
	if as != "" {
		p.Verify = append(p.Verify, Step{Title: "Ask the cluster whether the subject may now list every resource (expect yes)", Command: kc("auth", "can-i", "list", "*", "--all-namespaces", "--as", as)})
		if r.Access != "restore" {
			p.Verify = append(p.Verify, Step{Title: "And that it cannot open a shell in a pod (expect no)", Command: kc("auth", "can-i", "get", "pods/exec", "--all-namespaces", "--as", as)})
		}
	}
	p.Verify = append(p.Verify, Step{Title: "With a context that authenticates as " + r.Subject + ", check what it can read: truthform check --context with that context's name"})
	p.Undo = []Step{
		{Title: "Delete the role and its binding", Command: kc("delete", "-f", f)},
		{Title: "Check they are gone (expect NotFound for both)", Command: kc("get", "clusterrole,clusterrolebinding", role)},
	}
	return p, nil
}
