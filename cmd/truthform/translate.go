package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/usetruthform/core/internal/gcp"
	"github.com/usetruthform/core/internal/snapshot"
	"github.com/usetruthform/core/internal/translate"
)

// reportFile is the translation's report, written beside the snapshots it
// made; its presence is what lets translate rewrite the directory.
const reportFile = "translation.yaml"

// translateProof says how far a translation has been proven, wherever the
// command describes itself.
const translateProof = "Beta: no translated snapshot has been restored into a real AWS account or GCP project yet. " +
	"Run restore --dry-run on what translate writes before any restore."

// translateCmd rewrites an Azure snapshot for another cloud. It is offline:
// it reads one snapshot and a map and writes snapshots, so it runs in the
// capture-only build too. Exit 0: every object was carried over, with any
// losses named. Exit 3: something was refused, not looked at, left unread
// or lost in a way that widens, and the report says what. So does a
// Kubernetes manifest that names an Azure thing with no translation, when
// --kube or --gitops has them read.
func translateCmd(args []string) int {
	fs := flag.NewFlagSet("translate", flag.ContinueOnError)
	from := fs.String("from", "", "Azure snapshot directory to translate")
	mapFile := fs.String("map", "", "YAML map: the target (to, region), a destination per service class, and names")
	outDir := fs.String("out", "", "directory to write a snapshot per target platform into (aws/, gcp/, kubernetes/), and "+reportFile)
	schemas := fs.String("schemas", "", "aws: the CloudFormation registry's schema bundle (.zip) or a directory of schemas, instead of downloading the public bundle")
	discovery := fs.String("discovery", "", "gcp: a directory of Discovery documents (pubsub_v1.json, compute_v1.json, storage_v1.json, dns_v1.json, sqladmin_v1.json), instead of downloading them from Google")
	kubeDir := fs.String("kube", "", "a Kubernetes snapshot of the source cluster: report what in it names an Azure thing, and which of its workloads no GitOps source applies")
	gitops := fs.String("gitops", "", "a local checkout of the repository Flux reads: report, by file and line, what in it names an Azure thing. Nothing in it is changed")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage of translate:")
		fs.PrintDefaults()
		fmt.Fprintln(fs.Output(), translateProof)
	}
	if err := parseFlags(fs, args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return fail(err)
	}
	if *from == "" || *mapFile == "" || *outDir == "" || fs.NArg() > 0 {
		return fail(fmt.Errorf("translate: --from, --map and --out are required, and no positional arguments are accepted"))
	}
	src, err := snapshot.Read(*from)
	if err != nil {
		return fail(err)
	}
	m, err := translate.ReadMap(*mapFile)
	if err != nil {
		return fail(err)
	}
	tg, err := translateTargets(m, *schemas, *discovery)
	if err != nil {
		return fail(err)
	}
	res, err := translate.Translate(src, m, tg)
	if err != nil {
		return fail(err)
	}
	var variables []byte
	if *kubeDir != "" || *gitops != "" {
		in := translate.GitOpsInput{Dir: *gitops}
		if *kubeDir != "" {
			k, err := snapshot.Read(*kubeDir)
			if err != nil {
				return fail(fmt.Errorf("--kube: %w", err))
			}
			in.Kube = &k
		}
		if variables, err = translate.GitOps(src, m, &res, in); err != nil {
			return fail(err)
		}
	}
	if err := writeTranslation(*outDir, res, variables); err != nil {
		return fail(err)
	}
	code := 0
	if res.Report.Failed() {
		code = 3
	}
	printTranslation(res.Report, *outDir)
	if jsonOut {
		emit(map[string]any{"schema": jsonSchema, "command": command, "from": *from, "out": *outDir,
			"report": res.Report, "complete": !res.Report.Failed(), "exit": code})
	}
	return code
}

// translateTargets loads the definitions of what the map's destinations
// write: the AWS registry (as aws-coverage reads it) or GCP's Discovery
// documents. They are public; no account is read.
func translateTargets(m translate.Map, schemas, discovery string) (translate.Targets, error) {
	var tg translate.Targets
	cache, err := os.UserCacheDir()
	if err != nil && (schemas == "" || discovery == "") {
		return tg, err
	}
	if m.NeedsAWS() {
		a := awsFlags{region: m.Region, schemas: schemas}
		if tg.AWS, err = a.registry(); err != nil {
			return tg, err
		}
	}
	if m.NeedsGCP() {
		if discovery != "" {
			tg.GCP = gcp.LoadDocs(discovery)
		} else {
			tg.GCP = gcp.FetchDocs(filepath.Join(cache, "truthform", "gcp"), 24*time.Hour)
		}
	}
	return tg, nil
}

// writeTranslation writes into an empty directory, or one an earlier
// translation wrote. A platform the earlier one wrote and this one does
// not is removed, so a stale snapshot cannot be restored as this one's.
func writeTranslation(dir string, res translate.Result, variables []byte) error {
	entries, err := os.ReadDir(dir)
	switch {
	case os.IsNotExist(err):
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	case err != nil:
		return err
	case len(entries) > 0:
		if _, err := os.Stat(filepath.Join(dir, reportFile)); err != nil {
			return fmt.Errorf("%s is not empty and holds no %s: translate writes only into an empty directory or its own", dir, reportFile)
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			if _, ok := res.Snapshots[e.Name()]; ok {
				continue
			}
			if _, err := os.Stat(filepath.Join(dir, e.Name(), "snapshot.yaml")); err == nil {
				if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
					return err
				}
			}
		}
	}
	for p, s := range res.Snapshots {
		if err := s.Write(filepath.Join(dir, p)); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
	}
	// The variables file goes with the GitOps report: one an earlier run
	// wrote and this one does not is removed, like a stale snapshot.
	vf := filepath.Join(dir, translate.GitOpsVariablesFile)
	if variables != nil {
		if err := os.WriteFile(vf, variables, 0o644); err != nil {
			return err
		}
	} else if err := os.Remove(vf); err != nil && !os.IsNotExist(err) {
		return err
	}
	b, err := yaml.Marshal(res.Report)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, reportFile), b, 0o644)
}

func printTranslation(r translate.Report, dir string) {
	c := r.Counts()
	fmt.Printf("Translated for %s (%s): %d mapped, %d mapped with losses, %d refused, %d not looked at.\n",
		r.To, strings.Join(r.Destinations, ", "), c[translate.Mapped], c[translate.WithLosses], c[translate.Refused], c[translate.NotLooked])
	section := func(title string, lines []string) {
		if len(lines) == 0 {
			return
		}
		fmt.Printf("\n%s:\n", title)
		for _, l := range lines {
			fmt.Println("  " + l)
		}
	}
	var refused, notLooked, widens, unread []string
	for _, e := range r.Entries {
		switch e.State {
		case translate.Refused:
			refused = append(refused, e.Source+": "+e.Reason)
		case translate.NotLooked:
			notLooked = append(notLooked, e.Source)
		}
		for _, l := range e.Losses {
			switch {
			case l.Widens:
				widens = append(widens, e.Source+" "+l.Field+": "+l.Why)
			case l.Unread:
				unread = append(unread, e.Source+" "+l.Field)
			}
		}
	}
	section("Refused (looked at; no equivalent, or carrying it over would change what it does)", refused)
	section("Less protected on the target than on the source", widens)
	section("Settings no rule reads yet", unread)
	section("Not looked at (no descriptor for the type yet)", notLooked)
	section("Before a restore", r.Requirements)
	if r.GitOps != nil {
		printGitOps(*r.GitOps, dir, section)
	}
	fmt.Printf("\nEvery loss, object by object: %s\n", filepath.Join(dir, reportFile))
}

// printGitOps prints what the Kubernetes workloads name that the
// translation renamed: the count line, then each reference under its
// state, what no GitOps source applies, and what could not be seen.
func printGitOps(g translate.GitOpsReport, dir string, section func(string, []string)) {
	c := g.Counts()
	fmt.Printf("\nKubernetes workloads (read: %s): %d reference(s) to change, %d to check, %d with no translation; %d source(s) not available to check.\n",
		strings.Join(g.Read, "; "), c[translate.GitOpsChange], c[translate.GitOpsCheck], c[translate.GitOpsNone], g.NotAvailable())
	lines := map[translate.GitOpsState][]string{}
	for _, r := range g.References {
		if r.NotApplied {
			continue
		}
		where := "the Kubernetes snapshot"
		if r.File != "" {
			where = fmt.Sprintf("%s:%d", r.File, r.Line)
		}
		l := where
		if r.Object != "" {
			l += " " + r.Object
		}
		l += ", applied by " + r.AppliedBy + "\n    "
		if r.Field != "" {
			l += r.Field + " "
		}
		l += "names " + r.Names
		switch {
		case r.State == translate.GitOpsNone:
			l += "; it has no translation: " + r.Why
		case r.Why != "":
			l += "; on the target it is " + r.Target + "\n    (" + r.Why + ")"
		default:
			l += "; on the target it is " + r.Target
		}
		if r.Variable != "" {
			l += "\n    variable: ${" + r.Variable + "}"
		}
		lines[r.State] = append(lines[r.State], l)
	}
	section("Names an Azure thing with no translation (applied as it is, it would point at Azure)", lines[translate.GitOpsNone])
	section("To change in Git, or in the object where nothing in Git applies it", lines[translate.GitOpsChange])
	section("To check (the target has its own form, which a person chooses)", lines[translate.GitOpsCheck])
	var loose []string
	for _, n := range g.NotInGit {
		ns := n.Namespace
		if ns == "" {
			ns = "(no namespace)"
		}
		loose = append(loose, ns+": "+strings.Join(n.Workloads, ", "))
	}
	section("Workloads no GitOps source applies, by namespace (a restore recreates them from the snapshot as they are)", loose)
	var src []string
	for _, s := range g.Sources {
		l := s.Source + ": " + s.Checked
		if s.LeftOut > 0 {
			l += fmt.Sprintf(" (the capture left %d object(s) to it", s.LeftOut)
			if s.Checked == "files" {
				l += fmt.Sprintf(", %d of them in its files", s.Found)
			}
			l += ")"
		}
		if s.Why != "" {
			l += ": " + s.Why
		}
		src = append(src, l)
	}
	section("GitOps sources, and how much of each was read", src)
	section("Not seen", g.NotSeen)
	fmt.Printf("\nThe same names as a ConfigMap for Flux's postBuild.substituteFrom (optional): %s\n", filepath.Join(dir, g.Variables))
}
