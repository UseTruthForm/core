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

// translateCmd rewrites an Azure snapshot for another cloud. It is offline:
// it reads one snapshot and a map and writes snapshots, so it runs in the
// capture-only build too. Exit 0: every object was carried over, with any
// losses named. Exit 3: something was refused, not looked at, left unread
// or lost in a way that widens, and the report says what.
func translateCmd(args []string) int {
	fs := flag.NewFlagSet("translate", flag.ContinueOnError)
	from := fs.String("from", "", "Azure snapshot directory to translate")
	mapFile := fs.String("map", "", "YAML map: the target (to, region), a destination per service class, and names")
	outDir := fs.String("out", "", "directory to write a snapshot per target platform into (aws/, gcp/, kubernetes/), and "+reportFile)
	schemas := fs.String("schemas", "", "aws: the CloudFormation registry's schema bundle (.zip) or a directory of schemas, instead of downloading the public bundle")
	discovery := fs.String("discovery", "", "gcp: a directory of Discovery documents (pubsub_v1.json), instead of downloading them from Google")
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
	if err := writeTranslation(*outDir, res); err != nil {
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
	switch m.Destinations.Messaging {
	case "sqs-sns":
		a := awsFlags{region: m.Region, schemas: schemas}
		if tg.AWS, err = a.registry(); err != nil {
			return tg, err
		}
	case "pubsub":
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
func writeTranslation(dir string, res translate.Result) error {
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
	fmt.Printf("\nEvery loss, object by object: %s\n", filepath.Join(dir, reportFile))
}
