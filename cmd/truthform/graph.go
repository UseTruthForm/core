package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/usetruthform/core/internal/azarm"
	"github.com/usetruthform/core/internal/snapshot"
)

// graphCmd writes a snapshot as a graph of resources and relationships.
// It reads only the snapshot: no login, no request.
func graphCmd(args []string) int {
	fs := flag.NewFlagSet("graph", flag.ContinueOnError)
	from := fs.String("from", "", "snapshot directory")
	types := fs.String("types", "security", "what each node carries: security (built in), none, or a projection file")
	sub := fs.String("subscription", "", "replace the subscription placeholder with this ID (default: keep it, so the graph names no subscription)")
	tenant := fs.String("tenant", "", "replace the tenant placeholder with this ID")
	out := fs.String("out", "", "file to write (default: stdout)")
	if err := parseFlags(fs, args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return fail(err)
	}
	if *from == "" || fs.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "graph: --from is required and no positional arguments are accepted")
		return 1
	}
	for _, v := range []struct{ flag, val string }{{"--subscription", *sub}, {"--tenant", *tenant}} {
		if v.val != "" && !azarm.IsGUID(v.val) {
			return fail(fmt.Errorf("graph: %s %q is not a GUID", v.flag, v.val))
		}
	}
	s, err := snapshot.Read(*from)
	if err != nil {
		return fail(err)
	}
	if s.Platform != "azure" {
		return fail(fmt.Errorf("graph: %s is a %s snapshot; graph is for azure snapshots", *from, s.Platform))
	}
	p, name, err := azarm.LoadProjection(*types, os.ReadFile)
	if err != nil {
		return fail(err)
	}
	g := azarm.BuildGraph(s, p, name, *sub, *tenant)
	g.Generator = generator()
	if g.SnapshotDigest, err = snapshot.Digest(*from); err != nil {
		return fail(err)
	}
	b, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return fail(err)
	}
	b = append(b, '\n')
	if *out == "" {
		_, err = os.Stdout.Write(b)
	} else {
		err = os.WriteFile(*out, b, 0o644)
	}
	if err != nil {
		return fail(err)
	}
	if *out != "" {
		fmt.Fprintf(os.Stderr, "wrote %s: %s, %s\n", *out, count(len(g.Nodes), "node"), count(len(g.Edges), "edge"))
	}
	return 0
}
