package main

import (
	"encoding/json"
	"io"
	"os"
	"sort"

	"github.com/stackdna/core/internal/snapshot"
)

// --json makes stdout one JSON document, for a pipeline or an alert to
// read; the exit code is unchanged. Everything a person would read
// (progress, notes, the zone pairing) still goes out, to stderr: main
// points os.Stdout at stderr for the whole command, so no line printed
// anywhere can land in the JSON, and the document goes to the real stdout.
var (
	jsonOut bool
	jsonDst io.Writer = os.Stdout
	// command is the subcommand run, named in the document (diff and
	// compare share one report).
	command = "diff"
	// emitted is set once a document is written; lastErr is the error
	// fail reported, for the document a failed run ends with.
	emitted bool
	lastErr error
)

// jsonCommands produce a document of their own.
var jsonCommands = map[string]bool{"capture": true, "diff": true, "restore": true, "compare": true, "check": true, "permissions": true}

// emitError is the document of a run that produced none: what went wrong
// and the exit code, so a pipeline sees the failure, not empty output.
func emitError(code int) {
	msg := "failed; see stderr"
	if lastErr != nil {
		msg = lastErr.Error()
	}
	emit(map[string]any{"schema": jsonSchema, "command": command, "error": msg, "exit": code})
}

// jsonSchema names the document's shape; it changes only with a new name.
const jsonSchema = "stackdna.org/output/v1"

// takeJSONFlag removes --json from the arguments (every command accepts it)
// and reports whether it was there.
func takeJSONFlag(args []string) ([]string, bool) {
	out := args[:0:0]
	found := false
	for _, a := range args {
		if a == "--json" || a == "-json" {
			found = true
			continue
		}
		out = append(out, a)
	}
	return out, found
}

func emit(v any) {
	emitted = true
	enc := json.NewEncoder(jsonDst)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

type changeJSON struct {
	Key    string   `json:"key"`
	Kind   string   `json:"kind"` // missing, extra, changed, not working
	Fields []string `json:"fields,omitempty"`
}

func changesJSON(cs []snapshot.Change) []changeJSON {
	out := make([]changeJSON, 0, len(cs))
	for _, c := range cs {
		out = append(out, changeJSON{Key: c.Key, Kind: c.Kind, Fields: c.Fields})
	}
	return out
}

func emitDiff(changes []snapshot.Change, from, target string) {
	emit(map[string]any{"schema": jsonSchema, "command": command, "from": from, "target": target,
		"differences": len(changes), "changes": changesJSON(changes)})
}

type resultJSON struct {
	Key    string `json:"key"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

func emitRestore(results []snapshot.Result, target string) {
	out := make([]resultJSON, 0, len(results))
	applied := 0
	for _, r := range results {
		out = append(out, resultJSON{Key: r.Key, OK: r.OK, Detail: r.Detail})
		if r.OK {
			applied++
		}
	}
	emit(map[string]any{"schema": jsonSchema, "command": "restore", "target": target,
		"applied": applied, "total": len(results), "complete": applied == len(results), "results": out})
}

func emitCapture(dir string, s snapshot.Snapshot, target string) {
	if !jsonOut {
		return
	}
	read, notCaptured, failed := summarize(s)
	digest, _ := snapshot.Digest(dir)
	skipped := map[string]int{}
	for _, sk := range s.Skips {
		skipped[sk.Reason]++
	}
	g := gaps(s)
	sort.Strings(g)
	throttled := []string{} // the gaps a later capture can close as it is
	th := throttledGaps(s)
	for _, x := range g {
		if th[x] {
			throttled = append(throttled, x)
		}
	}
	emit(map[string]any{"schema": jsonSchema, "command": "capture", "target": target, "out": dir,
		"digest": digest, "objects": len(s.Objects), "typesRead": read, "typesNotCaptured": notCaptured,
		"failed": failed, "gaps": g, "throttled": throttled, "complete": len(g) == 0, "skipped": skipped})
}
