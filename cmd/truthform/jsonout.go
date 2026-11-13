package main

import (
	"encoding/json"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/azarm"
	"github.com/usetruthform/core/internal/kube"
	"github.com/usetruthform/core/internal/snapshot"
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
	// storeRefs is what a Kubernetes --rename did and did not do, for the
	// document; nil where none ran.
	storeRefs *kube.RenameReport
	// heldBack is what --leave-out took out of the snapshot, named in the
	// diff and restore documents so "no differences" says what it skipped.
	heldBack []string
)

// jsonCommands produce a document of their own.
var jsonCommands = map[string]bool{"capture": true, "diff": true, "restore": true, "compare": true, "check": true, "permissions": true, "plan": true}

// emitError is the document of a run that produced none: what went wrong
// and the exit code, so a pipeline sees the failure, not empty output.
func emitError(code int) {
	msg := "failed; see stderr"
	if lastErr != nil {
		msg = lastErr.Error()
	}
	doc := map[string]any{"schema": jsonSchema, "command": command, "error": msg, "exit": code}
	// A restore refused for what --rename would leave as the source's
	// says which, as one that went ahead does.
	if storeRefs != nil && command == "restore" {
		doc["complete"] = false
		doc["store_references"] = storeRefsJSON()
	}
	emit(doc)
}

// jsonSchema names the document's shape; it changes only with a new name.
const jsonSchema = "truthform.org/output/v1"

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
	doc := map[string]any{"schema": jsonSchema, "command": command, "from": from, "target": target,
		"differences": len(changes), "changes": changesJSON(changes), "left_out": leftOutJSON(), "access_elsewhere": elsewhereJSON()}
	if scopeDone != nil {
		doc["scope"] = scopeDone
	}
	if storeRefs != nil {
		doc["store_references"] = storeRefsJSON()
	}
	if sizeCheck != nil {
		doc["vm_sizes"] = sizeCheck
	}
	if namesHeld != nil {
		doc["names_held"] = namesHeld
	}
	emit(doc)
}

// sizeCheck is what the VM size check found, for the document of an Azure
// restore or diff; nil where none ran.
var sizeCheck *azarm.SizeCheck

// namesHeld is what the check for names held by deleted resources found, for
// the document of an Azure restore or diff; nil where none ran.
var namesHeld *heldJSON

type heldJSON struct {
	Held   []string `json:"held"`
	Unread []string `json:"unread"`
	// OnlyThisSubscription: the snapshot has names a deleted resource in
	// another subscription can hold, which the check cannot see.
	OnlyThisSubscription bool `json:"only_this_subscription"`
}

type resultJSON struct {
	Key    string `json:"key"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

func emitRestore(results []snapshot.Result, target string) {
	out := make([]resultJSON, 0, len(results))
	applied, pending := 0, 0
	notSent := []resultJSON{}
	for _, r := range results {
		out = append(out, resultJSON{Key: r.Key, OK: r.OK, Detail: r.Detail})
		if r.OK {
			applied++
		}
		// Applied, since Azure makes them, and listed: not sent is not sent. One
		// whose settings wait for Azure leaves the restore not complete.
		if strings.HasPrefix(r.Detail, azarm.NotSent) {
			notSent = append(notSent, resultJSON{Key: r.Key, OK: r.OK, Detail: strings.TrimPrefix(r.Detail, azarm.NotSent)})
			if azarm.Pending(r.Detail) {
				pending++
			}
		}
	}
	doc := map[string]any{"schema": jsonSchema, "command": "restore", "target": target,
		"applied": applied, "total": len(results), "complete": applied == len(results) && pending == 0, "results": out,
		"not_sent": notSent, "pending": pending, "left_out": leftOutJSON(), "access_elsewhere": elsewhereJSON()}
	if sizeCheck != nil {
		doc["vm_sizes"] = sizeCheck
	}
	if namesHeld != nil {
		doc["names_held"] = namesHeld
	}
	if storeRefs != nil {
		doc["store_references"] = storeRefsJSON()
	}
	if scopeDone != nil {
		doc["scope"] = scopeDone
	}
	emit(doc)
}

// storeRefsJSON is what --rename did to the snapshot's uses of a secret
// store: what points elsewhere, and what is still as the source's (kept
// because the file says so, unnamed because no start fits a store,
// unreached because a rename cannot change it), and the item names that
// no start fits, which are read from whichever store their object says. Lists, empty rather than null.
func storeRefsJSON() map[string]any {
	refs := func(l []kube.StoreRef) []map[string]string {
		out := []map[string]string{}
		for _, r := range l {
			out = append(out, map[string]string{"object": r.Object, "field": r.Field, "from": r.From, "to": r.To})
		}
		return out
	}
	return map[string]any{"kinds_read": kube.StoreKinds(), "changed": refs(storeRefs.Changed), "kept": refs(storeRefs.Kept), "unnamed": refs(storeRefs.Unnamed), "items_unchanged": refs(storeRefs.Within),
		"unreached": append([]string{}, storeRefs.Unreached...)}
}

// needElsewhere is what the snapshot restored or compared needs outside its
// target (azarm.AccessElsewhere), for the document.
var needElsewhere []string

// elsewhereJSON is needElsewhere as a list, empty rather than null.
func elsewhereJSON() []string {
	return append([]string{}, needElsewhere...)
}

// leftOutJSON is heldBack as a list, empty rather than null.
func leftOutJSON() []string {
	return append([]string{}, heldBack...)
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
