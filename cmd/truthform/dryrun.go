package main

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// dryNotes collects what a dry run says once and not per resource: what it
// could not check, and the write-only values each type would be created
// without.
type dryNotes struct {
	mu        sync.Mutex
	unchecked []string
	writeOnly map[string]*writeOnlyNote
	// counts is how many resources of each type got each outcome.
	counts map[string]map[string]int
}

type writeOnlyNote struct {
	count  int
	fields string
}

// add records something the dry run could not check. Checks run several
// at a time.
func (n *dryNotes) add(s string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.unchecked = append(n.unchecked, s)
}

// without counts the resources of a type that would go without the same
// values: --values can supply them for some of a type and not others.
func (n *dryNotes) without(kind, fields string) {
	if n.writeOnly == nil {
		n.writeOnly = map[string]*writeOnlyNote{}
	}
	key := kind + "\x00" + fields
	w := n.writeOnly[key]
	if w == nil {
		w = &writeOnlyNote{fields: fields}
		n.writeOnly[key] = w
	}
	w.count++
}

// dryRunOut is the dry run in progress, for the JSON document to say it is
// one and what it could not check. Nil on a real restore.
var dryRunOut *dryNotes

// notChecked is what the dry run could not check, each once, in order.
func (n *dryNotes) notChecked() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := []string{}
	sort.Strings(n.unchecked)
	for i, s := range n.unchecked {
		if i == 0 || s != n.unchecked[i-1] {
			out = append(out, s)
		}
	}
	return out
}

// count records one result: its type, and what the dry run said of it,
// without the names and fields that follow.
func (n *dryNotes) count(key string, ok bool, detail string) {
	what := "would not apply"
	if ok {
		what = detail
		for _, known := range []string{"would create", "would update", "would add", "already present"} {
			if strings.HasPrefix(detail, known) {
				what = known
			}
		}
	}
	if n.counts == nil {
		n.counts = map[string]map[string]int{}
	}
	kind := kindOfKey(key)
	if n.counts[kind] == nil {
		n.counts[kind] = map[string]int{}
	}
	n.counts[kind][what]++
}

func (n *dryNotes) print() {
	if len(n.counts) > 0 {
		fmt.Println("by type:")
		kinds := make([]string, 0, len(n.counts))
		for k := range n.counts {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		for _, k := range kinds {
			var parts []string
			for _, what := range []string{"would create", "would update", "would add", "already present", "would not apply"} {
				if c := n.counts[k][what]; c > 0 {
					parts = append(parts, fmt.Sprintf("%d %s", c, what))
					delete(n.counts[k], what)
				}
			}
			for what, c := range n.counts[k] {
				parts = append(parts, fmt.Sprintf("%d %s", c, what))
			}
			fmt.Printf("   %s: %s\n", k, strings.Join(parts, ", "))
		}
	}
	if len(n.writeOnly) > 0 {
		fmt.Println("write-only values the snapshot does not hold (AWS never returns them); a restore creates these without them unless --values supplies them:")
		kinds := make([]string, 0, len(n.writeOnly))
		for k := range n.writeOnly {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		for _, k := range kinds {
			kind, _, _ := strings.Cut(k, "\x00")
			fmt.Printf("   %s (%d): %s\n", kind, n.writeOnly[k].count, n.writeOnly[k].fields)
		}
	}
	for _, s := range n.notChecked() {
		fmt.Println("NOT CHECKED:", s)
	}
}

// kindOfKey is the kind in a result's key (apiVersion|kind|namespace|name).
func kindOfKey(key string) string {
	if p := strings.Split(key, "|"); len(p) > 1 {
		return p[1]
	}
	return key
}
