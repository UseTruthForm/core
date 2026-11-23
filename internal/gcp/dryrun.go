package gcp

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// globalNames are the types whose names every project shares: "Bucket
// names reside in a single namespace that is shared by all Cloud Storage
// users" (docs.cloud.google.com/storage/docs/buckets). The value is the
// URL one is read at, by its name.
var globalNames = map[string]string{"storage.googleapis.com/Bucket": "https://storage.googleapis.com/storage/v1/b/"}

var saEmailRE = regexp.MustCompile(`[a-z0-9-]+@([a-z0-9-]+)\.iam\.gserviceaccount\.com`)

// dryChecks looks, by reading only, for what would refuse a write the dry
// run planned and that the project's inventory does not show: an API that
// is not enabled, a name taken in another project, and a service account
// of this project that a resource names and that neither the project nor
// the snapshot holds. One refused here takes with it what refers to it.
// What could not be checked is said through note, never passed over.
func dryChecks(ctx context.Context, api API, docs *Docs, s snapshot.Snapshot, results []snapshot.Result, project, number string, resolved *names, note func(string)) {
	at := map[string]int{}
	for i, r := range results {
		at[r.Key] = i
	}
	planned := func(o snapshot.Object) (int, bool) {
		i, ok := at[o.Key()]
		return i, ok && results[i].OK && strings.HasPrefix(results[i].Detail, "would ")
	}
	services := map[string]string{} // host -> "" when enabled, else its state
	enabled := func(host string) string {
		state, seen := services[host]
		if seen {
			return state
		}
		got, err := api.Call(ctx, "GET", "https://serviceusage.googleapis.com/v1/projects/"+project+"/services/"+host, nil)
		switch st, _ := got["state"].(string); {
		case err != nil:
			note("could not check that " + host + " is enabled in project " + project + ": " + err.Error())
		case st != "ENABLED":
			state = st
			if state == "" {
				state = "not enabled"
			}
		}
		services[host] = state
		return state
	}
	accounts := map[string]string{} // email -> "" when there
	refused := map[string]bool{}
	// A grant names its resource in an annotation, not by a reference.
	refusedNames := map[string]bool{}
	for _, o := range s.Objects {
		i, ok := planned(o)
		if !ok {
			continue
		}
		fail := func(why string) {
			results[i].OK, results[i].Detail = false, why
			refused[refToken(o.Kind(), o.Name())] = true
			refusedNames[detok(o.Name(), project, number)] = true
		}
		ann, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
		disc, _ := ann[annDiscovery].(string)
		apiName, ver, _ := strings.Cut(disc, "/")
		if doc, err := docs.Doc(docURL(apiName, ver), ""); err == nil && !outsideProject(o) {
			if u, err := url.Parse(doc.RootURL); err == nil && u.Host != "" {
				if state := enabled(u.Host); state != "" {
					fail(u.Host + " is " + strings.ToLower(state) + " in project " + project + ": the write would be refused (gcloud services enable " + u.Host + " --project " + project + ")")
					continue
				}
			}
		}
		if base := globalNames[o.Kind()]; base != "" && strings.HasPrefix(results[i].Detail, "would create") {
			name := detok(o.Name()[strings.LastIndex(o.Name(), "/")+1:], project, number)
			switch _, err := api.Call(ctx, "GET", base+name, nil); {
			case err == nil, err != nil && !errors.Is(err, ErrNotFound) && strings.Contains(err.Error(), "403"):
				fail("the name " + name + " is taken by one this project does not hold (these names are shared by every project): the create would be refused")
				continue
			case !errors.Is(err, ErrNotFound):
				note("could not check whether the name " + name + " is free in every project: " + err.Error())
			}
		}
		spec, _ := o.Body["spec"].(map[string]any)
		desired, _ := resolveSpec(spec, resolved, project, number)
		var missing []string
		for _, m := range saEmailRE.FindAllStringSubmatch(canon(desired), -1) {
			email := m[0]
			if m[1] != project || o.Kind() == "iam.googleapis.com/ServiceAccount" {
				continue
			}
			rel := "projects/" + project + "/serviceAccounts/" + email
			why, seen := accounts[email]
			if !seen {
				if !resolved.has(rel) {
					switch _, err := api.Call(ctx, "GET", "https://iam.googleapis.com/v1/"+rel, nil); {
					case errors.Is(err, ErrNotFound):
						why = "missing"
					case err != nil:
						note("could not check that service account " + email + " exists: " + err.Error())
					}
				}
				accounts[email] = why
			}
			if why != "" {
				missing = append(missing, email)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			fail("names service account " + strings.Join(dedupe(missing), ", ") + ", which is neither in the project nor in the snapshot: the write would be refused")
		}
	}
	// What refers to one that would not be created would not be either.
	// The snapshot's objects are in no order, so this runs until settled.
	for changed := len(refused) > 0; changed; {
		changed = false
		for _, o := range s.Objects {
			i, ok := planned(o)
			if !ok {
				continue
			}
			ann, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
			if parent, _ := ann[annParent].(string); o.Kind() == BindingKind && refusedNames[detok(parent, project, number)] {
				results[i].OK, results[i].Detail = false, "is a grant on "+detok(parent, project, number)+", which would not be created"
				continue
			}
			for _, tok := range refRE.FindAllString(canon(o.Body), -1) {
				if refused[tok] && tok != refToken(o.Kind(), o.Name()) {
					m := refRE.FindStringSubmatch(tok)
					results[i].OK, results[i].Detail = false, "depends on "+m[1]+" "+m[2]+", which would not be created"
					refused[refToken(o.Kind(), o.Name())] = true
					refusedNames[detok(o.Name(), project, number)] = true
					changed = true
					break
				}
			}
		}
	}
}

// has reports a resource the target holds or a dry run would create, by
// its name.
func (n *names) has(name string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, v := range n.m {
		if v == name {
			return true
		}
	}
	return false
}
