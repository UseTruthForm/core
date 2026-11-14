package kube

import (
	"slices"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/usetruthform/core/internal/snapshot"
)

// Why a webhook's Service will not answer, or why that cannot be told.
const (
	// WhyNotBrought: the Service is not brought, and nothing that is
	// brought makes it.
	WhyNotBrought = "notBrought"
	// WhyHeld: it is brought, and every workload behind it that is
	// brought is held by the scope.
	WhyHeld = "held"
	// WhyLeftOut: it is brought, and every workload behind it was taken
	// out (the scope, --leave-out).
	WhyLeftOut = "leftOut"
	// WhyUnseen: it is brought, and every workload of the snapshot behind
	// it is held or taken out, but pods will run in its namespace that
	// the snapshot cannot show the labels of, and may be what answers.
	WhyUnseen = "unseen"
	// WhyUnknown: the snapshot does not say whether what is brought
	// makes it. A snapshot taken before captures listed what an object
	// owns by name leaves that open; one taken now settles it.
	WhyUnknown = "unknown"
)

// there is whether something is in the cluster once the restore has run.
type there int

const (
	thereNo there = iota
	thereUnknown
	thereYes
)

// WebhooksWithoutService is webhooksWithoutService for a snapshot
// restored with no scope: what is not in s is not brought. whole is the
// snapshot as it was read, before anything was left out of it.
func WebhooksWithoutService(whole, s snapshot.Snapshot) []ScopeWebhook {
	return webhooksWithoutService(whole, s, s, nil)
}

// after answers one question of anything: is it there once the restore
// has run? The same question is asked of a webhook's Service and then of
// whatever is said to make it, until it ends in something the restore
// brings (yes), something this restore takes out or holds, or nothing at
// all (no), or something the snapshot leaves open (unknown).
type after struct {
	whole, s, out snapshot.Snapshot
	held          map[string]bool // Kind namespace/name, held by the scope
	kind          map[string]string
	asked         map[string]bool
}

func newAfter(whole, s, out snapshot.Snapshot, held map[string]bool) *after {
	a := &after{whole: whole, s: s, out: out, held: held, kind: map[string]string{}, asked: map[string]bool{}}
	for _, c := range s.Coverage {
		a.kind[c.Resource] = c.Kind
	}
	return a
}

// kindOf is the kind of a resource as a capture writes it
// (group/version/resources): by what the capture recorded, and where it
// recorded nothing, by the name.
func (a *after) kindOf(resource string) string {
	if k := a.kind[resource]; k != "" {
		return strings.ToLower(k)
	}
	r := resource[strings.LastIndex(resource, "/")+1:]
	switch {
	case strings.HasSuffix(r, "ies"):
		return strings.TrimSuffix(r, "ies") + "y"
	case strings.HasSuffix(r, "sses"), strings.HasSuffix(r, "xes"), strings.HasSuffix(r, "ches"):
		return strings.TrimSuffix(r, "es")
	}
	return strings.TrimSuffix(r, "s")
}

// once guards a question against being asked of itself: what makes a
// thing is not the thing. Asked again within its own answer, it is no.
func (a *after) once(key string, ask func() there) there {
	if a.asked[key] {
		return thereNo
	}
	a.asked[key] = true
	defer delete(a.asked, key)
	return ask()
}

// object asks it of an object named by kind, as a reason names an owner:
// in its namespace, or with none.
func (a *after) object(kind, ns, name string) there {
	return a.once("object\x00"+kind+"\x00"+ns+"\x00"+name, func() there {
		is := func(o snapshot.Object) bool {
			return o.Kind() == kind && o.Name() == name && (o.Namespace() == ns || o.Namespace() == "")
		}
		for _, o := range a.out.Objects {
			if is(o) {
				// Held, it makes nothing: what it would have made is
				// not there.
				if a.held[o.Kind()+" "+o.Namespace()+"/"+o.Name()] {
					return thereNo
				}
				return thereYes
			}
		}
		// In the snapshot as read, and not brought: this restore took
		// it out.
		if slices.ContainsFunc(a.whole.Objects, is) {
			return thereNo
		}
		return a.skipped(name, func(sk snapshot.Skip) bool {
			return a.kindOf(sk.Resource) == strings.ToLower(kind) && (sk.Namespace == ns || sk.Namespace == "")
		})
	})
}

// skipped asks it of something the capture did not take, by the skips
// that cover it: it is there if what one of them leaves it to is.
func (a *after) skipped(name string, of func(snapshot.Skip) bool) there {
	best := thereNo
	for _, sk := range a.s.Skips {
		if !of(sk) {
			continue
		}
		open := false
		switch {
		case sk.Name == name:
		case sk.Name == "*" && len(sk.Names) > 0:
			if !slices.Contains(sk.Names, name) {
				continue
			}
		case sk.Name == "*" && systemNamespaces[sk.Namespace] && !a.ownerInSnapshot(sk):
			// In a system namespace, with an owner the capture left
			// to the platform too, it is the platform's whichever it
			// is, and a cluster has it. Where the snapshot holds the
			// owner (a capture that took system namespaces), it is
			// asked like any other.
			best = thereYes
			continue
		case sk.Name == "*":
			// What an object owns, listed with no names: a snapshot
			// from before they were written. Whether this is one of
			// them is not said.
			open = true
		default:
			continue
		}
		ans := a.provider(sk)
		if open && ans == thereYes {
			ans = thereUnknown
		}
		best = max(best, ans)
	}
	return best
}

// provider asks it of what a skip leaves its object to.
func (a *after) provider(sk snapshot.Skip) there {
	if m := ownedBy.FindStringSubmatch(sk.Reason); m != nil {
		return a.object(m[1], sk.Namespace, m[2])
	}
	kind, name, ok := SourceOf(sk.Reason)
	switch {
	case !ok:
		// The platform's, or the cluster's own: no object of the
		// snapshot makes it, and a cluster has it.
		return thereYes
	case kind == "Crossplane composite":
		return a.named(name)
	}
	return a.source(source{kind, name})
}

// ownerInSnapshot reports an owned skip whose owner is an object of the
// snapshot as it was read.
func (a *after) ownerInSnapshot(sk snapshot.Skip) bool {
	m := ownedBy.FindStringSubmatch(sk.Reason)
	return m != nil && slices.ContainsFunc(a.whole.Objects, func(o snapshot.Object) bool {
		return o.Kind() == m[1] && o.Name() == m[2] && (o.Namespace() == sk.Namespace || o.Namespace() == "")
	})
}

// source asks it of a GitOps source, which is an object like any other:
// brought and not held, or left by the capture to something that is
// asked in turn (the source that applies it, the ApplicationSet that
// generates it).
func (a *after) source(src source) there {
	return a.once("source\x00"+src.kind+"\x00"+src.name, func() there {
		obj := sourceObject[src.kind]
		// As a reason names it: namespace/name for Flux; for Argo CD
		// the name alone in Argo CD's own namespace, which the
		// snapshot does not say, and namespace_name outside it.
		ns, name, anyNS := "", src.name, false
		switch {
		case src.kind != "Argo CD application":
			ns, name, _ = strings.Cut(src.name, "/")
		case strings.Contains(src.name, "_"):
			ns, name, _ = strings.Cut(src.name, "_")
		default:
			anyNS = true
		}
		is := func(o snapshot.Object) bool {
			group, _, _ := strings.Cut(o.APIVersion(), "/")
			return group == obj.group && o.Kind() == obj.kind && o.Name() == name && (anyNS || o.Namespace() == ns)
		}
		// Of several of one name, one that runs is enough: which of
		// them a bare name means is not said.
		found := false
		for _, o := range a.out.Objects {
			if is(o) {
				found = true
				// Held (suspended, its automated sync off), it
				// applies nothing.
				if !a.held[o.Kind()+" "+o.Namespace()+"/"+o.Name()] {
					return thereYes
				}
			}
		}
		if found {
			return thereNo
		}
		return a.skipped(name, func(sk snapshot.Skip) bool {
			return strings.HasPrefix(sk.Resource, obj.group+"/") && strings.HasSuffix(sk.Resource, "/"+obj.resource) && (anyNS || sk.Namespace == ns)
		})
	})
}

// named asks it of a Crossplane composite, which a reason gives by name
// alone: an object of that name of an API that is not Kubernetes' own.
func (a *after) named(name string) there {
	return a.once("named\x00"+name, func() there {
		is := func(o snapshot.Object) bool {
			group, _, versioned := strings.Cut(o.APIVersion(), "/")
			return o.Name() == name && versioned && !ownGroups[group]
		}
		for _, o := range a.out.Objects {
			if is(o) {
				if a.held[o.Kind()+" "+o.Namespace()+"/"+o.Name()] {
					return thereNo
				}
				return thereYes
			}
		}
		if slices.ContainsFunc(a.whole.Objects, is) {
			return thereNo
		}
		// By its own name only: a skip that stands for whatever an
		// object owns, in some namespace, is not known to be it.
		return a.skipped(name, func(sk snapshot.Skip) bool {
			group, _, _ := strings.Cut(sk.Resource, "/")
			return sk.Name == name && !ownGroups[group] && group != "core"
		})
	})
}

var servicesResource = resourceID(schema.GroupVersionResource{Version: "v1", Resource: "services"})

func isService(o snapshot.Object) bool { return o.Kind() == "Service" && o.APIVersion() == "v1" }

// service asks it of a Service.
func (a *after) service(ns, name string) there {
	is := func(o snapshot.Object) bool { return isService(o) && o.Namespace() == ns && o.Name() == name }
	if slices.ContainsFunc(a.out.Objects, is) {
		return thereYes
	}
	if slices.ContainsFunc(a.whole.Objects, is) {
		return thereNo
	}
	return a.skipped(name, func(sk snapshot.Skip) bool { return sk.Resource == servicesResource && sk.Namespace == ns })
}

// selectorOf is the selector of a Service that will be there: its own
// where it is brought, and where its owner makes it, the one the capture
// wrote down beside its name.
func (a *after) selectorOf(ns, name string) map[string]string {
	for _, o := range a.out.Objects {
		if isService(o) && o.Namespace() == ns && o.Name() == name {
			return serviceSelector(o.Body)
		}
	}
	for _, sk := range a.s.Skips {
		if sk.Resource != servicesResource || sk.Namespace != ns || sk.Name != "*" || !slices.Contains(sk.Names, name) {
			continue
		}
		return sk.Selectors[name]
	}
	return nil
}

// behind says why nothing answers behind a Service that will be there,
// or "" where something does or it cannot be told. A Service answers
// through the pods its selector picks. Where the snapshot as read has
// the workloads that make them and none is brought and running, nothing
// answers; where it has none (an operator makes the pods), that cannot be
// told, and the Service is taken to answer.
func (a *after) behind(ns, name string) string {
	sel := a.selectorOf(ns, name)
	if len(sel) == 0 {
		return ""
	}
	id := func(o snapshot.Object) string {
		return o.APIVersion() + "|" + o.Kind() + "|" + o.Namespace() + "|" + o.Name()
	}
	brought := map[string]bool{}
	for _, o := range a.out.Objects {
		brought[id(o)] = true
	}
	behind, held := 0, 0
	for _, o := range a.whole.Objects {
		// Not a Job: it runs once and ends, and answers nothing for
		// long; a scope leaves every one out besides.
		if o.Namespace() != ns || isJob(o) {
			continue
		}
		spec, _ := o.Body["spec"].(map[string]any)
		tmpl, _ := spec["template"].(map[string]any)
		md, _ := tmpl["metadata"].(map[string]any)
		picks := tmpl != nil // a workload: it has a pod template
		if o.Kind() == "Pod" && o.APIVersion() == "v1" {
			// A pod nothing owns is in the snapshot itself, and
			// answers by its own labels.
			md, _ = o.Body["metadata"].(map[string]any)
			picks = true
		}
		labels, _ := md["labels"].(map[string]any)
		for k, v := range sel {
			picks = picks && labels[k] == v
		}
		switch {
		case !picks:
		case !brought[id(o)]:
			behind++
		case a.held[o.Kind()+" "+o.Namespace()+"/"+o.Name()]:
			behind++
			held++
		default:
			return "" // brought and running
		}
	}
	switch {
	case behind == 0:
		return ""
	case a.podsUnseen(ns):
		// Not known to answer, and not known not to: said, and
		// refuses nothing.
		return WhyUnseen
	case held > 0:
		return WhyHeld
	}
	return WhyLeftOut
}

// podMakers are the resources whose objects make pods, or are pods.
var podMakers = map[string]bool{"pods": true, "replicasets": true, "deployments": true, "statefulsets": true, "daemonsets": true, "replicationcontrollers": true}

// podsUnseen reports a namespace where pods will run that the snapshot
// cannot show the labels of: the capture left them, or what makes them,
// to something that will be there (an owner that is no workload of the
// snapshot, a GitOps source, the platform). A selector may pick those,
// so that every workload of the snapshot it picks is gone does not say
// that nothing answers.
func (a *after) podsUnseen(ns string) bool {
	for _, sk := range a.s.Skips {
		if sk.Namespace != ns || !podMakers[sk.Resource[strings.LastIndex(sk.Resource, "/")+1:]] {
			continue
		}
		if m := ownedBy.FindStringSubmatch(sk.Reason); m != nil {
			// The pods of a workload of the snapshot are that
			// workload's, and its labels are known: it has a pod
			// template, or as a CronJob has, the template of the
			// Jobs it makes. (A Job's pods end; they are never
			// what is counted as answering.)
			known := slices.ContainsFunc(a.whole.Objects, func(o snapshot.Object) bool {
				spec, _ := o.Body["spec"].(map[string]any)
				return o.Kind() == m[1] && o.Name() == m[2] && o.Namespace() == ns && (spec["template"] != nil || spec["jobTemplate"] != nil)
			})
			if known {
				continue
			}
		}
		if a.provider(sk) != thereNo {
			return true
		}
	}
	return false
}

// webhooksWithoutService finds the webhooks of out, what a restore
// brings of s, that call a Service which will not answer, or of which
// that cannot be told. whole is the snapshot as it was read, and held
// what the scope holds (Kind namespace/name). An APIService is read the
// same way. Such a webhook is asked about every write it matches, and
// the API server refuses those while nothing answers.
func webhooksWithoutService(whole, s, out snapshot.Snapshot, held map[string]bool) []ScopeWebhook {
	a := newAfter(whole, s, out, held)
	found := []ScopeWebhook{}
	add := func(o snapshot.Object, name string, config any, fails bool) {
		c, _ := config.(map[string]any)
		svc, _ := c["service"].(map[string]any)
		ns, n := strOf(svc["namespace"]), strOf(svc["name"])
		if n == "" {
			return
		}
		why := ""
		switch ans := a.service(ns, n); {
		case ans == thereNo:
			why = WhyNotBrought
		case ans == thereUnknown:
			why = WhyUnknown
		default:
			// It will be there, brought or made by what is: whether
			// anything answers behind it is the second question.
			why = a.behind(ns, n)
		}
		if why == "" {
			return
		}
		w := ScopeWebhook{Configuration: o.Kind() + " " + o.Name(), Webhook: name, Service: ns + "/" + n, Why: why, Fails: fails}
		// What cannot be told is said, and refuses nothing.
		w.Blocks = fails && why != WhyUnknown && why != WhyUnseen && admissionWebhook(w.Configuration)
		found = append(found, w)
	}
	for _, o := range out.Objects {
		group, _, _ := strings.Cut(o.APIVersion(), "/")
		switch {
		case group == "admissionregistration.k8s.io" && (o.Kind() == "ValidatingWebhookConfiguration" || o.Kind() == "MutatingWebhookConfiguration"):
			for _, w := range list(o.Body["webhooks"]) {
				m, _ := w.(map[string]any)
				policy := strOf(m["failurePolicy"])
				if policy == "" && strings.HasSuffix(o.APIVersion(), "/v1beta1") {
					policy = "Ignore" // that version's default
				}
				add(o, strOf(m["name"]), m["clientConfig"], policy != "Ignore")
			}
		case group == "apiextensions.k8s.io" && o.Kind() == "CustomResourceDefinition":
			spec, _ := o.Body["spec"].(map[string]any)
			conv, _ := spec["conversion"].(map[string]any)
			hook, _ := conv["webhook"].(map[string]any)
			add(o, "conversion", hook["clientConfig"], true)
		case group == "apiregistration.k8s.io" && o.Kind() == "APIService":
			// An API served by a Service: with none, the API is not
			// there, and what lists every API (a namespace's deletion,
			// a garbage collection) waits on it.
			spec, _ := o.Body["spec"].(map[string]any)
			add(o, "service", map[string]any{"service": spec["service"]}, true)
		}
	}
	sort.Slice(found, func(i, j int) bool {
		a, b := found[i], found[j]
		return a.Configuration+"\x00"+a.Webhook < b.Configuration+"\x00"+b.Webhook
	})
	return found
}
