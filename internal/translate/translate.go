// Package translate rewrites a snapshot of one cloud as snapshots for
// another, offline: no request is made, so it runs in the capture-only build
// too. What it writes are ordinary snapshots, which plan, restore and diff
// take as they are.
//
// It never guesses. Each source object ends in exactly one state, and the
// report names it with the reason:
//
//   - mapped: every configured field has a place on the target;
//   - mapped with losses: it is mapped, and each field with no equivalent is
//     named, with why;
//   - refused: it was looked at, and there is no equivalent, or carrying it
//     over would change what it does in a way nobody chose (a filter that
//     would deliver more, a key-protected endpoint left open);
//   - not looked at: no descriptor exists for its type yet.
//
// "Refused" and "not looked at" are listed apart and never shown the same way.
//
// The mapping is fixed. Each source service has a small fixed set of
// destinations, and the only per-customer input is the map file: which
// destination each service class goes to, the region, names that need one.
// Nothing the map leaves out is filled with a default.
package translate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/awscc"
	"github.com/usetruthform/core/internal/gcp"
	"github.com/usetruthform/core/internal/snapshot"
)

// State is where one source object ended.
type State string

// The four states; see the package comment.
const (
	Mapped     State = "mapped"
	WithLosses State = "mapped with losses"
	Refused    State = "refused"
	NotLooked  State = "not looked at"
)

// Loss is one source setting with no equivalent on the target.
type Loss struct {
	Field string `json:"field"`
	Why   string `json:"why"`
	// Widens marks a loss that makes the target more open or less
	// protected than the source (an endpoint reachable from where the
	// source's was not). It fails the translation like a refusal.
	Widens bool `json:"widens,omitempty"`
	// Unread marks a setting no rule reads. What it does is not known
	// here, so it fails the translation too, until a rule names it.
	Unread bool `json:"unread,omitempty"`
}

// Entry is the report for one source object.
type Entry struct {
	Source  string   `json:"source"` // kind group/name, as the snapshot names it
	State   State    `json:"state"`
	Reason  string   `json:"reason,omitempty"` // why refused or not looked at
	Targets []string `json:"targets,omitempty"`
	Losses  []Loss   `json:"losses,omitempty"`
}

// Report is everything a translation says about itself.
type Report struct {
	From         string   `json:"from"`
	To           string   `json:"to"`
	Destinations []string `json:"destinations"`
	Entries      []Entry  `json:"entries"`
	// Requirements are what the target needs that no snapshot holds and
	// nobody should miss: operators to install, a role to grant, who now
	// runs what the cloud ran.
	Requirements []string `json:"requirements,omitempty"`
	// GitOps is what the Kubernetes workloads name that the translation
	// renamed: see gitops.go. Absent unless it was asked for.
	GitOps *GitOpsReport `json:"gitops,omitempty"`
}

// Failed reports whether anything was refused, not looked at, lost in a
// way that widens, or left unread: the translation is then not a rebuild of the source, and
// a person has to look. So does a Kubernetes manifest that names an Azure
// thing with no translation, when the GitOps report was asked for.
func (r Report) Failed() bool {
	if r.GitOps != nil && r.GitOps.failed() {
		return true
	}
	for _, e := range r.Entries {
		if e.State == Refused || e.State == NotLooked {
			return true
		}
		for _, l := range e.Losses {
			if l.Widens || l.Unread {
				return true
			}
		}
	}
	return false
}

// Counts gives the number of entries in each state.
func (r Report) Counts() map[State]int {
	c := map[State]int{}
	for _, e := range r.Entries {
		c[e.State]++
	}
	return c
}

// Result is a translation: a snapshot per target platform (kubernetes, for
// what goes into a cluster) and the report.
type Result struct {
	Snapshots map[string]snapshot.Snapshot
	Report    Report
}

// Targets are the target platforms' own published definitions: the
// CloudFormation registry for AWS, the Discovery documents for GCP. Every
// object a translation writes is built and checked by them, so a field the
// target does not take is refused here, not by the cloud during a restore.
// They are public documents; no account is read.
type Targets struct {
	AWS *awscc.Registry
	GCP *gcp.Docs
}

// out collects the target objects and the report while families translate.
type out struct {
	m       Map
	tg      Targets
	objects map[string][]snapshot.Object // platform -> objects
	keys    map[string]string            // platform|key -> source that made it
	entries []Entry
	reqs    map[string]bool
	err     error
	// subnets are the Azure subnets the network family read, by
	// group/network/subnet in lower case, for a family that places what it
	// writes in them.
	subnets map[string]*subnet
	// netSubs are the subnets the network family wrote, keyed by the Azure
	// subnet (group/network/subnet, lower case), for what goes in them.
	netSubs map[string]*netSub
	// private is the private path private access wrote for each Azure
	// service that had a private endpoint (lockdown.go).
	private map[string]*privatePath
}

// written is the spec of an object already written for a platform, or nil.
func (o *out) written(platform, kind, name string) map[string]any {
	for _, x := range o.objects[platform] {
		if x.Kind() == kind && x.Name() == name {
			s, _ := x.Body["spec"].(map[string]any)
			return s
		}
	}
	return nil
}

// netSub is what one Azure subnet became on the target.
type netSub struct {
	vnet string // its network's group/name, lower case
	// AWS: the subnet's logical name and its availability zone.
	awsName, zone string
	// GCP: the network's and subnetwork's names, and the subnetwork's spec
	// (a cluster adds its secondary ranges to it).
	network, subnetwork string
	spec                map[string]any
	// tag is what stands for its NSG: the security group's name (AWS), the
	// network tag of its firewall rules (GCP).
	tag string
}

func (o *out) add(platform, source string, obj snapshot.Object) string {
	switch platform {
	case "aws":
		spec, _ := obj.Body["spec"].(map[string]any)
		built, err := o.tg.AWS.Object(obj.Kind(), obj.Name(), spec)
		if err != nil && o.err == nil {
			o.err = fmt.Errorf("%s: %w", source, err)
		}
		if err == nil {
			obj = built
		}
	case "gcp":
		ann, _ := obj.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
		api, ver, _ := strings.Cut(fmt.Sprint(ann["truthform.org/discovery"]), "/")
		doc, err := o.tg.GCP.DocFor(api, ver)
		if err == nil {
			spec, _ := obj.Body["spec"].(map[string]any)
			err = doc.CheckSpec(fmt.Sprint(ann["truthform.org/schema"]), spec)
		}
		if err != nil && o.err == nil {
			o.err = fmt.Errorf("%s: %w", source, err)
		}
	}
	k := platform + "|" + obj.Key()
	if prev, ok := o.keys[k]; ok && o.err == nil {
		o.err = fmt.Errorf("%s and %s both translate to %s %s: name one of them in the map's names", prev, source, obj.Kind(), obj.Name())
	}
	o.keys[k] = source
	o.objects[platform] = append(o.objects[platform], obj)
	return obj.Kind() + " " + obj.Name()
}

func (o *out) require(s string) { o.reqs[s] = true }

// family translates the source objects of one service.
type family interface {
	// claims reports whether the family looks at this kind.
	claims(kind string) bool
	translate(objs []snapshot.Object, o *out)
}

// The network family comes before those that use its networks: DNS
// private zones, databases placed in its subnets, and clusters whose nodes
// are. Private access comes next, before the services it reaches: each
// reads the private path written for it, to answer nowhere else.
var families = []family{network{}, privateAccess{}, serviceBus{}, storage{}, keyVault{}, registry{}, dnsFamily{}, databases{}, clusters{}, decided{}}

// Translate rewrites an Azure snapshot for the target the map names, with
// the target's definitions.
func Translate(src snapshot.Snapshot, m Map, tg Targets) (Result, error) {
	if src.Platform != "azure" {
		return Result{}, fmt.Errorf("translate reads an Azure snapshot; this one is %s", src.Platform)
	}
	if err := m.validate(); err != nil {
		return Result{}, err
	}
	switch {
	case m.NeedsAWS() && tg.AWS == nil:
		return Result{}, fmt.Errorf("the map's destinations write AWS objects, which need the AWS registry's schemas")
	case m.NeedsGCP() && tg.GCP == nil:
		return Result{}, fmt.Errorf("the map's destinations write GCP objects, which need GCP's Discovery documents")
	}
	o := &out{m: m, tg: tg, objects: map[string][]snapshot.Object{}, keys: map[string]string{}, reqs: map[string]bool{}, subnets: map[string]*subnet{}, netSubs: map[string]*netSub{}, private: map[string]*privatePath{}}
	claimed := make([][]snapshot.Object, len(families))
	for _, obj := range src.Objects {
		hit := false
		for i, f := range families {
			if f.claims(strings.ToLower(obj.Kind())) {
				claimed[i] = append(claimed[i], obj)
				hit = true
				break
			}
		}
		if !hit {
			o.entries = append(o.entries, Entry{Source: source(obj), State: NotLooked, Reason: "no descriptor for " + obj.Kind() + " yet"})
		}
	}
	for i, f := range families {
		if len(claimed[i]) > 0 {
			f.translate(claimed[i], o)
		}
	}
	if o.err != nil {
		return Result{}, o.err
	}
	res := Result{Snapshots: map[string]snapshot.Snapshot{}}
	for p, objs := range o.objects {
		res.Snapshots[p] = targetSnapshot(p, m, objs)
	}
	sort.Slice(o.entries, func(i, j int) bool { return o.entries[i].Source < o.entries[j].Source })
	for i := range o.entries {
		e := &o.entries[i]
		if e.State == Mapped && len(e.Losses) > 0 {
			e.State = WithLosses
		}
		sort.Strings(e.Targets)
	}
	res.Report = Report{From: "azure", To: m.To, Destinations: m.destinationList(), Entries: o.entries}
	for r := range o.reqs {
		res.Report.Requirements = append(res.Report.Requirements, r)
	}
	sort.Strings(res.Report.Requirements)
	return res, nil
}

// targetSnapshot makes the snapshot restore takes for one platform. Its
// policy is the default one, so a capture of the rebuilt target can be
// diffed against it.
func targetSnapshot(platform string, m Map, objs []snapshot.Object) snapshot.Snapshot {
	sort.Slice(objs, func(i, j int) bool { return objs[i].Key() < objs[j].Key() })
	s := snapshot.Snapshot{Platform: platform, Policy: "default", Objects: objs}
	switch platform {
	case "aws":
		s.ServerVersion = "cloudcontrol/" + m.Region
	case "gcp":
		s.ServerVersion = "discovery"
	}
	count := map[string]int{}
	for _, o := range objs {
		count[o.Kind()]++
	}
	kinds := make([]string, 0, len(count))
	for k := range count {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		s.Coverage = append(s.Coverage, snapshot.Coverage{Resource: k, Kind: k, Captured: count[k]})
	}
	return s
}

// source names an Azure object as the report does: its type, then its
// resource group and name.
func source(o snapshot.Object) string {
	if o.Namespace() == "" {
		return o.Kind() + " " + o.Name() // a resource group, or something above one
	}
	return o.Kind() + " " + o.Namespace() + "/" + o.Name()
}
