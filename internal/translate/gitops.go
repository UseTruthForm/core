package translate

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// Kubernetes workloads and GitOps.
//
// A cluster's workloads are not translated: Flux applies them from Git, a
// Kubernetes capture leaves out what Flux applies and keeps where Flux
// starts, and restoring that on the target has Flux rebuild the rest. But
// the manifests in Git still name Azure things (a registry's login server,
// a Service Bus queue, a Key Vault), and that repository is its owner's to
// edit. So this writes nothing into it. It reads what it is given, a
// Kubernetes snapshot and a checkout of the repository, and lists every
// place that names an Azure thing, with what the translation made of it:
//
//   - change: it has a counterpart on the target, and this is its name;
//   - check: the target has a form of its own that a person chooses (the
//     role a service account takes, a storage class, an ingress class);
//   - no translation: the Azure thing was refused, not looked at, or is
//     not in the Azure snapshot. It fails the run like a refusal: applied
//     as it is, the workload would point at Azure.
//
// What could not be read is said, never passed over: a source whose
// content was in neither input, a chart's templates, values Flux fills in.
// Nothing here is rendered: no kustomize build, no helm template, no
// request.

// GitOpsState is what one reference came to.
type GitOpsState string

// The three states; see the comment above.
const (
	GitOpsChange GitOpsState = "change"
	GitOpsCheck  GitOpsState = "check"
	GitOpsNone   GitOpsState = "no translation"
)

// GitOpsRef is one place that names an Azure thing.
type GitOpsRef struct {
	// File and Line are where it is in the repository checkout; empty for
	// an object read from the Kubernetes snapshot.
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
	// Object is the Kubernetes object: Kind namespace/name.
	Object string `json:"object,omitempty"`
	// AppliedBy is what applies it: a Flux Kustomization or HelmRelease,
	// or that nothing in Git does.
	AppliedBy string `json:"appliedBy"`
	Field     string `json:"field,omitempty"`
	// What is the class of thing named: image, messaging, secret, storage,
	// database, identity, storage class, ingress, load balancer, endpoint.
	What string `json:"what"`
	// Names is the Azure thing as it is written there. Never a whole
	// value: a connection string is named by its host.
	Names  string      `json:"names"`
	State  GitOpsState `json:"state"`
	Target string      `json:"target,omitempty"`
	Why    string      `json:"why,omitempty"`
	// Variable is the key in the variables file that holds Target.
	Variable string `json:"variable,omitempty"`
	// NotApplied marks a file that the cluster's Flux, followed from the
	// roots the snapshot holds, does not apply. It is listed and does not
	// fail the run.
	NotApplied bool `json:"notApplied,omitempty"`
}

// GitOpsSource is one Flux Kustomization or HelmRelease, and how much of
// what it applies could be read.
type GitOpsSource struct {
	Source string `json:"source"` // Flux Kustomization flux-system/apps
	Path   string `json:"path,omitempty"`
	// LeftOut is how many objects the capture left to it (from the
	// Kubernetes snapshot's skips); Found, how many of those are in the
	// files read for it.
	LeftOut int `json:"leftOut,omitempty"`
	Found   int `json:"found,omitempty"`
	// Checked: files (the manifests under its path were read), values
	// only (a HelmRelease: its values, not its chart), snapshot (its
	// objects are in the Kubernetes snapshot), or not available.
	Checked string `json:"checked"`
	Why     string `json:"why,omitempty"`
	// NotFound are objects the capture left to it that the files read for
	// it do not hold: generated, or from somewhere else.
	NotFound []string `json:"notFound,omitempty"`
}

// GitOpsNamespace lists the workloads of one namespace that no GitOps
// source applies: a restore recreates them from the snapshot as they are.
type GitOpsNamespace struct {
	Namespace string   `json:"namespace"`
	Workloads []string `json:"workloads"`
}

// GitOpsReport is the report's section on Kubernetes workloads.
type GitOpsReport struct {
	// Read says what was read.
	Read       []string          `json:"read"`
	References []GitOpsRef       `json:"references,omitempty"`
	Sources    []GitOpsSource    `json:"sources,omitempty"`
	NotInGit   []GitOpsNamespace `json:"notInGit,omitempty"`
	// NotSeen is everything this could not see, in words.
	NotSeen []string `json:"notSeen,omitempty"`
	// Variables is the file, beside the report, with the same names as a
	// ConfigMap.
	Variables string `json:"variables,omitempty"`
}

// Counts gives the references in each state that count: those in files
// the cluster's Flux does not apply are counted apart, under "".
func (g GitOpsReport) Counts() map[GitOpsState]int {
	c := map[GitOpsState]int{}
	for _, r := range g.References {
		if r.NotApplied {
			c[""]++
			continue
		}
		c[r.State]++
	}
	return c
}

// NotAvailable is how many sources' content was in neither input.
func (g GitOpsReport) NotAvailable() int {
	n := 0
	for _, s := range g.Sources {
		if s.Checked == goNotAvailable {
			n++
		}
	}
	return n
}

// failed: a reference to an Azure thing with no translation, in something
// the cluster applies. One that only needs editing does not fail the run,
// and neither does a source that could not be read: that is a limit of
// what was given, said in the report, and nothing a map could settle.
func (g GitOpsReport) failed() bool {
	for _, r := range g.References {
		if r.State == GitOpsNone && !r.NotApplied {
			return true
		}
	}
	return false
}

// GitOpsInput is what the GitOps report reads. Either may be absent.
type GitOpsInput struct {
	// Kube is a Kubernetes snapshot of the source cluster.
	Kube *snapshot.Snapshot
	// Dir is a local checkout of the repository Flux reads.
	Dir string
}

// GitOpsVariablesFile is the variables file's name, beside the report.
const GitOpsVariablesFile = "gitops-variables.yaml"

// The tokens a target snapshot uses for what is not known offline: the
// AWS account (awscc's accountToken) and the GCP project.
const (
	goAccount = "{{truthform|account|self|id}}"
	goProject = "{{truthform|project}}"
)

// GitOps adds the report's section on Kubernetes workloads to a
// translation and returns the variables file. It reads the Azure snapshot
// for what answers at which name, and the translation's own report for
// what each became: no name is worked out a second time.
func GitOps(src snapshot.Snapshot, m Map, res *Result, in GitOpsInput) ([]byte, error) {
	if in.Kube != nil && in.Kube.Platform != "kubernetes" {
		return nil, fmt.Errorf("--kube reads a Kubernetes snapshot; this one is %s", in.Kube.Platform)
	}
	x := newGoIndex(src, m, res)
	s := &goScan{x: x, stores: map[string]string{}}
	g := &GitOpsReport{Variables: GitOpsVariablesFile}
	var docs []*goDoc
	var repo *goRepo
	if in.Dir != "" {
		var err error
		if repo, err = goReadRepo(in.Dir); err != nil {
			return nil, err
		}
		docs = append(docs, repo.docs...)
	}
	var kube *goKube
	if in.Kube != nil {
		kube = goReadKube(*in.Kube)
		docs = append(docs, kube.docs...)
	}
	if repo != nil {
		repo.attribute(kube)
	}
	// Stores first: an ExternalSecret names its vault only through one.
	for _, d := range docs {
		s.store(d)
	}
	for _, d := range docs {
		s.doc(d)
	}
	g.References = s.refs
	sort.SliceStable(g.References, func(i, j int) bool {
		a, b := g.References[i], g.References[j]
		switch {
		case a.File != b.File:
			// The snapshot's objects after the files.
			return a.File != "" && (b.File == "" || a.File < b.File)
		case a.Line != b.Line:
			return a.Line < b.Line
		case a.Object != b.Object:
			return a.Object < b.Object
		case a.Field != b.Field:
			return a.Field < b.Field
		}
		return a.Names < b.Names
	})
	goSources(g, repo, kube, docs)
	goNotSeen(g, s, repo, kube, in)
	res.Report.GitOps = g
	return x.variablesFile(), nil
}

// goIndex is what the Azure snapshot holds that a workload can name, by
// the name it answers to, with the translation's entry for each.
type goIndex struct {
	m       Map
	res     *Result
	entries map[string]*Entry
	// Each maps a lower-case name to the source the report names. Azure
	// gives each of these a DNS name of its own, so no two share one.
	regs, sbNS, queues, topics, subs, vaults, secrets, accounts, containers, dbs map[string]string
}

func newGoIndex(src snapshot.Snapshot, m Map, res *Result) *goIndex {
	x := &goIndex{m: m, res: res, entries: map[string]*Entry{},
		regs: map[string]string{}, sbNS: map[string]string{}, queues: map[string]string{}, topics: map[string]string{}, subs: map[string]string{},
		vaults: map[string]string{}, secrets: map[string]string{}, accounts: map[string]string{}, containers: map[string]string{}, dbs: map[string]string{}}
	for i := range res.Report.Entries {
		x.entries[res.Report.Entries[i].Source] = &res.Report.Entries[i]
	}
	for _, o := range src.Objects {
		name := strings.ToLower(o.Name())
		var into map[string]string
		switch strings.ToLower(o.Kind()) {
		case azRegistry:
			into = x.regs
		case sbNamespace:
			into = x.sbNS
		case sbNamespace + "/queues":
			into = x.queues
		case sbNamespace + "/topics":
			into = x.topics
		case sbNamespace + "/topics/subscriptions":
			into = x.subs
		case azVault:
			into = x.vaults
		case azVault + "/secrets":
			into = x.secrets
		case azStorage:
			into = x.accounts
		case azStorage + "/blobservices/containers":
			// account/default/container
			if p := strings.Split(name, "/"); len(p) == 3 {
				name, into = p[0]+"/"+p[2], x.containers
			}
		case azPG, azSQL:
			into = x.dbs
		}
		if into != nil {
			into[name] = source(o)
		}
	}
	return x
}

// goTarget is what a reference came to.
type goTarget struct {
	state    GitOpsState
	target   string
	why      string
	variable string
}

func goNone(why string) goTarget { return goTarget{state: GitOpsNone, why: why} }

// made finds what the translation wrote for a source: the name of its
// target of this kind. A queue is written with its dead-letter queue,
// whose name is the queue's with a suffix, so the shortest is the queue.
// Without one it says why, as the report does.
func (x *goIndex) made(src, kind string) (string, goTarget) {
	e := x.entries[src]
	if e == nil {
		return "", goNone(src + " is not in the translation's report")
	}
	if e.State == Refused || e.State == NotLooked {
		return "", goNone(fmt.Sprintf("%s was %s: %s", src, e.State, e.Reason))
	}
	best := ""
	for _, t := range e.Targets {
		k, n, _ := strings.Cut(t, " ")
		if k == kind && (best == "" || len(n) < len(best)) {
			best = n
		}
	}
	if best == "" {
		why := src + " was translated, and no " + kind + " was written for it"
		if e.Reason != "" {
			why += ": " + e.Reason
		}
		return "", goNone(why)
	}
	return best, goTarget{}
}

// last is the final segment of a GCP resource name.
func goLast(n string) string { return n[strings.LastIndex(n, "/")+1:] }

// registry is what a registry's login server became: the host and path
// an image reference starts with.
func (x *goIndex) registry(name string) goTarget {
	src, ok := x.regs[strings.ToLower(name)]
	if !ok {
		return goNone("registry " + name + " is not in the Azure snapshot")
	}
	v := goVarName("registry", name)
	switch x.m.Destinations.Registry {
	case "ecr":
		prefix, t := x.made(src, awsRepoTmpl)
		if t.state != "" {
			return t
		}
		return goTarget{state: GitOpsChange, variable: v, target: fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/%s", goAccount, x.m.Region, prefix),
			why: "the account is not known offline: " + goAccount + " stands for it, as in the AWS snapshot"}
	case "artifact-registry":
		n, t := x.made(src, gcpRepo)
		if t.state != "" {
			return t
		}
		return goTarget{state: GitOpsChange, variable: v, target: fmt.Sprintf("%s-docker.pkg.dev/%s/%s", x.m.Region, goProject, goLast(n)),
			why: "the project is not known offline: " + goProject + " stands for it, as in the GCP snapshot"}
	}
	_, t := x.made(src, "")
	return t
}

// goEntity is a queue, topic or subscription a workload names.
type goEntity struct {
	kind                  string // queue, topic, subscription
	ns, name, sub, source string
}

// entity finds a queue, a topic or a topic's subscription. A workload
// that reaches its namespace through a connection string does not name
// it: the entity is then looked for by its own name, and taken only when
// one namespace in the snapshot has it.
func (x *goIndex) entity(ns, queue, topic, sub string) (goEntity, string) {
	e := goEntity{kind: "queue", ns: ns, name: queue}
	idx, key := x.queues, strings.ToLower(queue)
	switch {
	case topic != "" && sub != "":
		e, idx, key = goEntity{kind: "subscription", ns: ns, name: topic, sub: sub}, x.subs, strings.ToLower(topic+"/"+sub)
	case topic != "":
		e, idx, key = goEntity{kind: "topic", ns: ns, name: topic}, x.topics, strings.ToLower(topic)
	}
	what := e.kind + " " + strings.TrimSuffix(e.name+"/"+e.sub, "/")
	if ns != "" {
		src, ok := idx[strings.ToLower(ns)+"/"+key]
		if !ok {
			return e, what + " of Service Bus namespace " + ns + " is not in the Azure snapshot"
		}
		e.source = src
		return e, ""
	}
	var hits []string
	for k := range idx {
		if n, rest, _ := strings.Cut(k, "/"); rest == key {
			hits = append(hits, n)
		}
	}
	sort.Strings(hits)
	switch len(hits) {
	case 0:
		return e, what + " is in no Service Bus namespace of the Azure snapshot"
	case 1:
		e.ns, e.source = hits[0], idx[hits[0]+"/"+key]
		return e, ""
	}
	return e, fmt.Sprintf("%s is in %d Service Bus namespaces of the Azure snapshot (%s), and this does not say which", what, len(hits), strings.Join(hits, ", "))
}

// messaging is the name a queue, topic or subscription has on the
// messaging destination: an SQS queue's URL or an SNS topic's ARN, a
// Pub/Sub subscription's or topic's full name, a RabbitMQ queue's or
// exchange's name.
func (x *goIndex) messaging(e goEntity) goTarget {
	v := goVarName("servicebus", e.ns, e.kind, e.name, e.sub)
	switch x.m.Destinations.Messaging {
	case "sqs-sns":
		if e.kind == "topic" {
			n, t := x.made(e.source, "AWS::SNS::Topic")
			if t.state != "" {
				return t
			}
			return goTarget{state: GitOpsChange, variable: v, target: fmt.Sprintf("arn:aws:sns:%s:%s:%s", x.m.Region, goAccount, n)}
		}
		n, t := x.made(e.source, "AWS::SQS::Queue")
		if t.state != "" {
			return t
		}
		return goTarget{state: GitOpsChange, variable: v, target: fmt.Sprintf("https://sqs.%s.amazonaws.com/%s/%s", x.m.Region, goAccount, n)}
	case "pubsub":
		kind := "pubsub.googleapis.com/Subscription"
		if e.kind == "topic" {
			kind = "pubsub.googleapis.com/Topic"
		}
		n, t := x.made(e.source, kind)
		if t.state != "" {
			return t
		}
		return goTarget{state: GitOpsChange, variable: v, target: n}
	case "rabbitmq":
		kind := "Queue"
		if e.kind == "topic" {
			kind = "Exchange"
		}
		n, t := x.made(e.source, kind)
		if t.state != "" {
			return t
		}
		// The object's name is Kubernetes'; the broker's is in its spec.
		for _, o := range x.res.Snapshots["kubernetes"].Objects {
			if o.Kind() == kind && o.Name() == n {
				spec, _ := o.Body["spec"].(map[string]any)
				return goTarget{state: GitOpsChange, variable: v, target: fmt.Sprint(spec["name"])}
			}
		}
		return goNone(e.source + ": its " + kind + " " + n + " is not in the Kubernetes snapshot the translation wrote")
	}
	_, t := x.made(e.source, "")
	return t
}

// broker is where a Service Bus namespace's clients connect on the
// target, in words: only RabbitMQ has a host of its own.
func (x *goIndex) broker(ns string) goTarget {
	src, ok := x.sbNS[strings.ToLower(ns)]
	if !ok {
		return goNone("Service Bus namespace " + ns + " is not in the Azure snapshot (Event Hubs and Relay answer under the same domain, and are not translated)")
	}
	e := x.entries[src]
	if e == nil || e.State == Refused || e.State == NotLooked {
		_, t := x.made(src, "")
		return t
	}
	switch x.m.Destinations.Messaging {
	case "sqs-sns":
		return goTarget{state: GitOpsChange, target: fmt.Sprintf("no host of its own: each queue is https://sqs.%s.amazonaws.com/%s/<queue>, each topic arn:aws:sns:%s:%s:<topic>", x.m.Region, goAccount, x.m.Region, goAccount),
			why: "the client moves from the Service Bus SDK to the AWS SDK"}
	case "pubsub":
		return goTarget{state: GitOpsChange, target: "no host of its own: topics and subscriptions are named under projects/" + goProject,
			why: "the client moves from the Service Bus SDK to a Pub/Sub client"}
	case "rabbitmq":
		c, t := x.made(src, "RabbitmqCluster")
		if t.state != "" {
			return t
		}
		// https://www.rabbitmq.com/kubernetes/operator/using-operator: the
		// Service is named after the cluster, and the default user's
		// credentials are in the Secret <cluster>-default-user.
		port := "5672"
		if x.m.RabbitMQ.TLSSecret != "" {
			port = "5671 (TLS)"
		}
		return goTarget{state: GitOpsChange, target: fmt.Sprintf("%s.%s.svc, port %s", c, x.m.RabbitMQ.Namespace, port),
			why: "the client moves from the Service Bus SDK to an AMQP client; the Cluster Operator keeps the default user's name and password in Secret " + c + "-default-user"}
	}
	return goNone("the map chooses no destination for messaging (destinations.messaging)")
}

// secret is the name a Key Vault secret has on the target.
func (x *goIndex) secret(vault, name string) goTarget {
	if _, ok := x.vaults[strings.ToLower(vault)]; !ok {
		return goNone("Key Vault " + vault + " is not in the Azure snapshot")
	}
	src, ok := x.secrets[strings.ToLower(vault+"/"+name)]
	if !ok {
		return goNone("secret " + name + " of Key Vault " + vault + " is not in the Azure snapshot")
	}
	v := goVarName("keyvault", vault, "secret", name)
	switch x.m.To {
	case "aws":
		n, t := x.made(src, "AWS::SecretsManager::Secret")
		if t.state != "" {
			return t
		}
		return goTarget{state: GitOpsChange, variable: v, target: n}
	default:
		n, t := x.made(src, "secretmanager.googleapis.com/Secret")
		if t.state != "" {
			return t
		}
		return goTarget{state: GitOpsChange, variable: v, target: goLast(n)}
	}
}

// vault is what a Key Vault's address becomes, in words: neither target
// has a vault, so there is no URL to put in its place.
func (x *goIndex) vault(name string) goTarget {
	src, ok := x.vaults[strings.ToLower(name)]
	if !ok {
		return goNone("Key Vault " + name + " is not in the Azure snapshot")
	}
	if e := x.entries[src]; e == nil || e.State == Refused || e.State == NotLooked {
		_, t := x.made(src, "")
		return t
	}
	var secrets []string
	for k := range x.secrets {
		if v, s, _ := strings.Cut(k, "/"); v == strings.ToLower(name) {
			if t := x.secret(name, s); t.state == GitOpsChange {
				secrets = append(secrets, t.target)
			}
		}
	}
	sort.Strings(secrets)
	where := "AWS Secrets Manager in " + x.m.Region
	if x.m.To == "gcp" {
		where = "Secret Manager in projects/" + goProject
	}
	return goTarget{state: GitOpsChange, target: fmt.Sprintf("no vault address: its secrets are secrets of their own in %s (%s)", where, goList(secrets, "none translated"))}
}

// bucket is the bucket a blob container became.
func (x *goIndex) bucket(account, container string) goTarget {
	if _, ok := x.accounts[strings.ToLower(account)]; !ok {
		return goNone("storage account " + account + " is not in the Azure snapshot")
	}
	src, ok := x.containers[strings.ToLower(account+"/"+container)]
	if !ok {
		return goNone("container " + container + " of storage account " + account + " is not in the Azure snapshot")
	}
	kind := "AWS::S3::Bucket"
	if x.m.To == "gcp" {
		kind = "storage.googleapis.com/Bucket"
	}
	n, t := x.made(src, kind)
	if t.state != "" {
		return t
	}
	return goTarget{state: GitOpsChange, variable: goVarName("storage", account, container), target: n}
}

// account is what a storage account's blob endpoint becomes, in words:
// each container is a bucket, and the account is none.
func (x *goIndex) account(name string) goTarget {
	src, ok := x.accounts[strings.ToLower(name)]
	if !ok {
		return goNone("storage account " + name + " is not in the Azure snapshot")
	}
	if e := x.entries[src]; e == nil || e.State == Refused || e.State == NotLooked {
		_, t := x.made(src, "")
		return t
	}
	var buckets []string
	for k := range x.containers {
		if a, c, _ := strings.Cut(k, "/"); a == strings.ToLower(name) {
			if t := x.bucket(name, c); t.state == GitOpsChange {
				buckets = append(buckets, c+" -> "+t.target)
			}
		}
	}
	sort.Strings(buckets)
	if len(buckets) == 0 {
		return goNone("storage account " + name + " has no container that became a bucket")
	}
	return goTarget{state: GitOpsChange, target: "no endpoint of its own: each container is a bucket (" + strings.Join(buckets, ", ") + ")"}
}

// database is what a database server's host name becomes: an endpoint
// the target makes up when it creates the instance, so not known here.
func (x *goIndex) database(name string) goTarget {
	src, ok := x.dbs[strings.ToLower(name)]
	if !ok {
		return goNone("database server " + name + " is not in the Azure snapshot, or is of a kind that is not translated")
	}
	if x.m.To == "aws" {
		n, t := x.made(src, "AWS::RDS::DBInstance")
		if t.state != "" {
			return t
		}
		return goTarget{state: GitOpsChange, target: "the endpoint RDS gives DB instance " + n + " when it is created",
			why: "not known offline: read it from the instance after the restore (Endpoint.Address)"}
	}
	n, t := x.made(src, "sqladmin.googleapis.com/Instance")
	if t.state != "" {
		return t
	}
	return goTarget{state: GitOpsChange, target: "the address Cloud SQL gives instance " + goLast(n) + " when it is created",
		why: fmt.Sprintf("not known offline: read it from the instance after the restore (ipAddresses), or connect by its connection name %s:%s:%s", goProject, x.m.Region, goLast(n))}
}

func goList(items []string, none string) string {
	if len(items) == 0 {
		return none
	}
	return strings.Join(items, ", ")
}

// goVarName makes a variable's name from its parts. Flux takes only
// letters, digits and underscores, with no digit first
// (^[_[:alpha:]][_[:alpha:][:digit:]]*$):
// https://fluxcd.io/flux/components/kustomize/kustomizations/#post-build-variable-substitution
func goVarName(parts ...string) string {
	var b strings.Builder
	for _, p := range parts {
		if p == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('_')
		}
		for _, r := range strings.ToLower(p) {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
				b.WriteRune(r)
			} else {
				b.WriteByte('_')
			}
		}
	}
	return b.String()
}

// goVar is one line of the variables file.
type goVar struct{ name, was, value string }

// variables are the target's names for everything in the Azure snapshot
// that was translated and that a manifest can name, whether or not one
// was seen to: a reference this could not see can then still be written
// with its variable. Nothing here is a secret: they are names.
func (x *goIndex) variables() []goVar {
	var out []goVar
	add := func(was string, t goTarget) {
		if t.state == GitOpsChange {
			out = append(out, goVar{t.variable, was, t.target})
		}
	}
	for n := range x.regs {
		add(n+".azurecr.io", x.registry(n))
	}
	for k, src := range x.queues {
		ns, q, _ := strings.Cut(k, "/")
		add("queue "+q+" in Service Bus namespace "+ns, x.messaging(goEntity{kind: "queue", ns: ns, name: q, source: src}))
	}
	for k, src := range x.topics {
		ns, t, _ := strings.Cut(k, "/")
		add("topic "+t+" in Service Bus namespace "+ns, x.messaging(goEntity{kind: "topic", ns: ns, name: t, source: src}))
	}
	for k, src := range x.subs {
		if p := strings.SplitN(k, "/", 3); len(p) == 3 {
			add("subscription "+p[1]+"/"+p[2]+" in Service Bus namespace "+p[0], x.messaging(goEntity{kind: "subscription", ns: p[0], name: p[1], sub: p[2], source: src}))
		}
	}
	for k := range x.secrets {
		if v, s, ok := strings.Cut(k, "/"); ok {
			add("secret "+s+" in Key Vault "+v, x.secret(v, s))
		}
	}
	for k := range x.containers {
		if a, c, ok := strings.Cut(k, "/"); ok {
			add(fmt.Sprintf("https://%s.blob.core.windows.net/%s", a, c), x.bucket(a, c))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].name != out[j].name {
			return out[i].name < out[j].name
		}
		return out[i].was < out[j].was
	})
	// Two Azure names that differ only in what a variable's name cannot
	// hold would share one: the later takes a number.
	seen := map[string]int{}
	for i := range out {
		seen[out[i].name]++
		if n := seen[out[i].name]; n > 1 {
			out[i].name += "_" + strconv.Itoa(n)
		}
	}
	return out
}

// variablesFile is the ConfigMap a Flux Kustomization's
// spec.postBuild.substituteFrom can read. It is a file for a person to
// commit, not an object of the Kubernetes snapshot: its values hold
// tokens for what is not known offline, it belongs in the repository
// beside the manifests that use it, and a restore must not apply it
// behind Flux's back.
func (x *goIndex) variablesFile() []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# Written by truthform translate: the names on %s of what the Azure snapshot named.\n", x.m.To)
	b.WriteString(`#
# Optional. A Flux Kustomization reads it with spec.postBuild.substituteFrom
# (kind: ConfigMap, name: truthform-translation), and a manifest then says
# ${registry_shop}/api:1.0 where it said shop.azurecr.io/api:1.0. With one such
# ConfigMap per cluster, holding each cloud's values under the same keys, one
# repository serves both: the line above each key is its value on Azure.
#
# Before committing it:
#  - give it the namespace of the Kustomization that reads it;
`)
	switch x.m.To {
	case "aws":
		b.WriteString("#  - put the AWS account ID where " + goAccount + " stands: it is not known offline;\n")
	case "gcp":
		b.WriteString("#  - put the project ID where " + goProject + " stands: it is not known offline;\n")
	}
	b.WriteString(`#  - mind that Flux then substitutes every ${name} in what that Kustomization
#    applies, and an undefined one becomes empty: write $${name} where a script
#    or a config file must keep its own ${name}, or label the object
#    kustomize.toolkit.fluxcd.io/substitute: disabled.
# Database addresses are not here: the target makes them up at creation.
apiVersion: v1
kind: ConfigMap
metadata:
  name: truthform-translation
data:
`)
	fmt.Fprintf(&b, "  cloud: %s\n", strconv.Quote(x.m.To))
	if x.m.Region != "" {
		fmt.Fprintf(&b, "  region: %s\n", strconv.Quote(x.m.Region))
	}
	for _, v := range x.variables() {
		fmt.Fprintf(&b, "  # on Azure: %s\n  %s: %s\n", v.was, v.name, strconv.Quote(v.value))
	}
	return []byte(b.String())
}
