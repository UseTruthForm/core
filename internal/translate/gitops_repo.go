package translate

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	yaml3 "go.yaml.in/yaml/v3"

	"github.com/usetruthform/core/internal/snapshot"
)

// What the two inputs hold, and which Flux source applies what.
//
// A Kubernetes snapshot holds the objects no GitOps source applies and
// where Flux starts (the Kustomization that applies itself, with the
// repository it reads). What Flux applies is left out, and named: each
// skip says which Kustomization or HelmRelease recreates the object. So
// the snapshot says which sources the cluster has and how many objects
// each makes, and not what is in them.
//
// A checkout of the repository holds what is in them, as files. Which
// Kustomization applies a file is worked out as Flux does it: from the
// Kustomization's path, through that directory's kustomization.yaml and
// what it lists, or every manifest under the path when it has none. No
// file is built: see goNotSeen for what that leaves unseen.

const (
	goFluxKS      = "Flux Kustomization"
	goFluxHR      = "Flux HelmRelease"
	goKSGroup     = "kustomize.toolkit.fluxcd.io"
	goHRGroup     = "helm.toolkit.fluxcd.io"
	goMaxFileSize = 4 << 20

	goFiles        = "files"
	goValuesOnly   = "values only"
	goInSnapshot   = "snapshot"
	goNotAvailable = "not available"
)

// goFlux is a Flux Kustomization: where it is defined and what it reads.
type goFlux struct {
	ns, name  string
	path      string
	source    string // its sourceRef: kind namespace/name
	targetNS  string
	definedIn string
	// files are the checkout's files it applies; why says why it has
	// none.
	files map[string]bool
	why   string
}

func (f *goFlux) id() string { return goFluxKS + " " + f.ns + "/" + f.name }

func goFluxOf(d *goDoc) *goFlux {
	if d.group() != goKSGroup || d.kind() != "Kustomization" {
		return nil
	}
	spec := goMap(d.body, "spec")
	ref := goMap(spec, "sourceRef")
	f := &goFlux{ns: d.str("metadata", "namespace"), name: d.name(), path: goStr(spec, "path"), targetNS: goStr(spec, "targetNamespace"), definedIn: d.file}
	if ref != nil {
		ns := goStr(ref, "namespace")
		if ns == "" {
			ns = f.ns
		}
		f.source = goStr(ref, "kind") + " " + ns + "/" + goStr(ref, "name")
	}
	return f
}

// goRepo is a checkout of the repository Flux reads.
type goRepo struct {
	docs  []*goDoc
	files map[string][]*goDoc // by path relative to the checkout, slashes
	// dirs lists each directory's entries; a name ending in / is a
	// directory.
	dirs map[string][]string
	flux []*goFlux
	// rooted: which files apply was followed from the Flux
	// Kustomizations the Kubernetes snapshot holds.
	rooted bool
	// What was met and could not be read.
	yamlFiles, yamlDocs int
	asText              []string // not YAML as written: scanned as text
	skipped             []string // too large, or not text
	remote, inflated    int      // kustomize resources fetched from a URL; charts kustomize inflates
	outside             []string // kustomize entries that point outside the checkout
}

func goReadRepo(dir string) (*goRepo, error) {
	st, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("--gitops: %w", err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("--gitops: %s is not a directory", dir)
	}
	r := &goRepo{files: map[string][]*goDoc{}, dirs: map[string][]string{}}
	err = filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		parent := path.Dir(rel)
		if e.IsDir() {
			if e.Name() == ".git" {
				return filepath.SkipDir
			}
			r.dirs[parent] = append(r.dirs[parent], e.Name()+"/")
			return nil
		}
		if !e.Type().IsRegular() {
			return nil // a link is not followed out of the checkout
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		r.dirs[parent] = append(r.dirs[parent], e.Name())
		if info.Size() > goMaxFileSize {
			r.skipped = append(r.skipped, rel)
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if bytes.IndexByte(b, 0) >= 0 {
			return nil // not text
		}
		r.read(rel, b)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("--gitops: %w", err)
	}
	for _, d := range r.sortedFiles() {
		r.docs = append(r.docs, r.files[d]...)
	}
	return r, nil
}

func (r *goRepo) sortedFiles() []string {
	out := make([]string, 0, len(r.files))
	for f := range r.files {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

func goIsYAML(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".yaml", ".yml", ".json":
		return true
	}
	return path.Base(name) == "Kustomization"
}

// read parses one file. A YAML file that does not parse as written (a
// chart's template) and any other text file is kept as text: host names
// are still looked for in it, line by line.
func (r *goRepo) read(rel string, b []byte) {
	text := func() {
		r.files[rel] = []*goDoc{{file: rel, text: true, body: map[string]any{"text": string(b)}}}
	}
	if !goIsYAML(rel) {
		text()
		return
	}
	var docs []*goDoc
	dec := yaml3.NewDecoder(bytes.NewReader(b))
	for {
		var n yaml3.Node
		err := dec.Decode(&n)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			r.asText = append(r.asText, rel)
			text()
			return
		}
		d := &goDoc{file: rel, lines: map[string]int{}, blocks: map[string]bool{}}
		if m, ok := goDecode(&n, "", d).(map[string]any); ok {
			d.body = m
			docs = append(docs, d)
		}
	}
	r.yamlFiles++
	r.yamlDocs += len(docs)
	r.files[rel] = docs
}

// goKustomizeNames are the names kustomize reads its file under.
var goKustomizeNames = []string{"kustomization.yaml", "kustomization.yml", "Kustomization"}

// kustomizeFile is a directory's kustomize file, if it has one.
func (r *goRepo) kustomizeFile(dir string) string {
	for _, e := range r.dirs[dir] {
		for _, n := range goKustomizeNames {
			if e == n {
				return path.Join(dir, n)
			}
		}
	}
	return ""
}

func (r *goRepo) isDir(p string) bool {
	if p == "." {
		return true
	}
	for _, e := range r.dirs[path.Dir(p)] {
		if e == path.Base(p)+"/" {
			return true
		}
	}
	return false
}

var goRemote = regexp.MustCompile(`^([a-z][a-z0-9+.-]*://|git@|github\.com/|git::)`)

// reach collects the files a directory applies, as Flux builds it.
func (r *goRepo) reach(dir string, set, seen map[string]bool) {
	dir = path.Clean(dir)
	if seen[dir] {
		return
	}
	seen[dir] = true
	kf := r.kustomizeFile(dir)
	if kf == "" {
		// Flux generates a kustomization for every manifest in the tree;
		// a directory with a kustomization of its own is built as one
		// (fluxcd/pkg kustomize: scanManifests).
		for _, e := range r.dirs[dir] {
			p := path.Join(dir, e)
			switch {
			case strings.HasSuffix(e, "/"):
				r.reach(p, set, seen)
			case path.Ext(e) == ".yaml" || path.Ext(e) == ".yml":
				set[p] = true
			}
		}
		return
	}
	set[kf] = true
	docs := r.files[kf]
	if len(docs) == 0 || docs[0].text {
		return
	}
	body := docs[0].body
	entry := func(v any) {
		s, _ := v.(string)
		if s == "" || strings.Contains(s, "\n") {
			return // an inline patch
		}
		if goRemote.MatchString(s) {
			r.remote++
			return
		}
		p := path.Join(dir, s)
		switch {
		case p == ".." || strings.HasPrefix(p, "../"):
			r.outside = append(r.outside, kf+": "+s)
		case r.isDir(p):
			r.reach(p, set, seen)
		default:
			if _, ok := r.files[p]; ok {
				set[p] = true
			} else {
				r.outside = append(r.outside, kf+": "+s)
			}
		}
	}
	for _, k := range []string{"resources", "bases", "components", "crds", "patchesStrategicMerge", "configurations"} {
		l, _ := body[k].([]any)
		for _, v := range l {
			entry(v)
		}
	}
	for _, k := range []string{"patches", "patchesJson6902", "replacements"} {
		l, _ := body[k].([]any)
		for _, v := range l {
			entry(goMap(v)["path"])
		}
	}
	for _, k := range []string{"configMapGenerator", "secretGenerator"} {
		l, _ := body[k].([]any)
		for _, v := range l {
			g := goMap(v)
			for _, fk := range []string{"files", "envs"} {
				fl, _ := g[fk].([]any)
				for _, f := range fl {
					s, _ := f.(string)
					if _, after, ok := strings.Cut(s, "="); ok {
						s = after
					}
					entry(s)
				}
			}
		}
	}
	if l, _ := body["helmCharts"].([]any); len(l) > 0 {
		r.inflated += len(l)
	}
}

// follow gives a Flux Kustomization the files under its path.
func (r *goRepo) follow(f *goFlux) {
	p := path.Clean(strings.TrimPrefix(filepath.ToSlash(f.path), "/"))
	if f.path == "" {
		p = "."
	}
	switch {
	case p == ".." || strings.HasPrefix(p, "../"):
		f.why = "its path " + f.path + " leaves the repository"
		return
	case !r.isDir(p):
		f.why = "its path " + f.path + " is not in the --gitops directory"
		if f.source != "" {
			f.why += " (it reads " + f.source + ", which may be another repository)"
		}
		return
	}
	f.files = map[string]bool{}
	r.reach(p, f.files, map[string]bool{})
}

// attribute works out which Flux Kustomization applies each file. With
// a Kubernetes snapshot that holds where Flux starts, it follows from
// there, so a repository that serves several clusters is read as this
// cluster reads it; without, every Kustomization the files define is
// followed.
func (r *goRepo) attribute(k *goKube) {
	defined := map[string][]*goFlux{} // file -> the Flux Kustomizations it defines
	for _, d := range r.docs {
		if f := goFluxOf(d); f != nil {
			defined[d.file] = append(defined[d.file], f)
		}
	}
	var queue []*goFlux
	if k != nil && len(k.roots) > 0 {
		r.rooted = true
		for _, f := range k.roots {
			c := *f
			queue = append(queue, &c)
		}
	} else {
		for _, f := range goSortedSet(goKeysOf(defined)) {
			queue = append(queue, defined[f]...)
		}
	}
	seen := map[string]bool{}
	for len(queue) > 0 {
		f := queue[0]
		queue = queue[1:]
		// Two clusters' Kustomizations may share a name: each is one
		// source, told apart by where it is defined.
		key := f.id() + "|" + f.path
		if seen[key] {
			continue
		}
		seen[key] = true
		r.follow(f)
		r.flux = append(r.flux, f)
		if !r.rooted {
			continue
		}
		for _, file := range goSortedSet(f.files) {
			queue = append(queue, defined[file]...)
		}
	}
	applied := map[string]bool{}
	for _, f := range r.flux {
		for file := range f.files {
			applied[file] = true
			for _, d := range r.files[file] {
				d.by = append(d.by, f.id())
				if d.targetNS == "" {
					d.targetNS = f.targetNS
				}
			}
		}
	}
	for _, d := range r.docs {
		sort.Strings(d.by)
		d.by = dedupe(d.by)
		d.notApplied = r.rooted && !applied[d.file]
	}
}

func goKeysOf[V any](m map[string]V) map[string]bool {
	out := map[string]bool{}
	for k := range m {
		out[k] = true
	}
	return out
}

// goKube is what a Kubernetes snapshot says of GitOps.
type goKube struct {
	docs []*goDoc
	// roots are the Flux Kustomizations it holds.
	roots []*goFlux
	// left are the objects the capture left to each source, as the
	// report names it; held, how many objects of each source it holds.
	left map[string][]snapshot.Skip
	held map[string]int
	// kinds gives each resource's kind, from the coverage.
	kinds map[string]string
}

// goSkipSource reads the source a skip reason names: the reasons are the
// capture's own formats (snapshot.FluxKustomizationFormat and its like).
var goSkipSource = regexp.MustCompile(`^(?:rendered by (Flux HelmRelease)|applied by (Flux Kustomization)|managed by (Argo CD application)|composed by (Crossplane composite)) ([^;]+);`)

func goReadKube(s snapshot.Snapshot) *goKube {
	k := &goKube{left: map[string][]snapshot.Skip{}, held: map[string]int{}, kinds: map[string]string{}}
	for _, c := range s.Coverage {
		k.kinds[c.Resource] = c.Kind
	}
	for _, o := range s.Objects {
		d := &goDoc{body: o.Body, snapshot: true}
		labels := goMap(o.Body, "metadata", "labels")
		ann := goMap(o.Body, "metadata", "annotations")
		// As the capture reads them (internal/kube: renderedBy).
		switch {
		case goStr(labels, "helm.toolkit.fluxcd.io/name") != "":
			d.by = []string{goFluxHR + " " + goStr(labels, "helm.toolkit.fluxcd.io/namespace") + "/" + goStr(labels, "helm.toolkit.fluxcd.io/name")}
		case goStr(labels, "kustomize.toolkit.fluxcd.io/name") != "":
			d.by = []string{goFluxKS + " " + goStr(labels, "kustomize.toolkit.fluxcd.io/namespace") + "/" + goStr(labels, "kustomize.toolkit.fluxcd.io/name")}
		case goStr(labels, "argocd.argoproj.io/instance") != "":
			d.by = []string{"Argo CD application " + goStr(labels, "argocd.argoproj.io/instance")}
		case goStr(ann, "argocd.argoproj.io/tracking-id") != "":
			d.by = []string{"Argo CD application " + strings.SplitN(goStr(ann, "argocd.argoproj.io/tracking-id"), ":", 2)[0]}
		case goStr(labels, "crossplane.io/composite") != "":
			d.by = []string{"Crossplane composite " + goStr(labels, "crossplane.io/composite")}
		}
		for _, by := range d.by {
			k.held[by]++
		}
		if f := goFluxOf(d); f != nil {
			f.definedIn = "the Kubernetes snapshot"
			k.roots = append(k.roots, f)
		}
		k.docs = append(k.docs, d)
	}
	for _, sk := range s.Skips {
		if m := goSkipSource.FindStringSubmatch(sk.Reason); m != nil {
			src := m[1] + m[2] + m[3] + m[4] + " " + m[5]
			k.left[src] = append(k.left[src], sk)
		}
	}
	return k
}

// goWorkloads are the kinds that run something.
var goWorkloads = map[string]bool{"Deployment": true, "StatefulSet": true, "DaemonSet": true, "CronJob": true, "Job": true, "Pod": true}

// goSources lists every Flux source either input names, with how much of
// what it applies could be read, and the workloads no source applies.
func goSources(g *GitOpsReport, r *goRepo, k *goKube, docs []*goDoc) {
	byID := map[string]*GitOpsSource{}
	var order []string
	get := func(id string) *GitOpsSource {
		if byID[id] == nil {
			byID[id] = &GitOpsSource{Source: id, Checked: goNotAvailable}
			order = append(order, id)
		}
		return byID[id]
	}
	fluxFiles := map[string]map[string]bool{}
	if r != nil {
		for _, f := range r.flux {
			s := get(f.id())
			s.Path = f.path
			if f.files == nil {
				s.Why = f.why
				continue
			}
			s.Checked, s.Why = goFiles, ""
			if fluxFiles[f.id()] == nil {
				fluxFiles[f.id()] = map[string]bool{}
			}
			for file := range f.files {
				fluxFiles[f.id()][file] = true
			}
		}
	}
	// A HelmRelease whose own object was read: its values were, its
	// chart was not.
	for _, d := range docs {
		if d.group() != goHRGroup || d.kind() != "HelmRelease" || d.notApplied {
			continue
		}
		s := get(goFluxHR + " " + d.ns() + "/" + d.name())
		s.Checked = goValuesOnly
		s.Why = "its chart's templates and the chart's own default values were not read: only spec.values"
		if l, _ := goMap(d.body, "spec")["valuesFrom"].([]any); len(l) > 0 {
			s.Why += fmt.Sprintf("; %d valuesFrom reference(s) to a ConfigMap or Secret were not followed", len(l))
		}
	}
	if k != nil {
		for _, f := range k.roots {
			if s := get(f.id()); s.Path == "" {
				s.Path = f.path
			}
		}
		for _, id := range goSortedSet(goKeysOf(k.left)) {
			s := get(id)
			s.LeftOut = len(k.left[id])
			if fluxFiles[id] == nil {
				continue
			}
			// Which of the objects it applies are in its files.
			have := map[string]bool{}
			for _, d := range docs {
				if d.file != "" && fluxFiles[id][d.file] && d.kind() != "" {
					have[d.kind()+"|"+d.str("metadata", "namespace")+"|"+d.name()] = true
				}
			}
			for _, sk := range k.left[id] {
				kind := k.kinds[sk.Resource]
				if have[kind+"|"+sk.Namespace+"|"+sk.Name] {
					s.Found++
					continue
				}
				// A file that names no namespace takes the one its
				// kustomization gives it.
				bare := false
				for _, d := range docs {
					bare = bare || d.file != "" && fluxFiles[id][d.file] && d.kind() == kind && d.name() == sk.Name && d.str("metadata", "namespace") == ""
				}
				if bare {
					s.Found++
					continue
				}
				if kind == "" {
					kind = sk.Resource
				}
				s.NotFound = append(s.NotFound, strings.TrimSuffix(kind+" "+sk.Namespace, " ")+"/"+sk.Name)
			}
			sort.Strings(s.NotFound)
		}
		for id, n := range k.held {
			s := get(id)
			if s.Checked == goNotAvailable && s.LeftOut == 0 {
				s.Checked = goInSnapshot
				s.Why = fmt.Sprintf("the %d object(s) of it that the snapshot holds were read", n)
			}
		}
		// What no source applies.
		byNS := map[string][]string{}
		for _, d := range k.docs {
			if len(d.by) == 0 && goWorkloads[d.kind()] {
				byNS[d.ns()] = append(byNS[d.ns()], d.kind()+" "+d.name())
			}
		}
		for _, ns := range goSortedSet(goKeysOf(byNS)) {
			sort.Strings(byNS[ns])
			g.NotInGit = append(g.NotInGit, GitOpsNamespace{Namespace: ns, Workloads: byNS[ns]})
		}
	}
	sort.Strings(order)
	for _, id := range order {
		s := byID[id]
		if s.Checked == goNotAvailable && s.Why == "" {
			switch {
			case strings.HasPrefix(id, goFluxHR):
				s.Why = "its HelmRelease is in neither the snapshot nor the files read"
			case strings.HasPrefix(id, goFluxKS) && r == nil:
				s.Why = "the snapshot leaves out what it applies, and no checkout of its repository was given (--gitops)"
			case strings.HasPrefix(id, goFluxKS):
				s.Why = "no Kustomization of this name is defined in the files this cluster's Flux applies"
			default:
				s.Why = "only Flux's sources are followed"
			}
		}
		g.Sources = append(g.Sources, *s)
	}
}

// goNotSeen says what was read, and everything that was not.
func goNotSeen(g *GitOpsReport, s *goScan, r *goRepo, k *goKube, in GitOpsInput) {
	say := func(format string, a ...any) { g.NotSeen = append(g.NotSeen, fmt.Sprintf(format, a...)) }
	if k != nil {
		left := 0
		for _, l := range k.left {
			left += len(l)
		}
		g.Read = append(g.Read, fmt.Sprintf("a Kubernetes snapshot: %d object(s), and %d more the capture left to %d GitOps source(s)", len(k.docs), left, len(k.left)))
	} else {
		say("No Kubernetes snapshot was given (--kube): which sources the cluster has, and what runs in it that is in no repository, were not checked.")
	}
	if r != nil {
		g.Read = append(g.Read, fmt.Sprintf("a checkout of the repository: %d YAML document(s) in %d file(s), and %d other text file(s)", r.yamlDocs, r.yamlFiles, len(r.files)-r.yamlFiles))
	} else {
		say("No checkout of the repository Flux reads was given (--gitops): a Kubernetes snapshot leaves out what Flux applies, so none of that was checked.")
	}
	var missing []string
	for _, src := range g.Sources {
		if src.Checked == goNotAvailable {
			missing = append(missing, src.Source)
		}
	}
	if len(missing) > 0 {
		say("%d source(s) whose content was not available to check: %s.", len(missing), strings.Join(missing, ", "))
	}
	values, notFound := 0, 0
	for _, src := range g.Sources {
		if src.Checked == goValuesOnly {
			values++
		}
		notFound += len(src.NotFound)
	}
	if values > 0 {
		say("%d HelmRelease(s) were read by their values only: what a chart's templates render, and the defaults in the chart, were not.", values)
	}
	if notFound > 0 {
		say("%d object(s) the capture left to a Kustomization are not in the files read for it (generated by a chart or a generator, or from somewhere else): not checked. Each is named under its source.", notFound)
	}
	if r != nil {
		say("The files were read as written, not built: what a kustomize patch, replacement, name prefix or generator changes is not seen, and a reference is listed where it is written, which may be a base several overlays share.")
		if r.rooted {
			n := 0
			for _, ref := range g.References {
				if ref.NotApplied {
					n++
				}
			}
			if n > 0 {
				say("%d reference(s) are in files this cluster's Flux does not apply, followed from the Kustomization(s) the snapshot holds: listed, and not counted.", n)
			}
		} else if k != nil {
			say("The snapshot holds no Flux Kustomization to start from: every Kustomization the files define was followed, whether or not this cluster has it.")
		} else {
			say("Without a Kubernetes snapshot every Flux Kustomization the files define was followed: one repository may serve several clusters, and this does not tell them apart.")
		}
		if s.substituted > 0 {
			say("%d value(s) hold a ${...} that Flux fills in after the build (postBuild): read as written, so a registry or host given that way is seen only where the variable is defined in these files.", s.substituted)
		}
		if s.automations > 0 {
			say("Flux image automation (%d ImageUpdateAutomation) rewrites image references in Git: those listed are the ones in this checkout.", s.automations)
		}
		if r.remote > 0 {
			say("%d kustomize resource(s) are fetched from a URL: not read.", r.remote)
		}
		if r.inflated > 0 {
			say("%d chart(s) are inflated by kustomize (helmCharts): not rendered.", r.inflated)
		}
		if len(r.outside) > 0 {
			say("%d kustomize entr(ies) point at a path that is not in the checkout: %s.", len(r.outside), strings.Join(r.outside, "; "))
		}
		if len(r.asText) > 0 {
			sort.Strings(r.asText)
			say("%d file(s) are not YAML as written (a chart's templates): read line by line for Azure host names only: %s.", len(r.asText), strings.Join(r.asText, ", "))
		}
		if len(r.skipped) > 0 {
			sort.Strings(r.skipped)
			say("%d file(s) larger than %d MiB were not read: %s.", len(r.skipped), goMaxFileSize>>20, strings.Join(r.skipped, ", "))
		}
		say("Only the checkout as it is was read: no other branch, and no other repository a source may read.")
	}
	if s.encrypted > 0 {
		say("%d document(s) are encrypted with SOPS: their values cannot be read.", s.encrypted)
	}
	if s.unknownStores > 0 {
		say("%d ExternalSecret(s) read a store that is not among what was read: whether it is a Key Vault's cannot be told.", s.unknownStores)
	}
	say("Secret values are in neither input: a connection string or address kept in a Secret, or in the secret store, still names Azure and is not listed.")
	say("What the applications' own code and images name is not visible here.")
	for _, src := range g.Sources {
		if !strings.HasPrefix(src.Source, "Flux ") {
			say("Only Flux's sources are followed: Argo CD applications and Crossplane composites are named, and what they apply is not read.")
			break
		}
	}
}
