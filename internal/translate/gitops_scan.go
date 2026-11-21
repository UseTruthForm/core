package translate

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	yaml3 "go.yaml.in/yaml/v3"
)

// The rules that find an Azure thing in a Kubernetes manifest. Two kinds:
// rules for an object whose fields are known (a KEDA trigger, a
// SecretProviderClass, an External Secrets store), and rules that look at
// every value and key of every document, whatever its kind, so that an
// image in a HelmRelease's values or a host in a ConfigMap is found too.

// goDoc is one YAML document of the repository, or one object of the
// Kubernetes snapshot.
type goDoc struct {
	file string // relative to the checkout; "" for a snapshot object
	body map[string]any
	// lines is the line of each value, by its path; blocks marks block
	// scalars, whose text starts on the line after.
	lines  map[string]int
	blocks map[string]bool
	// text marks a file that is not YAML as written: body holds its text
	// under one key, and only host names are looked for.
	text bool
	// by is what applies it; targetNS the namespace that source gives
	// what it applies.
	by         []string
	targetNS   string
	snapshot   bool
	notApplied bool
}

func (d *goDoc) str(keys ...string) string {
	var v any = d.body
	for _, k := range keys {
		m, _ := v.(map[string]any)
		v = m[k]
	}
	s, _ := v.(string)
	return s
}

func (d *goDoc) kind() string { return d.str("kind") }
func (d *goDoc) group() string {
	g, _, ok := strings.Cut(d.str("apiVersion"), "/")
	if !ok {
		return ""
	}
	return g
}
func (d *goDoc) name() string { return d.str("metadata", "name") }
func (d *goDoc) ns() string {
	if n := d.str("metadata", "namespace"); n != "" {
		return n
	}
	return d.targetNS
}

// object names it as the report does: Kind namespace/name.
func (d *goDoc) object() string {
	if d.kind() == "" || d.name() == "" {
		return ""
	}
	if d.ns() == "" {
		return d.kind() + " " + d.name()
	}
	return d.kind() + " " + d.ns() + "/" + d.name()
}

// The two things said of an object no source applies.
const (
	goBySnapshot = "nothing in Git: a restore recreates it from the snapshot as it is"
	goByNothing  = "no Flux Kustomization found in these files"
)

func (d *goDoc) appliedBy() string {
	switch {
	case len(d.by) > 0:
		return strings.Join(d.by, ", ")
	case d.snapshot:
		return goBySnapshot
	}
	return goByNothing
}

func (d *goDoc) lineAt(path string, s string, off int) int {
	n := strings.Count(s[:off], "\n")
	if d.text {
		return n + 1
	}
	l := d.lines[path]
	if l == 0 || !d.blocks[path] {
		return l
	}
	return l + 1 + n
}

var goPlainKey = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func goKey(path, k string) string {
	switch {
	case !goPlainKey.MatchString(k):
		return path + "[" + strconv.Quote(k) + "]"
	case path == "":
		return k
	}
	return path + "." + k
}

// goDecode turns a YAML node into plain values, recording each value's
// line by its path.
func goDecode(n *yaml3.Node, path string, d *goDoc) any {
	switch n.Kind {
	case yaml3.DocumentNode:
		if len(n.Content) == 0 {
			return nil
		}
		return goDecode(n.Content[0], path, d)
	case yaml3.AliasNode:
		return goDecode(n.Alias, path, d)
	case yaml3.MappingNode:
		m := map[string]any{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i].Value
			p := goKey(path, k)
			d.lines[p] = n.Content[i].Line
			m[k] = goDecode(n.Content[i+1], p, d)
		}
		return m
	case yaml3.SequenceNode:
		l := make([]any, 0, len(n.Content))
		for i, c := range n.Content {
			p := path + "[" + strconv.Itoa(i) + "]"
			d.lines[p] = c.Line
			l = append(l, goDecode(c, p, d))
		}
		return l
	}
	if n.Style&(yaml3.LiteralStyle|yaml3.FoldedStyle) != 0 {
		d.blocks[path] = true
	}
	var v any
	if err := n.Decode(&v); err != nil {
		return n.Value
	}
	return v
}

// goWalk calls fn for every entry of every map and every item of every
// list, keys in order. An item is given the key of its list, and item
// set.
func goWalk(v any, path, key string, fn func(path, key string, item bool, v any)) {
	switch t := v.(type) {
	case map[string]any:
		for _, k := range sortedKeys(t) {
			p := goKey(path, k)
			fn(p, k, false, t[k])
			goWalk(t[k], p, k, fn)
		}
	case []any:
		for i, c := range t {
			p := path + "[" + strconv.Itoa(i) + "]"
			fn(p, key, true, c)
			goWalk(c, p, key, fn)
		}
	}
}

func goMap(v any, keys ...string) map[string]any {
	for _, k := range keys {
		m, _ := v.(map[string]any)
		v = m[k]
	}
	m, _ := v.(map[string]any)
	return m
}

func goStr(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

// goScan applies the rules and collects the references.
type goScan struct {
	x    *goIndex
	refs []GitOpsRef
	// stores are the External Secrets stores that read a Key Vault, by
	// kind|namespace|name, with the vault's name.
	stores map[string]string
	// done are the paths of the document at hand a rule for its kind has
	// spoken for: the rules for every value leave them alone.
	done []string
	// What was seen and cannot be followed.
	substituted, unknownStores, automations, encrypted int
}

func (s *goScan) add(d *goDoc, path string, line int, what, names string, t goTarget) {
	if line == 0 {
		line = d.lines[path]
	}
	if d.text {
		path = ""
	}
	s.refs = append(s.refs, GitOpsRef{File: d.file, Line: line, Object: d.object(), AppliedBy: d.appliedBy(), Field: path,
		What: what, Names: names, State: t.state, Target: t.target, Why: t.why, Variable: t.variable, NotApplied: d.notApplied})
}

func (s *goScan) isDone(path string) bool {
	for _, p := range s.done {
		if path == p || strings.HasPrefix(path, p+".") || strings.HasPrefix(path, p+"[") {
			return true
		}
	}
	return false
}

func (s *goScan) aws() bool { return s.x.m.To == "aws" }

// store notes an External Secrets store that reads a Key Vault.
func (s *goScan) store(d *goDoc) {
	if d.group() != "external-secrets.io" || d.kind() != "SecretStore" && d.kind() != "ClusterSecretStore" {
		return
	}
	if h := goAzureHost.FindString(goStr(goMap(d.body, "spec", "provider", "azurekv"), "vaultUrl")); strings.HasSuffix(strings.ToLower(h), ".vault.azure.net") {
		ns := d.ns()
		if d.kind() == "ClusterSecretStore" {
			ns = ""
		}
		s.stores[d.kind()+"|"+ns+"|"+d.name()] = strings.ToLower(h[:strings.Index(h, ".")])
	}
}

func (s *goScan) doc(d *goDoc) {
	s.done = nil
	if _, ok := d.body["sops"].(map[string]any); ok && !d.text {
		// Encrypted with SOPS: its values are ciphertext.
		s.encrypted++
	}
	switch g, k := d.group(), d.kind(); {
	case g == "keda.sh" && (k == "ScaledObject" || k == "ScaledJob"):
		s.keda(d)
	case g == "keda.sh" && (k == "TriggerAuthentication" || k == "ClusterTriggerAuthentication"):
		s.kedaAuth(d)
	case g == "secrets-store.csi.x-k8s.io" && k == "SecretProviderClass":
		s.providerClass(d)
	case g == "external-secrets.io" && (k == "SecretStore" || k == "ClusterSecretStore"):
		s.secretStore(d)
	case g == "external-secrets.io" && k == "ExternalSecret":
		s.externalSecret(d)
	case g == "spv.no" && k == "AzureKeyVaultSecret":
		s.akv2k8s(d)
	case g == "storage.k8s.io" && k == "StorageClass":
		s.storageClass(d)
	case g == "image.toolkit.fluxcd.io" && k == "ImageUpdateAutomation":
		s.automations++
	}
	if g := d.group(); g == "azure.com" || strings.HasSuffix(g, ".azure.com") {
		// Azure Service Operator's objects, and their like: the cluster
		// makes an Azure resource from each.
		s.add(d, "apiVersion", 0, "azure object", "an object of the API group "+g, goNone("its controller makes or configures an Azure resource from inside the cluster: on the target nothing serves this type, and what it made is translated, if it is, from the Azure snapshot"))
	}
	goWalk(d.body, "", "", func(path, key string, item bool, v any) {
		if s.isDone(path) {
			return
		}
		if !item {
			s.key(d, path, key, v)
		}
		if str, ok := v.(string); ok {
			if !d.text && goSubst.MatchString(str) {
				s.substituted++
			}
			if !goNames[key] {
				s.hosts(d, path, str)
			}
		}
	})
}

// goSubst is a variable as Flux's post-build substitution reads one:
// ${name}, with a name of letters, digits and underscores.
var goSubst = regexp.MustCompile(`(^|[^$])\$\{[_A-Za-z][_A-Za-z0-9]*[}:/]`)

// goAzureHost finds a host name under one of Azure's public domains.
var goAzureHost = regexp.MustCompile(`(?i)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.(?:azurecr\.io|windows\.net|azure\.com|azure\.net|azure-api\.net|azurewebsites\.net|azureedge\.net|azurefd\.net|azmk8s\.io|azure-devices\.net|trafficmanager\.net|microsoftonline\.com|cloudapp\.net)`)

var (
	goImageTail  = regexp.MustCompile(`^/[A-Za-z0-9._/@:-]*[A-Za-z0-9]`)
	goSecretPath = regexp.MustCompile(`^(?::443)?/secrets/([0-9A-Za-z-]+)`)
	goContainer  = regexp.MustCompile(`^(?::443)?/(\$?[a-z0-9][a-z0-9-]*)`)
	goEntityPath = regexp.MustCompile(`(?i)EntityPath=([^;"'\s]+)`)
)

// goNames are keys whose value is the name of an API group, a driver or
// a controller, which may sit under one of Azure's domains and is no
// host: the rules for those keys speak for them.
var goNames = map[string]bool{"apiVersion": true, "apiGroup": true, "apiGroups": true, "group": true, "provisioner": true, "driver": true,
	"controller": true, "ingressClassName": true, "className": true, "ingressClass": true, "kubernetes.io/ingress.class": true}

// goNotAzureResources answer under Azure's domains and are no part of what
// moves: Azure DevOps hosts a Git repository wherever the cluster is.
var goNotAzureResources = map[string]bool{"dev.azure.com": true, "ssh.dev.azure.com": true, "portal.azure.com": true}

// hosts finds the Azure host names in one value.
func (s *goScan) hosts(d *goDoc, path, str string) {
	seen := map[string]bool{}
	for _, m := range goAzureHost.FindAllStringIndex(str, -1) {
		// Part of a longer name is another name. (The match starts at the
		// first letter or digit, so only its end needs looking at.)
		if m[1] < len(str) && (str[m[1]] == '-' || goAlnum(str[m[1]]) || str[m[1]] == '.' && m[1]+1 < len(str) && goAlnum(str[m[1]+1])) {
			continue
		}
		written := str[m[0]:m[1]]
		host, rest := strings.ToLower(written), str[m[1]:]
		labels := strings.Split(host, ".")
		first := labels[0]
		what, names := "endpoint", written
		var t goTarget
		switch {
		case goNotAzureResources[host]:
			continue
		case strings.HasSuffix(host, ".azurecr.io"):
			what = "image"
			tail := goImageTail.FindString(rest)
			names += tail
			if t = s.x.registry(first); t.state == GitOpsChange {
				t.target += tail
			}
		case strings.HasSuffix(host, ".servicebus.windows.net"):
			what = "messaging"
			t = s.x.broker(first)
			if ep := goEntityPath.FindStringSubmatch(str); ep != nil && t.state == GitOpsChange {
				names += " (EntityPath " + ep[1] + ")"
				e, why := s.x.entity(first, ep[1], "", "")
				if why != "" {
					e, why = s.x.entity(first, "", ep[1], "")
				}
				if why != "" {
					t = goNone(ep[1] + " is neither a queue nor a topic of Service Bus namespace " + first + " in the Azure snapshot")
				} else {
					t = s.x.messaging(e)
				}
			}
			if strings.Contains(str, "SharedAccessKey") {
				t.why = strings.TrimPrefix(t.why+"; the connection string's shared access key is not carried over: who signs in is the identity translation's", "; ")
			}
		case strings.HasSuffix(host, ".vault.azure.net"):
			what = "secret"
			if sp := goSecretPath.FindStringSubmatch(rest); sp != nil {
				names += "/secrets/" + sp[1]
				t = s.x.secret(first, sp[1])
			} else {
				t = s.x.vault(first)
			}
		case strings.HasSuffix(host, ".core.windows.net") && len(labels) >= 5:
			what = "storage"
			switch svc := labels[len(labels)-4]; svc {
			case "blob", "dfs":
				if c := goContainer.FindStringSubmatch(rest); c != nil {
					names += "/" + c[1]
					if t = s.x.bucket(first, c[1]); t.state == GitOpsChange {
						if s.aws() {
							t.why = "a bucket has its own address, not a path under an account's: s3://" + t.target
						} else {
							t.why = "a bucket has its own address, not a path under an account's: gs://" + t.target
						}
					}
				} else {
					t = s.x.account(first)
				}
			default:
				t = goNone("only blob containers are translated: the " + svc + " service of storage account " + first + " has no counterpart here")
			}
		case strings.HasSuffix(host, ".postgres.database.azure.com"), strings.HasSuffix(host, ".database.windows.net") && len(labels) == 4:
			what = "database"
			t = s.x.database(first)
		case strings.HasSuffix(host, ".microsoftonline.com"):
			what = "identity"
			t = goTarget{state: GitOpsCheck, target: "the target's own sign-in",
				why: "Microsoft Entra ID's sign-in endpoint: what reads it signs in with an Azure identity, and what that becomes is the identity translation's"}
		default:
			t = goNone("nothing the translation wrote answers in its place: the service behind this name is not translated")
		}
		if seen[names] {
			continue
		}
		seen[names] = true
		s.add(d, path, d.lineAt(path, str, m[0]), what, names, t)
	}
}

func goAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// AKS's own storage classes, by what backs them:
// https://learn.microsoft.com/azure/aks/concepts-storage#storage-classes
// with the in-tree names older clusters still carry.
var goAKSClasses = map[string]string{
	"default": "disk", "managed": "disk", "managed-premium": "disk", "managed-csi": "disk", "managed-csi-premium": "disk", "managed-csi-premium-v2": "disk",
	"azurefile": "file", "azurefile-premium": "file", "azurefile-csi": "file", "azurefile-csi-premium": "file",
	"azureblob-nfs-premium": "blob", "azureblob-fuse-premium": "blob",
}

// Azure's volume provisioners, by what backs them.
var goAzureProvisioners = map[string]string{
	"disk.csi.azure.com": "disk", "kubernetes.io/azure-disk": "disk",
	"file.csi.azure.com": "file", "kubernetes.io/azure-file": "file",
	"blob.csi.azure.com": "blob",
}

// volumes names the target's driver for a kind of volume: a hint, since
// which class a cluster has is its own.
func (s *goScan) volumes(backing string) goTarget {
	t := goTarget{state: GitOpsCheck, why: "the target cluster has no class of this name; a volume's data is not moved"}
	switch {
	case backing == "disk" && s.aws():
		// https://docs.aws.amazon.com/eks/latest/userguide/ebs-csi.html
		t.target = "a StorageClass of the EBS CSI driver (provisioner ebs.csi.aws.com; ebs.csi.eks.amazonaws.com on EKS Auto Mode)"
	case backing == "disk":
		// https://docs.cloud.google.com/kubernetes-engine/docs/how-to/persistent-volumes/gce-pd-csi-driver
		t.target = "a StorageClass of the Persistent Disk CSI driver (provisioner pd.csi.storage.gke.io)"
	case backing == "file" && s.aws():
		// https://docs.aws.amazon.com/eks/latest/userguide/efs-csi.html
		t.target = "a StorageClass of the Amazon EFS CSI driver"
	case backing == "file":
		// https://docs.cloud.google.com/filestore/docs/csi-driver
		t.target = "a StorageClass of the Filestore CSI driver (provisioner filestore.csi.storage.gke.io)"
	default:
		t.target = "a class of whichever driver mounts object storage on the target (none is named here)"
	}
	return t
}

// Ingress classes that are Azure's: Application Gateway's controller
// (https://azure.github.io/application-gateway-kubernetes-ingress/annotations/)
// and AKS's application routing add-on
// (https://learn.microsoft.com/azure/aks/app-routing).
var goAzureIngress = map[string]bool{"azure/application-gateway": true, "azure-application-gateway": true, "webapprouting.kubernetes.azure.com": true}

func (s *goScan) ingress(why string) goTarget {
	t := goTarget{state: GitOpsCheck, why: why}
	if s.aws() {
		// https://kubernetes-sigs.github.io/aws-load-balancer-controller/latest/guide/ingress/ingress_class/
		t.target = "an IngressClass of the AWS Load Balancer Controller (controller ingress.k8s.aws/alb) with its alb.ingress.kubernetes.io/ annotations, or the class of whichever ingress controller the cluster runs"
	} else {
		// https://docs.cloud.google.com/kubernetes-engine/docs/concepts/ingress
		t.target = "GKE's Ingress controller (annotation kubernetes.io/ingress.class: gce, or gce-internal) or the Gateway API, or the class of whichever ingress controller the cluster runs"
	}
	return t
}

// key applies the rules that read one key of any map: labels and
// annotations wherever they are (a pod template, a chart's values), and
// the settings charts and manifests name alike.
func (s *goScan) key(d *goDoc, path, key string, v any) {
	val, isStr := v.(string)
	switch {
	case key == "azure.workload.identity/client-id":
		// https://azure.github.io/azure-workload-identity/docs/topics/service-account-labels-and-annotations.html
		t := goTarget{state: GitOpsCheck, why: "which role or service account is the identity translation's: this names only the form the target reads"}
		if s.aws() {
			// https://docs.aws.amazon.com/eks/latest/userguide/associate-service-account-role.html
			// https://docs.aws.amazon.com/eks/latest/userguide/pod-id-association.html
			t.target = "eks.amazonaws.com/role-arn: <the role's ARN> (IAM roles for service accounts), or no annotation and an EKS Pod Identity association of the role with this service account"
		} else {
			// https://docs.cloud.google.com/kubernetes-engine/docs/how-to/workload-identity
			t.target = "iam.gke.io/gcp-service-account: <service account>@" + goProject + ".iam.gserviceaccount.com, or no annotation and roles granted to the Kubernetes service account itself (principal://iam.googleapis.com/projects/<project number>/locations/global/workloadIdentityPools/" + goProject + ".svc.id.goog/subject/ns/<namespace>/sa/<name>)"
		}
		s.add(d, path, 0, "identity", "Azure Workload Identity client ID (annotation "+key+")", t)
	case key == "azure.workload.identity/use":
		where := "EKS"
		if !s.aws() {
			where = "GKE"
		}
		s.add(d, path, 0, "identity", "Azure Workload Identity pod label "+key, goTarget{state: GitOpsCheck, target: "remove it",
			why: where + " reads no pod label: a pod has the identity of its service account, which is the identity translation's to give"})
	case strings.HasPrefix(key, "azure.workload.identity/"):
		s.add(d, path, 0, "identity", "Azure Workload Identity setting "+key, goTarget{state: GitOpsCheck, target: "remove it", why: "it configures Azure Workload Identity's webhook, which the target does not run"})
	case key == "aadpodidbinding":
		s.add(d, path, 0, "identity", "AAD Pod Identity label "+key, goTarget{state: GitOpsCheck, target: "remove it",
			why: "it binds the pod to an Azure identity; on the target a pod has the identity of its service account, which is the identity translation's to give"})
	case key == "service.beta.kubernetes.io/azure-load-balancer-internal":
		// https://cloud-provider-azure.sigs.k8s.io/topics/loadbalancer/
		if isStr && val != "true" || !isStr && v != true {
			return
		}
		t := goTarget{state: GitOpsChange, why: "nothing on the target reads Azure's annotation: applied as it is, a Service that was internal may be given a public load balancer"}
		if s.aws() {
			// https://kubernetes-sigs.github.io/aws-load-balancer-controller/latest/guide/service/annotations/
			t.target = "service.beta.kubernetes.io/aws-load-balancer-scheme: internal (AWS Load Balancer Controller; the in-tree controller reads service.beta.kubernetes.io/aws-load-balancer-internal: \"true\")"
		} else {
			// https://docs.cloud.google.com/kubernetes-engine/docs/how-to/internal-load-balancing
			t.target = "networking.gke.io/load-balancer-type: \"Internal\" (or spec.loadBalancerClass: networking.gke.io/l4-regional-internal, GKE 1.33.1 and later)"
		}
		s.add(d, path, 0, "load balancer", "annotation "+key, t)
	case strings.HasPrefix(key, "service.beta.kubernetes.io/azure-"):
		where := "the AWS Load Balancer Controller's Service annotations"
		if !s.aws() {
			where = "GKE's LoadBalancer Service parameters"
		}
		s.add(d, path, 0, "load balancer", "annotation "+key, goTarget{state: GitOpsCheck, target: "its counterpart, if any, among " + where,
			why: "an Azure load balancer setting: nothing on the target reads it, and no counterpart is named here"})
	case strings.HasPrefix(key, "appgw.ingress.kubernetes.io/"):
		s.add(d, path, 0, "ingress", "annotation "+key, s.ingress("an Application Gateway setting: it has no one-to-one counterpart, and is set again in the target controller's own terms"))
	case isStr && goAzureIngress[val] && (key == "kubernetes.io/ingress.class" || key == "ingressClassName" || key == "className" || key == "ingressClass"):
		s.add(d, path, 0, "ingress", "ingress class "+val, s.ingress("no controller on the target answers to Azure's class: the Ingress would be served by nothing"))
	case isStr && goAKSClasses[val] != "" && (key == "storageClassName" || key == "storageClass"):
		s.add(d, path, 0, "storage class", "AKS storage class "+val, s.volumes(goAKSClasses[val]))
	}
}

// storageClass: a class of the cluster's own that an Azure driver backs.
func (s *goScan) storageClass(d *goDoc) {
	if p := d.str("provisioner"); goAzureProvisioners[p] != "" {
		t := s.volumes(goAzureProvisioners[p])
		t.why = "its provisioner is Azure's, and its parameters (skuName, and the like) are that driver's: the target's driver takes its own"
		s.add(d, "provisioner", 0, "storage class", "provisioner "+p, t)
	}
}

// keda: ScaledObject and ScaledJob triggers.
//
// https://keda.sh/docs/2.17/scalers/azure-service-bus/ names the source's
// metadata; the targets' are from
// https://keda.sh/docs/2.17/scalers/aws-sqs/,
// https://keda.sh/docs/2.17/scalers/gcp-pub-sub/ and
// https://keda.sh/docs/2.17/scalers/rabbitmq-queue/.
func (s *goScan) keda(d *goDoc) {
	spec := goMap(d.body, "spec")
	if d.kind() == "ScaledJob" && spec["triggers"] == nil {
		return
	}
	triggers, _ := spec["triggers"].([]any)
	for i, raw := range triggers {
		tr, _ := raw.(map[string]any)
		typ := goStr(tr, "type")
		if !strings.HasPrefix(typ, "azure-") {
			continue
		}
		path := "spec.triggers[" + strconv.Itoa(i) + "]"
		s.done = append(s.done, path)
		if typ != "azure-servicebus" {
			s.add(d, path+".type", 0, "scaler", "KEDA trigger "+typ, goNone("no rule translates a KEDA "+typ+" trigger: what it scales on has no counterpart written here"))
			continue
		}
		md := goMap(tr, "metadata")
		queue, topic, sub, ns := goStr(md, "queueName"), goStr(md, "topicName"), goStr(md, "subscriptionName"), goStr(md, "namespace")
		names := "KEDA azure-servicebus trigger on "
		switch {
		case queue != "":
			names += "queue " + queue
		default:
			names += "topic " + topic + ", subscription " + sub
		}
		if ns != "" {
			names += " (namespace " + ns + ")"
		}
		var t goTarget
		switch {
		case queue == "" && (topic == "" || sub == ""):
			t = goNone("it names neither a queue nor a topic with its subscription, so what it scales on cannot be told here (a name given through an environment variable is not followed)")
		case goStr(md, "useRegex") == "true":
			t = goNone("it selects queues by a regular expression (useRegex), which is not followed")
		default:
			e, why := s.x.entity(ns, queue, topic, sub)
			if why != "" {
				t = goNone(why)
				break
			}
			if t = s.x.messaging(e); t.state == GitOpsChange {
				t = s.trigger(t, md, e)
			}
		}
		s.add(d, path, 0, "scaler", names, t)
	}
}

// trigger writes the target's trigger for what a Service Bus one scaled
// on. messageCount is the number of active messages per replica, 5 when
// it is not given; it is written out, since the targets' defaults differ.
func (s *goScan) trigger(t goTarget, md map[string]any, e goEntity) goTarget {
	count := goStr(md, "messageCount")
	if count == "" {
		count = "5"
	}
	act := goStr(md, "activationMessageCount")
	q := strconv.Quote
	switch s.x.m.Destinations.Messaging {
	case "sqs-sns":
		t.target = fmt.Sprintf("type: aws-sqs-queue; metadata: queueURL: %s, awsRegion: %s, queueLength: %s, scaleOnInFlight: \"false\"", t.target, q(s.x.m.Region), q(count))
		if act != "" {
			t.target += ", activationQueueLength: " + q(act)
		}
		t.why = "Service Bus counted active messages; SQS counts those in flight too unless scaleOnInFlight is false. connectionFromEnv goes; authenticationRef: a TriggerAuthentication with podIdentity.provider: aws, whose role is the identity translation's. " + goAccount + " stands for the account, not known offline"
	case "pubsub":
		t.target = fmt.Sprintf("type: gcp-pubsub; metadata: subscriptionName: %s, mode: SubscriptionSize, value: %s", t.target, q(count))
		if act != "" {
			t.target += ", activationValue: " + q(act)
		}
		t.why = "connectionFromEnv goes; authenticationRef: a TriggerAuthentication with podIdentity.provider: gcp, whose service account is the identity translation's. KEDA deprecated this scaler in 2025 for its prometheus scaler over Cloud Monitoring, and still ships it. " + goProject + " stands for the project, not known offline"
	case "rabbitmq":
		t.target = fmt.Sprintf("type: rabbitmq; metadata: queueName: %s, mode: QueueLength, value: %s", t.target, q(count))
		if act != "" {
			t.target += ", activationValue: " + q(act)
		}
		b := s.x.broker(e.ns)
		t.why = "connectionFromEnv goes; its host comes from a TriggerAuthentication (parameter host), as amqp://<user>:<password>@<host>:<port>/"
		if b.state == GitOpsChange {
			t.why += ", the brokers being at " + b.target
		}
	}
	return t
}

// kedaAuth: a TriggerAuthentication that signs in to Azure, or reads its
// parameters from a Key Vault
// (https://keda.sh/docs/2.17/concepts/authentication/).
func (s *goScan) kedaAuth(d *goDoc) {
	spec := goMap(d.body, "spec")
	if p := goStr(goMap(spec, "podIdentity"), "provider"); strings.HasPrefix(p, "azure") {
		s.done = append(s.done, "spec.podIdentity")
		t := goTarget{state: GitOpsCheck, target: "podIdentity.provider: gcp", why: "which service account is the identity translation's"}
		if s.aws() {
			t = goTarget{state: GitOpsCheck, target: "podIdentity.provider: aws (with roleArn, or identityOwner: workload)", why: "which role is the identity translation's"}
		}
		if s.x.m.Destinations.Messaging == "rabbitmq" {
			t.why += "; a rabbitmq trigger signs in with the host its TriggerAuthentication gives it (secretTargetRef, parameter host), not with a pod identity"
		}
		s.add(d, "spec.podIdentity.provider", 0, "identity", "KEDA pod identity provider "+p, t)
	}
	kv := goMap(spec, "azureKeyVault")
	if kv == nil {
		return
	}
	s.done = append(s.done, "spec.azureKeyVault")
	h := strings.ToLower(goAzureHost.FindString(goStr(kv, "vaultUri")))
	vault, _, _ := strings.Cut(h, ".")
	secrets, _ := kv["secrets"].([]any)
	for i, raw := range secrets {
		sec, _ := raw.(map[string]any)
		name := goStr(sec, "name")
		t := s.x.secret(vault, name)
		if !strings.HasSuffix(h, ".vault.azure.net") {
			t = goNone("its vaultUri is not a Key Vault's address this can read")
		}
		if t.state == GitOpsChange {
			if s.aws() {
				t.target = fmt.Sprintf("spec.awsSecretManager: region: %s, secrets[].name: %s", s.x.m.Region, t.target)
			} else {
				t.target = "spec.gcpSecretManager: secrets[].id: " + t.target
			}
			t.why = "spec.azureKeyVault goes, with its vaultUri and credentials; the parameter stays"
		}
		s.add(d, "spec.azureKeyVault.secrets["+strconv.Itoa(i)+"].name", 0, "secret", "Key Vault "+vault+" secret "+name, t)
	}
}

// providerClass: a SecretProviderClass of the Secrets Store CSI driver's
// Azure provider
// (https://azure.github.io/secrets-store-csi-driver-provider-azure/docs/getting-started/usage/).
// The targets' are from
// https://github.com/aws/secrets-store-csi-driver-provider-aws and
// https://github.com/GoogleCloudPlatform/secrets-store-csi-driver-provider-gcp.
func (s *goScan) providerClass(d *goDoc) {
	spec := goMap(d.body, "spec")
	if goStr(spec, "provider") != "azure" {
		return
	}
	s.done = append(s.done, "spec.parameters", "spec.provider")
	par := goMap(spec, "parameters")
	vault := goStr(par, "keyvaultName")
	class := s.x.vault(vault)
	if class.state == GitOpsChange {
		if s.aws() {
			class.target = fmt.Sprintf("provider: aws; parameters: region: %s, objects: a list of objectName and objectType (each is listed below)", strconv.Quote(s.x.m.Region))
			class.why = "keyvaultName, tenantID, clientID and Azure's other parameters go. Who may read the secrets is the identity translation's: IAM roles for service accounts, or usePodIdentity: \"true\" for EKS Pod Identity"
		} else {
			class.target = "provider: gcp; parameters: secrets: a list of resourceName and path (each is listed below)"
			class.why = "keyvaultName, tenantID, clientID and Azure's other parameters go. Who may read the secrets is the identity translation's"
		}
	}
	s.add(d, "spec.provider", 0, "secret", "Secrets Store provider azure, Key Vault "+vault, class)

	const path = "spec.parameters.objects"
	raw := goStr(par, "objects")
	var outer struct {
		Array []string `yaml:"array"`
	}
	if err := yaml3.Unmarshal([]byte(raw), &outer); err != nil || raw != "" && len(outer.Array) == 0 {
		s.add(d, path, 0, "secret", "the objects of Key Vault "+vault, goTarget{state: GitOpsCheck, target: "each object, by the target's name for it",
			why: "parameters.objects is not the list the Azure provider documents (array: of objectName, objectType), so its objects could not be read"})
		return
	}
	for _, item := range outer.Array {
		var o struct {
			Name    string `yaml:"objectName"`
			Type    string `yaml:"objectType"`
			Alias   string `yaml:"objectAlias"`
			Version string `yaml:"objectVersion"`
		}
		if err := yaml3.Unmarshal([]byte(item), &o); err != nil || o.Name == "" {
			continue
		}
		if o.Type == "" {
			o.Type = "secret"
		}
		line := 0
		if i := strings.Index(raw, "objectName: "+o.Name); i >= 0 {
			line = d.lineAt(path, raw, i)
		}
		file := o.Alias
		if file == "" {
			file = o.Name
		}
		var t goTarget
		if o.Type != "secret" {
			t = goNone("a Key Vault " + o.Type + ": only a vault's secrets are translated")
		} else if t = s.x.secret(vault, o.Name); t.state == GitOpsChange {
			if s.aws() {
				t.target = fmt.Sprintf("objectName: %q, objectType: \"secretsmanager\", objectAlias: %q", t.target, file)
				t.why = "objectAlias keeps the mounted file's name, which spec.secretObjects and the pod read"
			} else {
				t.target = fmt.Sprintf("resourceName: \"projects/%s/secrets/%s/versions/latest\", path: %q", goProject, t.target, file)
				t.why = "path keeps the mounted file's name, which spec.secretObjects and the pod read; " + goProject + " stands for the project, not known offline"
			}
			if o.Version != "" {
				t.why += "; its objectVersion is a Key Vault version, which is not carried over: the target's versions are its own"
			}
		}
		s.add(d, path, line, "secret", "Key Vault "+vault+" "+o.Type+" "+o.Name, t)
	}
}

// secretStore: an External Secrets store that reads a Key Vault
// (https://external-secrets.io/latest/provider/azure-key-vault/). The
// targets' are from https://external-secrets.io/latest/provider/aws-secrets-manager/
// and https://external-secrets.io/latest/provider/google-secrets-manager/.
func (s *goScan) secretStore(d *goDoc) {
	kv := goMap(d.body, "spec", "provider", "azurekv")
	if kv == nil {
		return
	}
	const path = "spec.provider.azurekv"
	s.done = append(s.done, path)
	h := strings.ToLower(goAzureHost.FindString(goStr(kv, "vaultUrl")))
	vault, _, _ := strings.Cut(h, ".")
	t := s.x.vault(vault)
	switch {
	case !strings.HasSuffix(h, ".vault.azure.net"):
		t = goNone("its vaultUrl is not a Key Vault's address this can read")
	case t.state != GitOpsChange:
	case s.aws():
		t.target = fmt.Sprintf("provider: aws: service: SecretsManager, region: %s", s.x.m.Region)
		t.why = "its auth (authType, tenantId, what it signs in with) is the identity translation's"
	default:
		t.target = "provider: gcpsm: projectID: " + goProject
		t.why = "its auth (authType, tenantId, what it signs in with) is the identity translation's; " + goProject + " stands for the project, not known offline"
	}
	s.add(d, path, 0, "secret", "External Secrets store of Key Vault "+vault, t)
}

// externalSecret: the keys an ExternalSecret reads from a Key Vault's
// store. A key says which kind of object it is with a prefix, secret/
// when it has none.
func (s *goScan) externalSecret(d *goDoc) {
	spec := goMap(d.body, "spec")
	ref := goMap(spec, "secretStoreRef")
	kind := goStr(ref, "kind")
	if kind == "" {
		kind = "SecretStore"
	}
	ns := d.ns()
	if kind == "ClusterSecretStore" {
		ns = ""
	}
	vault, ok := s.stores[kind+"|"+ns+"|"+goStr(ref, "name")]
	if !ok {
		// A file that names no namespace takes its kustomization's: the
		// store is then looked for by name, and taken when there is one.
		var found []string
		for k, v := range s.stores {
			if strings.HasPrefix(k, kind+"|") && strings.HasSuffix(k, "|"+goStr(ref, "name")) && (ns == "" || strings.Contains(k, "||")) {
				found = append(found, v)
			}
		}
		if len(found) != 1 {
			// Its store is not among what was read: whether it reads a
			// Key Vault cannot be told.
			s.unknownStores++
			return
		}
		vault = found[0]
	}
	one := func(path, key string) {
		typ, name := "secret", key
		if p, rest, ok := strings.Cut(key, "/"); ok && (p == "secret" || p == "key" || p == "cert") {
			typ, name = p, rest
		}
		var t goTarget
		if typ != "secret" {
			t = goNone("a Key Vault " + typ + ": only a vault's secrets are translated")
		} else {
			t = s.x.secret(vault, name)
		}
		s.done = append(s.done, path)
		s.add(d, path, 0, "secret", "Key Vault "+vault+" "+typ+" "+name, t)
	}
	data, _ := spec["data"].([]any)
	for i, raw := range data {
		if key := goStr(goMap(raw, "remoteRef"), "key"); key != "" {
			one(fmt.Sprintf("spec.data[%d].remoteRef.key", i), key)
		}
	}
	from, _ := spec["dataFrom"].([]any)
	for i, raw := range from {
		if key := goStr(goMap(raw, "extract"), "key"); key != "" {
			one(fmt.Sprintf("spec.dataFrom[%d].extract.key", i), key)
		}
		if goMap(raw, "find") != nil {
			sep := "/"
			if !s.aws() {
				sep = "_"
			}
			path := fmt.Sprintf("spec.dataFrom[%d].find", i)
			s.add(d, path, 0, "secret", "the secrets of Key Vault "+vault+" it finds by name or tag", goTarget{state: GitOpsCheck,
				target: "the same search over names that start with " + vault + sep,
				why:    "the target has no vault: each secret is named after its vault and its own name, so a pattern over the names must take the prefix in"})
		}
	}
}

// akv2k8s: an AzureKeyVaultSecret is read by a controller that knows
// only Key Vault.
func (s *goScan) akv2k8s(d *goDoc) {
	v := goMap(d.body, "spec", "vault")
	vault, obj := goStr(v, "name"), goMap(v, "object")
	s.done = append(s.done, "spec.vault")
	t := goNone("a Key Vault " + goStr(obj, "type") + ": only a vault's secrets are translated")
	if goStr(obj, "type") == "secret" || goStr(obj, "type") == "" {
		if t = s.x.secret(vault, goStr(obj, "name")); t.state == GitOpsChange {
			t = goNone("akv2k8s reads only Azure Key Vault: on the target the secret is " + t.target + ", for External Secrets or the Secrets Store CSI driver to read")
		}
	}
	s.add(d, "spec.vault", 0, "secret", "akv2k8s AzureKeyVaultSecret of Key Vault "+vault+", "+goStr(obj, "name"), t)
}

// goSortedSet is the keys of a set, sorted.
func goSortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
