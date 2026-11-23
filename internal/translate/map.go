package translate

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"
)

// Map is the only per-customer input: where each service class goes, and
// what a destination needs that the source cannot say. Every field is
// chosen by a person; none has a default.
type Map struct {
	// To is the target cloud: aws or gcp.
	To string `json:"to"`
	// Region is the region the cloud objects are for: required on AWS,
	// and on GCP wherever something regional (a subnetwork, a bucket's
	// location) is written.
	Region string `json:"region,omitempty"`
	// Destinations chooses, per service class, where it goes. A class with
	// objects in the snapshot and no choice is refused.
	Destinations struct {
		// Messaging: sqs-sns (aws), pubsub (gcp) or rabbitmq (in the
		// cluster, on either).
		Messaging string `json:"messaging,omitempty"`
		// Network: vpc (a VPC on AWS, a VPC network on GCP).
		Network string `json:"network,omitempty"`
		// Secrets: secret-manager (AWS Secrets Manager, GCP Secret
		// Manager), for Key Vault secrets.
		Secrets string `json:"secrets,omitempty"`
		// Registry: ecr (aws) or artifact-registry (gcp), for container
		// registries.
		Registry string `json:"registry,omitempty"`
		// Storage: buckets (an S3 bucket on AWS, a Cloud Storage bucket
		// on GCP, per blob container).
		Storage string `json:"storage,omitempty"`
		// DNS: route53 (aws) or cloud-dns (gcp), for Azure's public and
		// private DNS zones.
		DNS string `json:"dns,omitempty"`
		// Databases: rds (aws) or cloud-sql (gcp), for Azure Database for
		// PostgreSQL flexible servers and Azure SQL servers.
		Databases string `json:"databases,omitempty"`
		// Clusters: eks (aws) or gke (gcp), for AKS clusters. Their
		// workloads travel through the Kubernetes snapshot, not this.
		Clusters string `json:"clusters,omitempty"`
		// Identity: workload (map_identity.go).
		Identity string `json:"identity,omitempty"`
	} `json:"destinations"`
	// Secrets is what GCP's Secret Manager needs that Key Vault cannot say.
	Secrets *SecretsMap `json:"secrets,omitempty"`
	// Network is what the network destination needs that Azure cannot
	// say.
	Network *NetworkMap `json:"network,omitempty"`
	// Databases is what each database server needs on the target that
	// Azure cannot say, keyed by its group/server.
	Databases map[string]DatabaseMap `json:"databases,omitempty"`
	// Clusters is what each AKS cluster needs on the target that Azure
	// cannot say, keyed group/cluster.
	Clusters map[string]ClusterMap `json:"clusters,omitempty"`
	// PrivateAccess is where a service perimeter goes, for the Google
	// services only one closes to the internet (map_perimeter.go).
	PrivateAccess *PrivateAccessMap `json:"privateAccess,omitempty"`
	// RabbitMQ is needed when messaging goes to rabbitmq.
	RabbitMQ *RabbitMQ `json:"rabbitmq,omitempty"`
	// Sessions says how a Service Bus session queue is carried over: fifo
	// (aws: FIFO queues, the session ID as the message group),
	// ordering (gcp: ordered delivery, the session ID as the ordering
	// key), or single-active-consumer (rabbitmq: one consumer at a time,
	// which keeps order but not per-session parallelism). Without it a
	// session queue is refused: each of these changes how the app sends.
	Sessions string `json:"sessions,omitempty"`
	// Names gives a target name to a source object, keyed as the report
	// names its source ("<group>/<namespace>/<queue>"): for a name the
	// target does not allow, or two that would collide.
	Names map[string]string `json:"names,omitempty"`
	// Prefixes gives every queue and topic of a Service Bus namespace
	// (keyed group/namespace) a prefix on the target. Two namespaces are
	// one account, project or cluster there, so the names they share
	// collide: a prefix for one of them tells them all apart at once. A
	// name under names is used as it is.
	Prefixes map[string]string `json:"prefixes,omitempty"`
}

// NetworkMap is what networks need on the target.
type NetworkMap struct {
	// Zone is the AWS availability zone every subnet goes in, and Zones
	// one per subnet, keyed group/network/subnet. An Azure subnet spans
	// the region's zones; an AWS one is in a single zone, so which one is
	// a choice.
	Zone  string            `json:"zone,omitempty"`
	Zones map[string]string `json:"zones,omitempty"`
	// Egress gives each network (group/network) whose subnets reach the
	// internet through a NAT the public subnet AWS puts NAT gateways in.
	Egress map[string]EgressMap `json:"egress,omitempty"`
	// DefaultOutbound says what Azure's default outbound access becomes:
	// nat (a NAT gateway on AWS, Cloud NAT on GCP, which are billed).
	// Without it such a subnet has no internet egress on the target.
	DefaultOutbound string `json:"defaultOutbound,omitempty"`
	// NSGs names the network (group/network) a network security group
	// (group/nsg) is written in when nothing in the snapshot uses it.
	NSGs map[string]string `json:"nsgs,omitempty"`
	// FlowLogs is where flow logs go on the target.
	FlowLogs *FlowLogsMap `json:"flowLogs,omitempty"`
}

// SecretsMap is what secrets need on GCP.
type SecretsMap struct {
	// Replication is where Secret Manager keeps a secret's data:
	// automatic (where Google chooses) or user-managed (only in
	// Locations). A Key Vault is in one region and says nothing of this,
	// and it cannot be changed once a secret is made, so it is a choice.
	Replication string `json:"replication,omitempty"`
	// Locations are the regions a user-managed secret is kept in.
	Locations []string `json:"locations,omitempty"`
}

// DatabaseMap is what one database server needs on the target. An Azure
// SKU names Azure's hardware, not a target's, so the size is always the
// map's: nothing here is worked out from the source.
type DatabaseMap struct {
	// InstanceClass is the RDS DB instance class (db.m6g.large). AWS only.
	InstanceClass string `json:"instanceClass,omitempty"`
	// Tier is the Cloud SQL machine tier (db-custom-2-8192, or
	// db-perf-optimized-N-4 for Enterprise Plus). GCP only.
	Tier string `json:"tier,omitempty"`
	// Subnets are subnets of a translated network (group/network/subnet)
	// the instance is placed in, with a PostgreSQL server's delegated
	// subnet. RDS needs subnets in two availability zones at least, and a
	// server with no delegated subnet is placed by these alone.
	Subnets []string `json:"subnets,omitempty"`
	// Edition is RDS's SQL Server engine: sqlserver-ex, sqlserver-web,
	// sqlserver-se or sqlserver-ee. AWS, SQL Server only.
	Edition string `json:"edition,omitempty"`
	// LicenseModel is RDS's SQL Server license: license-included or
	// bring-your-own-media. AWS, SQL Server only.
	LicenseModel string `json:"licenseModel,omitempty"`
	// Version is the SQL Server version, which Azure SQL Database does not
	// have: RDS's EngineVersion (16.00.4185.3.v1) on AWS, Cloud SQL's
	// databaseVersion (SQLSERVER_2022_STANDARD) on GCP. SQL Server only.
	Version string `json:"version,omitempty"`
	// StorageGB is a SQL Server instance's storage, when its databases do
	// not give their maximum sizes. SQL Server only.
	StorageGB int `json:"storageGB,omitempty"`
	// KMSKey is the key the target encrypts with, for a server encrypted
	// with the customer's own key: a KMS key ARN or alias (AWS), a Cloud
	// KMS key name (GCP). Without it such a server is encrypted with the
	// target's own key, and that is reported as widening.
	KMSKey string `json:"kmsKey,omitempty"`
	// AcceptTLSFloor accepts the target's own oldest TLS version where it
	// cannot be set to the source's (SQL Server on Cloud SQL; TLS 1.3 only
	// on RDS for SQL Server, which always takes 1.2). Set it once the
	// floor has been checked on the target: the loss is then named, and
	// not counted as widening.
	AcceptTLSFloor bool `json:"acceptTlsFloor,omitempty"`
}

// ClusterMap is what one cluster needs on the target. Identity is not
// translated (#32), so roles and service accounts are ones that exist,
// named here; VM sizes are not translated either, so each pool's machine
// is named here too.
type ClusterMap struct {
	// RoleARN (eks) is the IAM role the control plane uses, NodeRoleARN
	// the one its nodes use.
	RoleARN     string `json:"roleArn,omitempty"`
	NodeRoleARN string `json:"nodeRoleArn,omitempty"`
	// Subnets (eks) are more of the network's subnets, by
	// group/network/subnet, for the control plane: EKS takes subnets in at
	// least two availability zones, and the pools' may all be in one.
	Subnets []string `json:"subnets,omitempty"`
	// KMSKey encrypts the cluster's secrets with the customer's own key: a
	// KMS key ARN (eks) or a Cloud KMS key's name (gke).
	KMSKey string `json:"kmsKey,omitempty"`
	// PodCIDR (gke) is the pods' range, for a cluster whose pods took
	// addresses from the network's subnets (Azure CNI without overlay).
	PodCIDR string `json:"podCidr,omitempty"`
	// ServiceAccount (gke) runs the nodes of every pool that names none:
	// an email, or an account ID in the target project.
	ServiceAccount string `json:"serviceAccount,omitempty"`
	// Pools are keyed by the AKS pool's name.
	Pools map[string]PoolMap `json:"pools,omitempty"`
}

// PoolMap is what one node pool needs on the target.
type PoolMap struct {
	// InstanceType (eks) or MachineType (gke) is what each node runs on.
	InstanceType string `json:"instanceType,omitempty"`
	MachineType  string `json:"machineType,omitempty"`
	// Zones (gke) are the zones the pool's nodes go in: a GKE pool puts
	// the same number in each.
	Zones []string `json:"zones,omitempty"`
	// ServiceAccount (gke) runs this pool's nodes.
	ServiceAccount string `json:"serviceAccount,omitempty"`
	// Subnet is one of the network's subnets (group/network/subnet) for a
	// pool AKS gave a network of its own, which no snapshot holds.
	Subnet string `json:"subnet,omitempty"`
}

// clusterMap is the map's entry for a cluster (group/cluster).
func (m Map) clusterMap(key string) ClusterMap {
	for k, c := range m.Clusters {
		if strings.EqualFold(k, key) {
			return c
		}
	}
	return ClusterMap{}
}

// pool is the cluster entry's pool.
func (c ClusterMap) pool(name string) PoolMap {
	for k, p := range c.Pools {
		if strings.EqualFold(k, name) {
			return p
		}
	}
	return PoolMap{}
}

// RabbitMQ is what the in-cluster messaging destination needs.
type RabbitMQ struct {
	// Namespace is the Kubernetes namespace the brokers and their queues
	// go into.
	Namespace string `json:"namespace"`
	// Replicas is the size of each broker cluster. A quorum queue needs
	// 3 to survive the loss of one.
	Replicas int `json:"replicas"`
	// TLSSecret names a Secret in Namespace holding the brokers'
	// certificate (tls.crt, tls.key). Service Bus takes only TLS; without
	// one the brokers listen in plain text, and that is reported as
	// widening.
	TLSSecret string `json:"tlsSecret,omitempty"`
}

// ReadMap reads a map file, refusing a field it does not know: a misspelt
// choice must not read as no choice.
func ReadMap(path string) (Map, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Map{}, err
	}
	var m Map
	if err := yaml.UnmarshalStrict(b, &m); err != nil {
		return Map{}, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

var dns1123 = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

func (m Map) validate() error {
	switch m.To {
	case "aws":
		if m.Region == "" {
			return fmt.Errorf("map: to: aws needs region")
		}
	case "gcp":
	case "":
		return fmt.Errorf("map: to is required (aws or gcp)")
	default:
		return fmt.Errorf("map: to: %q is not aws or gcp", m.To)
	}
	switch d := m.Destinations.Messaging; d {
	case "", "rabbitmq":
	case "sqs-sns":
		if m.To != "aws" {
			return fmt.Errorf("map: messaging sqs-sns is an AWS destination, and to is %s", m.To)
		}
	case "pubsub":
		if m.To != "gcp" {
			return fmt.Errorf("map: messaging pubsub is a GCP destination, and to is %s", m.To)
		}
	default:
		return fmt.Errorf("map: messaging: %q is not sqs-sns, pubsub or rabbitmq", d)
	}
	if m.Destinations.Messaging == "rabbitmq" {
		switch {
		case m.RabbitMQ == nil:
			return fmt.Errorf("map: messaging rabbitmq needs rabbitmq.namespace and rabbitmq.replicas")
		case !dns1123.MatchString(m.RabbitMQ.Namespace) || len(m.RabbitMQ.Namespace) > 63:
			return fmt.Errorf("map: rabbitmq.namespace %q is not a Kubernetes namespace name", m.RabbitMQ.Namespace)
		case m.RabbitMQ.Replicas < 1:
			return fmt.Errorf("map: rabbitmq.replicas must be at least 1")
		}
	} else if m.RabbitMQ != nil {
		return fmt.Errorf("map: rabbitmq is set, and messaging does not go to rabbitmq")
	}
	if err := m.validatePerimeter(); err != nil {
		return err
	}
	switch m.Destinations.Network {
	case "", "vpc":
	default:
		return fmt.Errorf("map: network: %q is not vpc", m.Destinations.Network)
	}
	switch d := m.Destinations.DNS; d {
	case "":
	case "route53":
		if m.To != "aws" {
			return fmt.Errorf("map: dns route53 is an AWS destination, and to is %s", m.To)
		}
	case "cloud-dns":
		if m.To != "gcp" {
			return fmt.Errorf("map: dns cloud-dns is a GCP destination, and to is %s", m.To)
		}
	default:
		return fmt.Errorf("map: dns: %q is not route53 or cloud-dns", d)
	}
	if m.Network != nil {
		if m.Destinations.Network == "" {
			return fmt.Errorf("map: network is set, and destinations.network is not")
		}
		if m.To != "aws" && (m.Network.Zone != "" || len(m.Network.Zones) > 0) {
			return fmt.Errorf("map: network zones are for aws: a GCP subnetwork spans its region's zones")
		}
	}
	switch m.Destinations.Secrets {
	case "", "secret-manager":
	default:
		return fmt.Errorf("map: secrets: %q is not secret-manager", m.Destinations.Secrets)
	}
	if sm := m.Secrets; sm != nil {
		switch {
		case m.Destinations.Secrets == "":
			return fmt.Errorf("map: secrets is set, and destinations.secrets is not")
		case m.To != "gcp":
			return fmt.Errorf("map: secrets.replication is for gcp: an AWS secret is kept in its region")
		case sm.Replication == "automatic" && len(sm.Locations) > 0:
			return fmt.Errorf("map: secrets.locations are for replication user-managed")
		case sm.Replication == "user-managed" && len(sm.Locations) == 0:
			return fmt.Errorf("map: secrets.replication user-managed needs secrets.locations")
		case sm.Replication != "automatic" && sm.Replication != "user-managed":
			return fmt.Errorf("map: secrets.replication: %q is not automatic or user-managed", sm.Replication)
		}
	}
	switch d := m.Destinations.Registry; d {
	case "":
	case "ecr":
		if m.To != "aws" {
			return fmt.Errorf("map: registry ecr is an AWS destination, and to is %s", m.To)
		}
	case "artifact-registry":
		if m.To != "gcp" {
			return fmt.Errorf("map: registry artifact-registry is a GCP destination, and to is %s", m.To)
		}
	default:
		return fmt.Errorf("map: registry: %q is not ecr or artifact-registry", d)
	}
	switch m.Destinations.Storage {
	case "", "buckets":
	default:
		return fmt.Errorf("map: storage: %q is not buckets", m.Destinations.Storage)
	}
	if err := m.validateNSG(); err != nil {
		return err
	}
	if err := m.validateRouting(); err != nil {
		return err
	}
	if err := m.validateDatabases(); err != nil {
		return err
	}
	if err := m.validateClusters(); err != nil {
		return err
	}
	if err := m.validateIdentity(); err != nil {
		return err
	}
	want := map[string]string{"sqs-sns": "fifo", "pubsub": "ordering", "rabbitmq": "single-active-consumer"}[m.Destinations.Messaging]
	if m.Sessions != "" && m.Sessions != want {
		return fmt.Errorf("map: sessions: %q does not go with messaging %s (it takes %q)", m.Sessions, m.Destinations.Messaging, want)
	}
	return nil
}

var (
	rdsClass    = regexp.MustCompile(`^db\.[a-z0-9]+\.[a-z0-9]+$`)
	sqlTier     = regexp.MustCompile(`^db-[a-z0-9-]+$`)
	rdsEditions = map[string]bool{"sqlserver-ex": true, "sqlserver-web": true, "sqlserver-se": true, "sqlserver-ee": true}
	sqlLicense  = map[string]bool{"license-included": true, "bring-your-own-media": true}
)

func (m Map) validateDatabases() error {
	switch d := m.Destinations.Databases; d {
	case "":
		if len(m.Databases) > 0 {
			return fmt.Errorf("map: databases is set, and destinations.databases is not")
		}
		return nil
	case "rds":
		if m.To != "aws" {
			return fmt.Errorf("map: databases rds is an AWS destination, and to is %s", m.To)
		}
	case "cloud-sql":
		if m.To != "gcp" {
			return fmt.Errorf("map: databases cloud-sql is a GCP destination, and to is %s", m.To)
		}
	default:
		return fmt.Errorf("map: databases: %q is not rds or cloud-sql", d)
	}
	for k, d := range m.Databases {
		f := "map: databases." + k + "."
		switch {
		case m.To == "aws" && d.Tier != "":
			return fmt.Errorf("%stier is Cloud SQL's; on AWS the size is instanceClass", f)
		case m.To == "gcp" && (d.InstanceClass != "" || d.Edition != "" || d.LicenseModel != ""):
			return fmt.Errorf("%sinstanceClass, edition and licenseModel are RDS's; on GCP the size is tier and the edition is in version", f)
		case d.InstanceClass != "" && !rdsClass.MatchString(d.InstanceClass):
			return fmt.Errorf("%sinstanceClass: %q is not an RDS instance class (db.m6g.large)", f, d.InstanceClass)
		case d.Tier != "" && !sqlTier.MatchString(d.Tier):
			return fmt.Errorf("%stier: %q is not a Cloud SQL tier (db-custom-2-8192)", f, d.Tier)
		case d.Edition != "" && !rdsEditions[d.Edition]:
			return fmt.Errorf("%sedition: %q is not sqlserver-ex, sqlserver-web, sqlserver-se or sqlserver-ee", f, d.Edition)
		case d.LicenseModel != "" && !sqlLicense[d.LicenseModel]:
			return fmt.Errorf("%slicenseModel: %q is not license-included or bring-your-own-media", f, d.LicenseModel)
		case d.StorageGB < 0:
			return fmt.Errorf("%sstorageGB must be positive", f)
		}
		for _, s := range d.Subnets {
			if strings.Count(s, "/") != 2 {
				return fmt.Errorf("%ssubnets: %q is not group/network/subnet", f, s)
			}
		}
	}
	return nil
}

func (m Map) validateClusters() error {
	switch d := m.Destinations.Clusters; d {
	case "":
		if len(m.Clusters) > 0 {
			return fmt.Errorf("map: clusters is set, and destinations.clusters is not")
		}
		return nil
	case "eks", "gke":
		if want := map[string]string{"eks": "aws", "gke": "gcp"}[d]; m.To != want {
			return fmt.Errorf("map: clusters %s is a%s destination, and to is %s", d, map[string]string{"aws": "n AWS", "gcp": " GCP"}[want], m.To)
		}
	default:
		return fmt.Errorf("map: clusters: %q is not eks or gke", d)
	}
	for _, k := range sortedMapKeys(m.Clusters) {
		c := m.Clusters[k]
		var wrong []string
		if m.Destinations.Clusters == "eks" {
			if c.PodCIDR != "" {
				wrong = append(wrong, "podCidr")
			}
			if c.ServiceAccount != "" {
				wrong = append(wrong, "serviceAccount")
			}
			for _, pn := range sortedMapKeys(c.Pools) {
				p := c.Pools[pn]
				if p.MachineType != "" || len(p.Zones) > 0 || p.ServiceAccount != "" {
					wrong = append(wrong, "pools."+pn+" (machineType, zones, serviceAccount)")
				}
			}
		} else {
			if c.RoleARN != "" || c.NodeRoleARN != "" {
				wrong = append(wrong, "roleArn, nodeRoleArn")
			}
			if len(c.Subnets) > 0 {
				wrong = append(wrong, "subnets")
			}
			for _, pn := range sortedMapKeys(c.Pools) {
				if c.Pools[pn].InstanceType != "" {
					wrong = append(wrong, "pools."+pn+".instanceType")
				}
			}
		}
		if len(wrong) > 0 {
			return fmt.Errorf("map: clusters[%s]: %s do not go with clusters %s", k, strings.Join(wrong, ", "), m.Destinations.Clusters)
		}
	}
	return nil
}

// database is the map's entry for a server (group/server), if any.
func (m Map) database(key string) (DatabaseMap, bool) {
	for k, d := range m.Databases {
		if strings.EqualFold(k, key) {
			return d, true
		}
	}
	return DatabaseMap{}, false
}

func sortedMapKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func (m Map) destinationList() []string {
	var d []string
	if m.Destinations.Messaging != "" {
		d = append(d, "messaging: "+m.Destinations.Messaging)
	}
	if m.Destinations.Network != "" {
		d = append(d, "network: "+m.Destinations.Network)
	}
	if m.Destinations.Secrets != "" {
		d = append(d, "secrets: "+m.Destinations.Secrets)
	}
	if m.Destinations.Registry != "" {
		d = append(d, "registry: "+m.Destinations.Registry)
	}
	if m.Destinations.Storage != "" {
		d = append(d, "storage: "+m.Destinations.Storage)
	}
	if m.Destinations.DNS != "" {
		d = append(d, "dns: "+m.Destinations.DNS)
	}
	if m.Destinations.Databases != "" {
		d = append(d, "databases: "+m.Destinations.Databases)
	}
	if m.Destinations.Clusters != "" {
		d = append(d, "clusters: "+m.Destinations.Clusters)
	}
	d = append(d, m.identityDestination()...)
	sort.Strings(d)
	return d
}

// name is the map's name for a source, or the one given.
func (m Map) name(src, given string) string {
	if n, ok := m.named(src); ok {
		return n
	}
	return given
}

// named is the name the map gives a source, if it gives one.
func (m Map) named(src string) (string, bool) {
	if n, ok := m.Names[src]; ok {
		return n, true
	}
	for k, n := range m.Names {
		if strings.EqualFold(k, src) {
			return n, true
		}
	}
	return "", false
}

// sbName is the target name of a queue or topic: the map's own for it,
// or its name behind its namespace's prefix, if the map gives one.
func (m Map) sbName(e *sbEntity) string {
	if n, ok := m.named(e.key); ok {
		return n
	}
	for k, p := range m.Prefixes {
		if strings.EqualFold(k, e.group+"/"+e.ns) {
			return p + e.name
		}
	}
	return e.name
}

// zoneFor is the AWS availability zone the map gives a subnet
// (group/network/subnet), or "".
func (m Map) zoneFor(key string) string {
	if m.Network == nil {
		return ""
	}
	for k, z := range m.Network.Zones {
		if strings.EqualFold(k, key) {
			return z
		}
	}
	return m.Network.Zone
}

// NeedsAWS reports whether a destination the map chooses writes AWS
// objects, which are built from the CloudFormation registry.
func (m Map) NeedsAWS() bool {
	return m.Destinations.Messaging == "sqs-sns" || m.Destinations.Registry == "ecr" || m.Destinations.DNS == "route53" || m.Destinations.Databases == "rds" || m.Destinations.Clusters == "eks" ||
		(m.To == "aws" && (m.Destinations.Network != "" || m.Destinations.Secrets != "" || m.Destinations.Storage != "" || m.Destinations.Identity != ""))
}

// NeedsGCP reports whether a destination the map chooses writes GCP
// objects, which are checked against Google's Discovery documents.
func (m Map) NeedsGCP() bool {
	return m.Destinations.Messaging == "pubsub" || m.Destinations.Registry == "artifact-registry" || m.Destinations.DNS == "cloud-dns" || m.Destinations.Databases == "cloud-sql" || m.Destinations.Clusters == "gke" ||
		(m.To == "gcp" && (m.Destinations.Network != "" || m.Destinations.Secrets != "" || m.Destinations.Storage != "" || m.Destinations.Identity != ""))
}
