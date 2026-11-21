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
	} `json:"destinations"`
	// Secrets is what GCP's Secret Manager needs that Key Vault cannot say.
	Secrets *SecretsMap `json:"secrets,omitempty"`
	// Network is what the network destination needs that Azure cannot
	// say.
	Network *NetworkMap `json:"network,omitempty"`
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
}

// NetworkMap is what networks need on the target.
type NetworkMap struct {
	// Zone is the AWS availability zone every subnet goes in, and Zones
	// one per subnet, keyed group/network/subnet. An Azure subnet spans
	// the region's zones; an AWS one is in a single zone, so which one is
	// a choice.
	Zone  string            `json:"zone,omitempty"`
	Zones map[string]string `json:"zones,omitempty"`
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
	switch m.Destinations.Network {
	case "", "vpc":
	default:
		return fmt.Errorf("map: network: %q is not vpc", m.Destinations.Network)
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
	want := map[string]string{"sqs-sns": "fifo", "pubsub": "ordering", "rabbitmq": "single-active-consumer"}[m.Destinations.Messaging]
	if m.Sessions != "" && m.Sessions != want {
		return fmt.Errorf("map: sessions: %q does not go with messaging %s (it takes %q)", m.Sessions, m.Destinations.Messaging, want)
	}
	return nil
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
	sort.Strings(d)
	return d
}

// name is the map's name for a source, or the one given.
func (m Map) name(src, given string) string {
	if n, ok := m.Names[src]; ok {
		return n
	}
	for k, n := range m.Names {
		if strings.EqualFold(k, src) {
			return n
		}
	}
	return given
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
	return m.Destinations.Messaging == "sqs-sns" || m.Destinations.Registry == "ecr" ||
		(m.To == "aws" && (m.Destinations.Network != "" || m.Destinations.Secrets != "" || m.Destinations.Storage != ""))
}

// NeedsGCP reports whether a destination the map chooses writes GCP
// objects, which are checked against Google's Discovery documents.
func (m Map) NeedsGCP() bool {
	return m.Destinations.Messaging == "pubsub" || m.Destinations.Registry == "artifact-registry" ||
		(m.To == "gcp" && (m.Destinations.Network != "" || m.Destinations.Secrets != "" || m.Destinations.Storage != ""))
}
