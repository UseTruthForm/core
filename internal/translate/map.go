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
	// and on GCP wherever something regional (a subnetwork) is written.
	Region string `json:"region,omitempty"`
	// Destinations chooses, per service class, where it goes. A class with
	// objects in the snapshot and no choice is refused.
	Destinations struct {
		// Messaging: sqs-sns (aws), pubsub (gcp) or rabbitmq (in the
		// cluster, on either).
		Messaging string `json:"messaging,omitempty"`
		// Network: vpc (a VPC on AWS, a VPC network on GCP).
		Network string `json:"network,omitempty"`
	} `json:"destinations"`
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
	return m.Destinations.Messaging == "sqs-sns" || (m.To == "aws" && m.Destinations.Network != "")
}

// NeedsGCP reports whether a destination the map chooses writes GCP
// objects, which are checked against Google's Discovery documents.
func (m Map) NeedsGCP() bool {
	return m.Destinations.Messaging == "pubsub" || (m.To == "gcp" && m.Destinations.Network != "")
}
