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
	// Region is the AWS region the cloud objects are for.
	Region string `json:"region,omitempty"`
	// Destinations chooses, per service class, where it goes. A class with
	// objects in the snapshot and no choice is refused.
	Destinations struct {
		// Messaging: sqs-sns (aws), pubsub (gcp) or rabbitmq (in the
		// cluster, on either).
		Messaging string `json:"messaging,omitempty"`
	} `json:"destinations"`
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
		if m.Region != "" {
			return fmt.Errorf("map: region is for aws; a GCP project's Pub/Sub is global")
		}
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
