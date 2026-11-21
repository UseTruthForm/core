package translate

import (
	"fmt"
	"regexp"
)

// PrivateAccessMap says where the VPC Service Controls perimeter goes that
// closes Pub/Sub, Secret Manager and Artifact Registry to the internet,
// for a source that answered only privately (perimeter.go). Without it no
// perimeter is written, and those stay reported as less protected.
type PrivateAccessMap struct {
	// AccessPolicy is an existing access policy, accessPolicies/<number>:
	// the organization's, or one scoped to the project or its folder. An
	// organization's administrator makes it; a translation does not.
	AccessPolicy string `json:"accessPolicy"`
	// Perimeter is the perimeter's ID in that policy, unique in it: a
	// letter, then letters, digits and underscores. A person chooses it,
	// because a second project restored under the same one would be
	// refused, or with --update take the first project's place in it.
	Perimeter string `json:"perimeter"`
	// RestoreIdentity is the principal that runs restores and captures
	// from outside the perimeter (serviceAccount:<email>, user:<email>):
	// an ingress rule admits it. RestoreFromInside says they run from one
	// of the project's own networks instead, and no rule is written. One
	// of the two is required: a perimeter with neither would refuse the
	// restore that made it its very next call.
	RestoreIdentity   string `json:"restoreIdentity,omitempty"`
	RestoreFromInside bool   `json:"restoreFromInside,omitempty"`
}

var (
	perimeterPolicy = regexp.MustCompile(`^accessPolicies/[0-9]+$`)
	// "The service_perimeter component must begin with a letter, followed
	// by alphanumeric characters or _"
	// (https://accesscontextmanager.googleapis.com/$discovery/rest?version=v1).
	perimeterID = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)
	// "user:USER_EMAIL_ADDRESS", "serviceAccount:SA_EMAIL_ADDRESS"
	// (https://docs.cloud.google.com/vpc-service-controls/docs/supported-identities).
	perimeterIdentity = regexp.MustCompile(`^(user|serviceAccount):[^@\s:]+@[^@\s:]+$`)
)

func (m Map) validatePerimeter() error {
	p := m.PrivateAccess
	switch {
	case p == nil:
		return nil
	case m.To != "gcp":
		return fmt.Errorf("map: privateAccess is for gcp (a VPC Service Controls perimeter); on aws a private service is closed by a policy of its own")
	case !perimeterPolicy.MatchString(p.AccessPolicy):
		return fmt.Errorf("map: privateAccess.accessPolicy: %q is not an access policy's name (accessPolicies/<number>, an existing one: gcloud access-context-manager policies list)", p.AccessPolicy)
	case !perimeterID.MatchString(p.Perimeter):
		return fmt.Errorf("map: privateAccess.perimeter: %q is not a perimeter ID (a letter, then letters, digits and underscores); it must be unique in the policy", p.Perimeter)
	case p.RestoreIdentity == "" && !p.RestoreFromInside:
		return fmt.Errorf("map: privateAccess needs restoreIdentity (serviceAccount:<email> or user:<email>, admitted by an ingress rule) or restoreFromInside: true: a perimeter refuses management calls from outside it too, so without one of them it would lock out the restore that wrote it, and every capture after")
	case p.RestoreIdentity != "" && p.RestoreFromInside:
		return fmt.Errorf("map: privateAccess.restoreIdentity and restoreFromInside are both set: from inside the perimeter no ingress rule is needed, and one would admit that principal from anywhere")
	case p.RestoreIdentity != "" && !perimeterIdentity.MatchString(p.RestoreIdentity):
		return fmt.Errorf("map: privateAccess.restoreIdentity: %q is not serviceAccount:<email> or user:<email>", p.RestoreIdentity)
	}
	return nil
}
