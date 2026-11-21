package translate

import "fmt"

// Identity's destination is workload: each managed identity that
// Kubernetes service accounts of a translated cluster federate to becomes
// an IAM role assumed through EKS Pod Identity (aws) or a service account
// used through workload identity federation for GKE (gcp), holding what
// the identity's data-plane role assignments gave it on the translated
// objects and nothing else (identity.go).

const identityWorkload = "workload"

func (m Map) validateIdentity() error {
	switch d := m.Destinations.Identity; d {
	case "", identityWorkload:
		return nil
	default:
		return fmt.Errorf("map: identity: %q is not %s", d, identityWorkload)
	}
}

func (m Map) identityDestination() []string {
	if m.Destinations.Identity == "" {
		return nil
	}
	return []string{"identity: " + m.Destinations.Identity}
}
