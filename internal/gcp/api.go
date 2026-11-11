package gcp

import (
	"context"
	"errors"
	"regexp"
	"strings"
)

// API is the slice of Google Cloud Truthform uses: Cloud Asset Inventory to
// list, and plain HTTP calls to each resource's own API, whose URLs and
// bodies come from its Discovery document.
type API interface {
	Project() string
	ProjectNumber(ctx context.Context) (string, error)
	// Assets lists the project's resources with Cloud Asset Inventory.
	Assets(ctx context.Context) ([]Asset, error)
	// Call sends a request and returns the decoded response; a create that
	// answers with a long-running operation is waited for.
	Call(ctx context.Context, method, url string, body any) (map[string]any, error)
}

// Asset is one resource as Cloud Asset Inventory reports it.
type Asset struct {
	// Name is the full name: //iam.googleapis.com/projects/p/serviceAccounts/x
	Name, Type string
	// DiscoveryURI, Version and DiscoveryName locate its schema.
	DiscoveryURI, Version, DiscoveryName string
}

// RelName is the name without its service prefix: projects/p/serviceAccounts/x.
func (a Asset) RelName() string {
	n := strings.TrimPrefix(a.Name, "//")
	if i := strings.Index(n, "/"); i >= 0 {
		return n[i+1:]
	}
	return n
}

// ErrNotFound means the resource does not exist.
var ErrNotFound = errors.New("resource not found")

// ErrUnsupported means the API cannot be used in this project (disabled,
// or needs billing). Reported per type, not as a failed run.
var ErrUnsupported = errors.New("API not enabled or not available in this project")

var generatedRE = regexp.MustCompile(`^([0-9]+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)

// generatedID reports a last name segment the server chose. Google's
// user-chosen IDs follow [a-z][a-z0-9-]*; server-assigned ones are numbers
// (Monitoring notification channels) or UUIDs. Such a name differs in
// every project, so the resource needs a logical name of its own.
func generatedID(relName string) bool {
	return generatedRE.MatchString(relName[strings.LastIndex(relName, "/")+1:])
}
