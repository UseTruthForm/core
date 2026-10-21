package azarm

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ARM is the slice of Azure Resource Manager StackDNA uses: generic list,
// GET and PUT by resource ID, which serve every resource type, and the
// provider registrations, which say which API versions each type offers.
type ARM interface {
	Subscription() string
	Tenant(ctx context.Context) (string, error)
	// ResourceGroups and Resources list the subscription. Resources lists
	// tracked resources (what GET /subscriptions/{id}/resources returns).
	ResourceGroups(ctx context.Context) ([]Ref, error)
	Resources(ctx context.Context) ([]Ref, error)
	// APIVersions maps each resource type of a provider namespace, lower
	// case, to the API versions this subscription offers for it.
	APIVersions(ctx context.Context, namespace string) (map[string][]string, error)
	Get(ctx context.Context, id, apiVersion string) (map[string]any, error)
	// Put creates or replaces a resource and waits for it to finish.
	Put(ctx context.Context, id, apiVersion string, body map[string]any) (map[string]any, error)
}

// Ref is a listed resource.
type Ref struct {
	ID, Type, Location, ManagedBy string
}

// ErrNotFound means the resource does not exist.
var ErrNotFound = errors.New("resource not found")

// ResourceID is a parsed ARM resource ID.
type ResourceID struct {
	Subscription, ResourceGroup string
	// Type is the full type ("Microsoft.Network/virtualNetworks/subnets")
	// and Name the matching name path ("vnet/default").
	Type, Name string
}

// ParseID parses /subscriptions/{s}/resourceGroups/{rg}/providers/{ns}/{t}/{n}[/{t}/{n}...]
// and /subscriptions/{s}/resourceGroups/{rg}.
func ParseID(id string) (ResourceID, error) {
	p := strings.Split(strings.Trim(id, "/"), "/")
	if len(p) < 4 || !strings.EqualFold(p[0], "subscriptions") || !strings.EqualFold(p[2], "resourceGroups") {
		return ResourceID{}, fmt.Errorf("not a resource ID: %q", id)
	}
	r := ResourceID{Subscription: p[1], ResourceGroup: p[3]}
	if len(p) == 4 {
		r.Type, r.Name = "Microsoft.Resources/resourceGroups", p[3]
		return r, nil
	}
	if len(p) < 8 || !strings.EqualFold(p[4], "providers") || len(p)%2 != 0 {
		return ResourceID{}, fmt.Errorf("not a resource ID: %q", id)
	}
	types, names := []string{p[5] + "/" + p[6]}, []string{p[7]}
	for i := 8; i+1 < len(p); i += 2 {
		types = append(types, p[i])
		names = append(names, p[i+1])
	}
	r.Type, r.Name = strings.Join(types, "/"), strings.Join(names, "/")
	return r, nil
}

// String rebuilds the ID.
func (r ResourceID) String() string {
	base := "/subscriptions/" + r.Subscription + "/resourceGroups/" + r.ResourceGroup
	if strings.EqualFold(r.Type, "Microsoft.Resources/resourceGroups") {
		return base
	}
	ts := strings.Split(r.Type, "/")
	ns := strings.Split(r.Name, "/")
	out := base + "/providers/" + ts[0] + "/" + ts[1] + "/" + ns[0]
	for i := 2; i < len(ts) && i-1 < len(ns); i++ {
		out += "/" + ts[i] + "/" + ns[i-1]
	}
	return out
}

// Namespace is the provider namespace of a type (Microsoft.Network).
func Namespace(typ string) string { ns, _, _ := strings.Cut(typ, "/"); return ns }
