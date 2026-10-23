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
	// List reads a collection by path, following nextLink: an extension
	// type across the subscription (.../providers/Microsoft.Authorization/
	// roleAssignments) or a child collection ({parentId}/blobServices).
	List(ctx context.Context, path, apiVersion string) ([]map[string]any, error)
}

// Ref is a listed resource.
type Ref struct {
	ID, Type, Location, ManagedBy string
}

// ErrNotFound means the resource does not exist.
var ErrNotFound = errors.New("resource not found")

// ErrNotApplicable means a collection does not exist for this resource or
// type (HTTP 400 or 405 on a list): there is nothing of that kind here.
var ErrNotApplicable = errors.New("not applicable to this resource")

// ErrAPIVersion means the request was refused for its API version at this
// scope: the subscription's diagnostic settings answer "Invalid
// api-version query string value" to the newest stable version, and only
// preview versions work there (sandbox, 2026-10-22).
var ErrAPIVersion = errors.New("API version not accepted here")

// ResourceID is a parsed ARM resource ID.
type ResourceID struct {
	// ResourceGroup is "" for a resource at subscription scope (a role
	// definition, a subscription-wide role assignment).
	Subscription, ResourceGroup string
	// Type is the full type ("Microsoft.Network/virtualNetworks/subnets")
	// and Name the matching name path ("vnet/default").
	Type, Name string
	// Scope is set for an extension resource attached to another resource:
	// a role assignment on a storage account has Scope
	// /subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/x
	// and Type Microsoft.Authorization/roleAssignments.
	Scope string
}

// ParseID parses any ARM ID in a subscription: a resource group, a
// resource (nested types included), or an extension resource at
// subscription, group or resource scope. The type and name come from after
// the last /providers/; what is before it is the scope.
func ParseID(id string) (ResourceID, error) {
	bad := fmt.Errorf("not a resource ID in a subscription: %q", id)
	lower := strings.ToLower(id)
	i := strings.LastIndex(lower, "/providers/")
	scope, rest := id, ""
	if i >= 0 {
		scope, rest = id[:i], id[i+len("/providers/"):]
	}
	sp := strings.Split(strings.Trim(scope, "/"), "/")
	if len(sp) < 2 || !strings.EqualFold(sp[0], "subscriptions") {
		return ResourceID{}, bad
	}
	r := ResourceID{Subscription: sp[1]}
	switch {
	case len(sp) == 2:
	case len(sp) == 4 && strings.EqualFold(sp[2], "resourceGroups"):
		r.ResourceGroup = sp[3]
	case len(sp) > 4 && strings.EqualFold(sp[2], "resourceGroups"):
		r.ResourceGroup, r.Scope = sp[3], scope
	default:
		return ResourceID{}, bad
	}
	if rest == "" {
		if r.ResourceGroup == "" || r.Scope != "" {
			return ResourceID{}, bad
		}
		r.Type, r.Name = groupType, r.ResourceGroup
		return r, nil
	}
	p := strings.Split(strings.Trim(rest, "/"), "/")
	if len(p) < 3 || len(p)%2 != 1 {
		return ResourceID{}, bad
	}
	types, names := []string{p[0] + "/" + p[1]}, []string{p[2]}
	for j := 3; j+1 < len(p); j += 2 {
		types = append(types, p[j])
		names = append(names, p[j+1])
	}
	r.Type, r.Name = strings.Join(types, "/"), strings.Join(names, "/")
	return r, nil
}

// base is what the provider path hangs off: the scope resource, the
// resource group, or the subscription.
func (r ResourceID) base() string {
	switch {
	case r.Scope != "":
		return r.Scope
	case r.ResourceGroup != "":
		return "/subscriptions/" + r.Subscription + "/resourceGroups/" + r.ResourceGroup
	}
	return "/subscriptions/" + r.Subscription
}

// String rebuilds the ID.
func (r ResourceID) String() string {
	if strings.EqualFold(r.Type, groupType) {
		return "/subscriptions/" + r.Subscription + "/resourceGroups/" + r.ResourceGroup
	}
	ts := strings.Split(r.Type, "/")
	ns := strings.Split(r.Name, "/")
	out := r.base() + "/providers/" + ts[0] + "/" + ts[1] + "/" + ns[0]
	for i := 2; i < len(ts) && i-1 < len(ns); i++ {
		out += "/" + ts[i] + "/" + ns[i-1]
	}
	return out
}

// Extension reports a resource whose scope is not simply its group or
// subscription, or which sits at subscription scope: everything the
// subscription's resource list does not return.
func (r ResourceID) Extension() bool { return r.Scope != "" || r.ResourceGroup == "" }

// LocalName is the name a snapshot uses: the name path for an ordinary
// resource, and for an extension resource its ID below the group or
// subscription, so assignments on two different resources cannot collide.
func (r ResourceID) LocalName() string {
	if !r.Extension() || strings.EqualFold(r.Type, groupType) {
		return r.Name
	}
	prefix := "/subscriptions/" + r.Subscription
	if r.ResourceGroup != "" {
		prefix += "/resourceGroups/" + r.ResourceGroup
	}
	return strings.TrimPrefix(r.String()[len(prefix):], "/")
}

// Namespace is the provider namespace of a type (Microsoft.Network).
func Namespace(typ string) string { ns, _, _ := strings.Cut(typ, "/"); return ns }
