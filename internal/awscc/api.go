package awscc

import (
	"context"
	"errors"
	"strings"
)

// CloudControl is the slice of the AWS Cloud Control API StackDNA uses. One
// generic API serves every type the registry describes, which is why the
// adapter needs no per-service code. sdk.go implements it against AWS;
// Fake implements it in memory from the same schemas.
type CloudControl interface {
	// List returns one page of identifiers. model carries the parent
	// properties a parent-scoped type requires (RestApiId).
	List(ctx context.Context, typeName string, model map[string]any, token string) (ids []string, next string, err error)
	// Get returns a resource's current properties. AWS omits write-only
	// properties, so a read can never return a secret or a code bundle.
	Get(ctx context.Context, typeName, identifier string) (map[string]any, error)
	// Create creates a resource and waits for it, returning its identifier.
	Create(ctx context.Context, typeName string, desired map[string]any) (string, error)
}

// ErrUnsupported means the type cannot be used in this account or region
// (not activated, not offered there). A capture records it as not captured
// by design, not as a failure: a region without a service has nothing in it.
var ErrUnsupported = errors.New("type not available in this account or region")

// ErrNotFound means the identifier does not exist.
var ErrNotFound = errors.New("resource not found")

// Identifier joins a resource's primary identifier values the way Cloud
// Control expects compound identifiers ("RestApiId|ResourceId").
func Identifier(t *TypeInfo, props map[string]any) (string, bool) {
	parts := make([]string, 0, len(t.PrimaryIdentifier))
	for _, p := range t.PrimaryIdentifier {
		v, ok := props[p].(string)
		if !ok || v == "" {
			return "", false
		}
		parts = append(parts, v)
	}
	return strings.Join(parts, "|"), true
}
