package awscc

import (
	"context"
	"errors"
	"strings"
)

// CloudControl is the slice of the AWS Cloud Control API TruthForm uses. One
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
	// Update applies a JSON Patch to a resource and waits for it.
	Update(ctx context.Context, typeName, identifier string, patch []PatchOp) error
	// Zones lists a region's Availability Zones, for restoring a snapshot
	// captured in another region.
	Zones(ctx context.Context, region string) ([]Zone, error)
	// Account returns the 12-digit ID of the account being read, so that
	// resources another account owns (AWS's own, or shared in) are told
	// apart from this account's.
	Account(ctx context.Context) (string, error)
}

// PatchOp is one RFC 6902 operation, the form Cloud Control's
// UpdateResource takes. Value is omitted only when nil (a remove), so false
// and 0 are still sent.
type PatchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value,omitempty"`
}

// ErrUnsupported means the type cannot be used in this account or region
// (not activated, not offered there). A capture records it as not captured
// by design, not as a failure: a region without a service has nothing in it.
var ErrUnsupported = errors.New("type not available in this account or region")

// ErrNotAccepted marks a write AWS refused for throttling before accepting
// it: nothing was started, so sending it again is safe. Any other error,
// a throttled status poll included, may follow a request AWS did accept,
// and sending that again could create a second resource.
var ErrNotAccepted = errors.New("refused before AWS accepted it")

// ErrNotFound means the identifier does not exist.
var ErrNotFound = errors.New("resource not found")

// ErrNotSetUp means the service has not been set up or subscribed to in
// this account (Audit Manager, Control Tower, Cloud9), so it holds nothing.
// It is not a permission gap: "not authorized to perform" stays a failure.
var ErrNotSetUp = errors.New("service not set up in this account")

// ErrNeedsInput means the type cannot be listed without input its schema
// does not declare (lifecycle hooks need an Auto Scaling group name). That
// is a stable gap in the registry, reported apart from failures so it is
// neither hidden nor mistaken for a broken run.
var ErrNeedsInput = errors.New("list needs input the schema does not declare")

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

// cleanMessage keeps the handler's own sentence and drops request IDs,
// which change on every run and would make coverage.yaml differ each time.
func cleanMessage(msg string) string {
	if i := strings.Index(msg, "Handler returned status FAILED: "); i >= 0 {
		msg = msg[i+len("Handler returned status FAILED: "):]
	} else if i := strings.LastIndex(msg, "Exception: "); i >= 0 {
		msg = msg[i+len("Exception: "):]
	}
	for _, cut := range []string{" (Service:", " (HandlerErrorCode:", ", RequestId", ", model: ResourceModel"} {
		if i := strings.Index(msg, cut); i >= 0 {
			msg = msg[:i]
		}
	}
	// Handlers' messages can run over several lines (Java stack frames);
	// one line keeps coverage.yaml and the summary readable.
	return strings.Join(strings.Fields(msg), " ")
}
