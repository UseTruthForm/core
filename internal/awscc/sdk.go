package awscc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ratelimit"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/stackdna/core/internal/readonly"
)

// SDK is CloudControl backed by AWS.
//
// Verified against a real account only for List, Get and Create on the six
// types scripts/drill-aws.sh uses (2026-10-21). Throttling across a
// full-registry capture and the long-running create path (types that take
// minutes) have not been exercised.
type SDK struct {
	c   *cloudcontrol.Client
	sts *sts.Client
}

// NewSDK connects with the standard AWS credential chain. profile may be
// empty to use the default.
func NewSDK(ctx context.Context, profile, region string, readOnly bool) (*SDK, error) {
	opts := []func(*config.LoadOptions) error{config.WithRegion(region)}
	if readOnly {
		opts = append(opts, config.WithHTTPClient(readonly.Client()))
	}
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("aws config: %w", err)
	}
	// The SDK retries briefly; throttling is retried by the inventory with
	// the in-flight slot released (see inv.call). What the full captures
	// taught: the default client retry budget ran dry and dropped 188 types
	// ("retry quota exceeded"), so it is removed; adaptive mode slowed the
	// whole client whenever one service throttled (52 minutes); and long
	// SDK retries held the slots while sleeping, stalling everything for 21
	// minutes on reads that fail with HTTP 500.
	cfg.Retryer = func() aws.Retryer {
		return retry.NewStandard(func(so *retry.StandardOptions) {
			so.MaxAttempts = 4
			so.RateLimiter = ratelimit.None
		})
	}
	return &SDK{c: cloudcontrol.NewFromConfig(cfg), sts: sts.NewFromConfig(cfg)}, nil
}

// Account asks STS who the caller is. It needs no permissions.
func (s *SDK) Account(ctx context.Context) (string, error) {
	out, err := s.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("identify the account: %w", err)
	}
	return aws.ToString(out.Account), nil
}

// List returns one page of identifiers.
func (s *SDK) List(ctx context.Context, typeName string, model map[string]any, token string) ([]string, string, error) {
	in := &cloudcontrol.ListResourcesInput{TypeName: &typeName}
	if token != "" {
		in.NextToken = &token
	}
	// Sent only when needed: an empty model on a type that takes none is
	// an input Cloud Control has never been seen to receive from us.
	if len(model) > 0 {
		b, _ := json.Marshal(model)
		in.ResourceModel = aws.String(string(b))
	}
	out, err := s.c.ListResources(ctx, in)
	if err != nil {
		return nil, "", classifyList(err)
	}
	ids := make([]string, 0, len(out.ResourceDescriptions))
	for _, d := range out.ResourceDescriptions {
		ids = append(ids, aws.ToString(d.Identifier))
	}
	return ids, aws.ToString(out.NextToken), nil
}

// Get reads one resource.
func (s *SDK) Get(ctx context.Context, typeName, identifier string) (map[string]any, error) {
	out, err := s.c.GetResource(ctx, &cloudcontrol.GetResourceInput{TypeName: &typeName, Identifier: &identifier})
	if err != nil {
		return nil, classify(err)
	}
	var props map[string]any
	if err := json.Unmarshal([]byte(aws.ToString(out.ResourceDescription.Properties)), &props); err != nil {
		return nil, fmt.Errorf("%s %s: properties are not JSON: %w", typeName, identifier, err)
	}
	return props, nil
}

// createTimeout bounds one create. Some types (databases, clusters) take
// tens of minutes; a restore that gave up sooner would report a failure
// while AWS went on creating the resource.
const createTimeout = 2 * time.Hour

// Create creates a resource and waits until Cloud Control reports success
// or failure, returning the handler's own message on failure.
func (s *SDK) Create(ctx context.Context, typeName string, desired map[string]any) (string, error) {
	b, err := json.Marshal(desired)
	if err != nil {
		return "", err
	}
	out, err := s.c.CreateResource(ctx, &cloudcontrol.CreateResourceInput{TypeName: &typeName, DesiredState: aws.String(string(b))})
	if err != nil {
		return "", classify(err)
	}
	ev := out.ProgressEvent
	deadline := time.Now().Add(createTimeout)
	for {
		switch ev.OperationStatus {
		case types.OperationStatusSuccess:
			return aws.ToString(ev.Identifier), nil
		case types.OperationStatusFailed, types.OperationStatusCancelComplete:
			return "", fmt.Errorf("%s create %s: %s %s", typeName, ev.OperationStatus, ev.ErrorCode, aws.ToString(ev.StatusMessage))
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("%s create still %s after %s (request %s); it may yet complete", typeName, ev.OperationStatus, createTimeout, aws.ToString(ev.RequestToken))
		}
		wait := 5 * time.Second
		if ev.RetryAfter != nil {
			if d := time.Until(*ev.RetryAfter); d > 0 {
				wait = d
			}
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(wait):
		}
		st, err := s.c.GetResourceRequestStatus(ctx, &cloudcontrol.GetResourceRequestStatusInput{RequestToken: ev.RequestToken})
		if err != nil {
			return "", fmt.Errorf("%s create: polling request %s: %w", typeName, aws.ToString(ev.RequestToken), err)
		}
		ev = st.ProgressEvent
	}
}

func classify(err error) error {
	var tnf *types.TypeNotFoundException
	var ua *types.UnsupportedActionException
	var rnf *types.ResourceNotFoundException
	switch {
	case errors.As(err, &tnf), errors.As(err, &ua):
		return fmt.Errorf("%w: %v", ErrUnsupported, err)
	case errors.As(err, &rnf):
		return fmt.Errorf("%w: %v", ErrNotFound, err)
	}
	return err
}

// The reasons a list fails because of the account rather than StackDNA are
// only in the handlers' messages; there is no error code for them. These
// patterns come from the full us-east-2 capture (2026-10-21). Anything they
// do not match stays a failure, so a new message is loud, not hidden.
var (
	needsInputRE  = regexp.MustCompile(`(?i)required property|must not be null|is required to list|is required for list|is required argument|arn is required|cannot be empty|must be provided|missing or invalid resourcemodel|should be one of arn|is not present|missing \w*identifier|\bundefined does not exist|list operation is not supported`)
	notSetUpRE    = regexp.MustCompile(`(?i)not subscribed|not registered|complete .{0,40}setup|does not have access to the|landing zone|could not assume the|not onboarded|isn['’]t onboarded|is not enabled|isn['’]t enabled|subscription does not exist|only existing .{0,60}customers|no longer available to new customers|service role not found|instance does not exist|no default admin could be found|no detector was found|must be a .{0,40}delegated administrator|account not found for the request`)
	notInRegionRE = regexp.MustCompile(`(?i)region is not supported|UnknownHostException|unable to execute http request: connect to`)
)

func classifyList(err error) error {
	err = classify(err)
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not authorized to perform"), strings.Contains(msg, "Throttling"), strings.Contains(msg, "Rate exceeded"):
		return err // a permission gap or throttling: a real failure
	case notInRegionRE.MatchString(msg):
		// The service's endpoint does not exist in this region.
		return fmt.Errorf("%w: %s", ErrUnsupported, cleanMessage(msg))
	case needsInputRE.MatchString(msg):
		return fmt.Errorf("%w: %s", ErrNeedsInput, cleanMessage(msg))
	case notSetUpRE.MatchString(msg):
		return fmt.Errorf("%w: %s", ErrNotSetUp, cleanMessage(msg))
	case errors.Is(err, ErrNotFound):
		// A list that answers "not found" has nothing to list.
		return fmt.Errorf("%w: %s", ErrNotSetUp, cleanMessage(msg))
	}
	return err
}

var _ CloudControl = (*SDK)(nil)
