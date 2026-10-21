package awscc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol/types"
)

// SDK is CloudControl backed by AWS.
//
// Verified against a real account only for List, Get and Create on the six
// types scripts/drill-aws.sh uses (2026-10-21). Throttling across a
// full-registry capture and the long-running create path (types that take
// minutes) have not been exercised.
type SDK struct {
	c *cloudcontrol.Client
}

// NewSDK connects with the standard AWS credential chain. profile may be
// empty to use the default.
func NewSDK(ctx context.Context, profile, region string) (*SDK, error) {
	opts := []func(*config.LoadOptions) error{config.WithRegion(region)}
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("aws config: %w", err)
	}
	// A full capture lists every type in the region; the default three
	// attempts turn ordinary throttling into "list failed" coverage gaps.
	cfg.RetryMode = aws.RetryModeAdaptive
	cfg.RetryMaxAttempts = 10
	return &SDK{c: cloudcontrol.NewFromConfig(cfg)}, nil
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
		return nil, "", classify(err)
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

var _ CloudControl = (*SDK)(nil)
