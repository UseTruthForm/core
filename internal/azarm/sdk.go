package azarm

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/stackdna/core/internal/readonly"
)

// SDK is ARM reached with Azure's own Go SDK core: its pipeline brings
// authentication, retries (including ARM's 429 throttling with
// Retry-After) and long-running-operation polling, with no per-service
// client. Credentials come from the standard chain, so `az login` works.
//
// Verified against a real subscription by scripts/drill-azure.sh
// (2026-10-21): list, GET, synchronous and asynchronous PUT.
type SDK struct {
	sub string
	pl  runtime.Pipeline
	ep  string
}

// Versions of ARM's own management APIs used for listing.
const (
	resourcesAPI     = "2021-04-01"
	subscriptionsAPI = "2022-12-01"
)

// NewSDK connects to a subscription with the default credential chain.
func NewSDK(subscription string, readOnly bool) (*SDK, error) {
	if subscription == "" {
		return nil, fmt.Errorf("a subscription ID is required (restore and capture never guess their target)")
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure credentials: %w", err)
	}
	var opts *arm.ClientOptions
	if readOnly {
		opts = &arm.ClientOptions{ClientOptions: policy.ClientOptions{Transport: readonly.Client()}}
	}
	c, err := arm.NewClient("stackdna", "v0.1.0", cred, opts)
	if err != nil {
		return nil, err
	}
	return &SDK{sub: subscription, pl: c.Pipeline(), ep: strings.TrimRight(c.Endpoint(), "/")}, nil
}

func (s *SDK) Subscription() string { return s.sub }

func (s *SDK) url(path, apiVersion string) string {
	return s.ep + path + "?api-version=" + url.QueryEscape(apiVersion)
}

func (s *SDK) do(ctx context.Context, method, u string, body any) (*http.Response, error) {
	req, err := runtime.NewRequest(ctx, method, u)
	if err != nil {
		return nil, err
	}
	if body != nil {
		if err := runtime.MarshalAsJSON(req, body); err != nil {
			return nil, err
		}
	}
	return s.pl.Do(req)
}

func (s *SDK) getJSON(ctx context.Context, u string, v any) error {
	resp, err := s.do(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return fmt.Errorf("%s: %w", u, ErrNotFound)
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		err := runtime.NewResponseError(resp)
		// A collection a resource does not have, or a type that does not
		// support it (diagnostic settings on most types), answers 400 or
		// 405 with a recognisable code; it means "none here".
		if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusMethodNotAllowed {
			return fmt.Errorf("%w: %v", ErrNotApplicable, err)
		}
		return err
	}
	return runtime.UnmarshalAsJSON(resp, v)
}

// Tenant reads the subscription's tenant.
func (s *SDK) Tenant(ctx context.Context) (string, error) {
	var out struct {
		TenantID string `json:"tenantId"`
	}
	if err := s.getJSON(ctx, s.url("/subscriptions/"+s.sub, subscriptionsAPI), &out); err != nil {
		return "", fmt.Errorf("read subscription %s: %w", s.sub, err)
	}
	return out.TenantID, nil
}

// list follows nextLink until the last page.
func (s *SDK) list(ctx context.Context, u string) ([]Ref, error) {
	var out []Ref
	for u != "" {
		var page struct {
			Value []struct {
				ID, Type, Location, ManagedBy string
			} `json:"value"`
			NextLink string `json:"nextLink"`
		}
		if err := s.getJSON(ctx, u, &page); err != nil {
			return nil, err
		}
		for _, v := range page.Value {
			out = append(out, Ref{ID: v.ID, Type: v.Type, Location: v.Location, ManagedBy: v.ManagedBy})
		}
		u = page.NextLink
	}
	return out, nil
}

func (s *SDK) ResourceGroups(ctx context.Context) ([]Ref, error) {
	return s.list(ctx, s.url("/subscriptions/"+s.sub+"/resourcegroups", resourcesAPI))
}

func (s *SDK) Resources(ctx context.Context) ([]Ref, error) {
	return s.list(ctx, s.url("/subscriptions/"+s.sub+"/resources", resourcesAPI))
}

// APIVersions reads the provider registration: the live source of which
// API versions each type offers in this subscription.
func (s *SDK) APIVersions(ctx context.Context, namespace string) (map[string][]string, error) {
	var out struct {
		Namespace     string `json:"namespace"`
		ResourceTypes []struct {
			ResourceType string   `json:"resourceType"`
			APIVersions  []string `json:"apiVersions"`
		} `json:"resourceTypes"`
	}
	if err := s.getJSON(ctx, s.url("/subscriptions/"+s.sub+"/providers/"+namespace, resourcesAPI), &out); err != nil {
		return nil, fmt.Errorf("read provider %s: %w", namespace, err)
	}
	m := map[string][]string{}
	for _, rt := range out.ResourceTypes {
		m[strings.ToLower(out.Namespace+"/"+rt.ResourceType)] = rt.APIVersions
	}
	return m, nil
}

// List reads a collection, following nextLink.
func (s *SDK) List(ctx context.Context, path, apiVersion string) ([]map[string]any, error) {
	var out []map[string]any
	u := s.url(path, apiVersion)
	for u != "" {
		var page struct {
			Value    []map[string]any `json:"value"`
			NextLink string           `json:"nextLink"`
		}
		if err := s.getJSON(ctx, u, &page); err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
		u = page.NextLink
	}
	return out, nil
}

func (s *SDK) Get(ctx context.Context, id, apiVersion string) (map[string]any, error) {
	var out map[string]any
	if err := s.getJSON(ctx, s.url(id, apiVersion), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// putTimeout bounds one PUT. Some resources take tens of minutes; giving up
// sooner would report a failure while Azure went on creating it.
const putTimeout = 2 * time.Hour

// Put creates the resource and waits for ARM to finish, then reads it back.
func (s *SDK) Put(ctx context.Context, id, apiVersion string, body map[string]any) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, putTimeout)
	defer cancel()
	resp, err := s.do(ctx, http.MethodPut, s.url(id, apiVersion), body)
	if err != nil {
		return nil, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK, http.StatusCreated, http.StatusAccepted) {
		return nil, runtime.NewResponseError(resp)
	}
	// Only an asynchronous answer goes to the poller: 202, or a header that
	// names an operation to poll. A 200 or 201 without one is finished
	// (managed identities answer that way), and the SDK's poller refused
	// it as "invalid polling URL" in the first real drill.
	if resp.StatusCode == http.StatusAccepted || resp.Header.Get("Azure-AsyncOperation") != "" {
		p, err := runtime.NewPoller[map[string]any](resp, s.pl, nil)
		if err != nil {
			return nil, err
		}
		if _, err := p.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{Frequency: 5 * time.Second}); err != nil {
			return nil, fmt.Errorf("%s: %w", id, err)
		}
	} else {
		resp.Body.Close()
	}
	return s.settled(ctx, id, apiVersion)
}

// settled reads the resource until its provisioningState is final, for
// the resources that answer a PUT synchronously but keep provisioning.
func (s *SDK) settled(ctx context.Context, id, apiVersion string) (map[string]any, error) {
	for {
		got, err := s.Get(ctx, id, apiVersion)
		if err != nil {
			return nil, err
		}
		props, _ := got["properties"].(map[string]any)
		switch state, _ := props["provisioningState"].(string); state {
		case "", "Succeeded":
			return got, nil
		case "Failed", "Canceled":
			return nil, fmt.Errorf("%s: provisioning %s", id, state)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

var _ ARM = (*SDK)(nil)
