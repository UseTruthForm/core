package azarm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
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

// retryOptions is the SDK's retry policy for every call: its own retry
// count and pace (3, from 0.8 seconds), so a server error costs what it
// always did, but a Retry-After of up to 2 minutes is honoured, where the
// default 60-second cap made the SDK stop at the first longer one. Longer
// throttling is waited out by getJSON, as ARM asks; one 6 retries from 2
// seconds made a persistent 500 cost 5 minutes a call (review of #36).
var retryOptions = policy.RetryOptions{MaxRetryDelay: 2 * time.Minute}

// putRetry is a write's retry policy: only a 429, which ARM sends before
// it accepts anything. A 5xx can come after a create has started, and
// sent again it can collide with it (review of #36).
var putRetry = policy.RetryOptions{StatusCodes: []int{http.StatusTooManyRequests}}

func clientOptions(readOnly bool) *arm.ClientOptions {
	o := &arm.ClientOptions{ClientOptions: policy.ClientOptions{Retry: retryOptions}}
	if readOnly {
		o.Transport = readonly.Client()
	}
	return o
}

// NewSDK connects to a subscription with the default credential chain.
func NewSDK(subscription string, readOnly bool) (*SDK, error) {
	if subscription == "" {
		return nil, fmt.Errorf("a subscription ID is required (restore and capture never guess their target)")
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure credentials: %w", err)
	}
	c, err := arm.NewClient("stackdna", "v0.1.0", cred, clientOptions(readOnly))
	if err != nil {
		return nil, err
	}
	return &SDK{sub: subscription, pl: c.Pipeline(), ep: strings.TrimRight(c.Endpoint(), "/")}, nil
}

func (s *SDK) Subscription() string { return s.sub }

// url adds the API version to a path, which may already carry a query (a
// list filtered by kind).
func (s *SDK) url(path, apiVersion string) string {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return s.ep + path + sep + "api-version=" + url.QueryEscape(apiVersion)
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

// patientWaits are the pauses before reading again what ARM still
// throttled after the SDK's own retries, each at least the Retry-After ARM
// gave, up to maxPatience. ARM throttles reads per subscription and
// principal, and each resource provider on its own behind it (Storage
// allows 100 list calls in 5 minutes); in a real subscription Service Bus
// answered 429 after the SDK's default retries. The slot the read holds
// stays taken while it waits, so the capture as a whole slows down instead
// of adding to the burst.
//
// At worst, a read ARM keeps throttling with the longest Retry-After takes
// about 25 minutes before it is reported as throttled: three rounds of the
// SDK's retries (each Retry-After up to 2 minutes) and two pauses of up to
// 5 minutes.
var patientWaits = []time.Duration{time.Minute, 2 * time.Minute}

const maxPatience = 5 * time.Minute

// getJSON reads one URL. Reads only: a write is never sent twice here.
func (s *SDK) getJSON(ctx context.Context, u string, v any) error {
	for i := 0; ; i++ {
		err := s.getOnce(ctx, u, v)
		var ae *armError
		if i == len(patientWaits) || !errors.As(err, &ae) || ae.status != http.StatusTooManyRequests {
			return err
		}
		wait := max(patientWaits[i], min(ae.retryAfter, maxPatience))
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return err
		}
	}
}

func (s *SDK) getOnce(ctx context.Context, u string, v any) error {
	resp, err := s.do(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		err := runtime.NewResponseError(resp)
		code := ""
		var re *azcore.ResponseError
		if errors.As(err, &re) {
			code = re.ErrorCode
		}
		ae := &armError{url: u, status: resp.StatusCode, code: code, msg: armMessage(resp), retryAfter: retryAfter(resp), err: err}
		if c := classifyARM(resp.StatusCode, code, ae.msg); c != nil {
			return fmt.Errorf("%w: %v", c, ae)
		}
		if resp.StatusCode == http.StatusBadRequest && code == "KindNotSpecified" {
			return fmt.Errorf("%w: %v", ErrNeedsKind, ae)
		}
		if resp.StatusCode == http.StatusBadRequest && (code == "InvalidApiVersionParameter" || strings.Contains(strings.ToLower(err.Error()), "invalid api-version")) {
			return fmt.Errorf("%w: %v", ErrAPIVersion, ae)
		}
		return ae
	}
	return runtime.UnmarshalAsJSON(resp, v)
}

// armError is a refusal in one line: the request, status, code and Azure's
// message without its per-request IDs. The SDK's own text is a multi-line
// dump of the request and response; written into coverage it made a report
// hard to read, and an Operation Id in it made two captures of an unchanged
// subscription differ. The SDK's error is kept underneath, for errors.As.
type armError struct {
	url        string
	status     int
	code       string
	msg        string
	retryAfter time.Duration // what the last answer asked for, if anything
	err        error
}

// Error keeps the status text: check reads "Forbidden" as a denial when
// the code does not say so (review of #32).
func (e *armError) Error() string {
	s := fmt.Sprintf("GET %s: %d %s", e.url, e.status, http.StatusText(e.status))
	if e.code != "" {
		s += " " + e.code
	}
	if e.msg != "" {
		s += ": " + e.msg
	}
	return s
}

func (e *armError) Unwrap() error { return e.err }

// requestIDRE matches the per-request IDs Azure puts in error messages
// ("Operation Id: '…'", "(Request ID: …)", Tracking, Correlation, Activity
// and Trace IDs) and the time the request was answered. An ID is matched
// only after a label and a separator, and only as a whole GUID or 32 hex
// digits, so a resource named "request id deadbeefcafe" keeps its name
// (review of #32).
var requestIDRE = regexp.MustCompile(`(?i)\s*[(\[]?\b(?:operation|tracking|correlation|request|activity|trace)[ _-]?id\s*[:=]\s*'?(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{32})\b'?[)\]]?\.?` +
	`|\s*\btimestamp\s*[:=]\s*'?\d{4}-\d{2}-\d{2}[ T][0-9:.]+(?:Z|[+-]\d{2}:?\d{2})?'?\.?`)

// retryAfter reads ARM's Retry-After, in seconds or as an HTTP date.
func retryAfter(resp *http.Response) time.Duration {
	v := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(time.Until(t), 0)
	}
	return 0
}

// armMessage reads ARM's error message from a response body, in the
// {"error": {"message": …}} envelope or bare. A body that is not JSON (a
// gateway's error page) gives its first 200 bytes. Either way it is one
// line, without per-request IDs.
func armMessage(resp *http.Response) string {
	b, err := runtime.Payload(resp)
	if err != nil {
		return ""
	}
	var body struct {
		Error   struct{ Message string } `json:"error"`
		Message string                   `json:"message"`
	}
	m := ""
	if json.Unmarshal(b, &body) == nil {
		m = body.Error.Message
		if m == "" {
			m = body.Message
		}
	} else {
		if len(b) > 200 {
			b = b[:200]
		}
		m = string(b)
	}
	return strings.Join(strings.Fields(requestIDRE.ReplaceAllString(m, "")), " ")
}

// classifyARM says which refusals mean "none here", by ARM's error code,
// not by status alone. A type without diagnostic settings answers
// 400 ResourceTypeNotSupported (seen in the sandbox, 2026-10-22); a list
// at an API version the provider lacks answers 404 InvalidResourceType.
// Every 400 and 404 used to read as "none here", so a list that was
// refused looked exactly like a list that was empty (review,
// 2026-10-22). nil means a real failure.
func classifyARM(status int, code, msg string) error {
	switch {
	case status == http.StatusMethodNotAllowed,
		status == http.StatusBadRequest && cannotExistHere[code],
		status == http.StatusBadRequest && unregisteredFeatureRE.MatchString(msg),
		// A data source kind the definition names but the service does
		// not implement (ApplicationInsights, SqlDataClassification).
		status == http.StatusNotImplemented && code == "DataSourceNotImplemented":
		return ErrNotApplicable
	case status == http.StatusNotFound && !notAnAbsence[code]:
		return ErrNotFound
	}
	return nil
}

// cannotExistHere are 400 codes that say the collection cannot hold
// anything for this resource, so it is "none here". In a real subscription,
// workload groups answer FeatureDisabledOnSelectedEdition on every database
// below the edition that has them, and a Recovery Services vault's
// cross-tenant mappings BMSUserErrorFeatureNotAvailable in a region without
// the feature; both read as failed, and an otherwise complete capture
// reported itself incomplete.
var cannotExistHere = map[string]bool{"ResourceTypeNotSupported": true, "FeatureDisabledOnSelectedEdition": true, "BMSUserErrorFeatureNotAvailable": true}

// unregisteredFeatureRE is ARM's answer, under the bare code BadRequest,
// for a child type behind a preview feature the subscription has not
// registered ("Agent fabric membership is not available in subscription
// ... Please register the Microsoft.ContainerService/EnableAgentFabricPreview
// feature"): without the feature there can be none.
var unregisteredFeatureRE = regexp.MustCompile(`(?i)\bregister the [\w.-]+/[\w.-]+ feature\b`)

// notAnAbsence are 404 codes that say the request was wrong, not that the
// thing is not there.
var notAnAbsence = map[string]bool{"InvalidResourceType": true, "InvalidApiVersionParameter": true, "NoRegisteredProviderFound": true, "InvalidResourceNamespace": true}

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
	ctx = policy.WithRetryOptions(ctx, putRetry)
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
