package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/usetruthform/core/internal/readonly"
)

// SDK is the API reached with Application Default Credentials (gcloud auth
// application-default login) and plain HTTPS; every URL and body comes
// from a Discovery document, so there is no per-service client.
//
// Verified against a real project by scripts/drill-gcp.sh (2026-10-21):
// Cloud Asset Inventory listing, GET, and wrapped and direct creates.
type SDK struct {
	project string
	hc      *http.Client
}

// NewSDK connects to a project.
func NewSDK(ctx context.Context, project string, readOnly bool) (*SDK, error) {
	if project == "" {
		return nil, fmt.Errorf("a project ID is required (capture and restore never guess their target)")
	}
	creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return nil, fmt.Errorf("google credentials (run: gcloud auth application-default login): %w", err)
	}
	var base http.RoundTripper
	if readOnly {
		base = readonly.Transport(nil)
	}
	hc := &http.Client{Transport: &oauth2.Transport{Source: creds.TokenSource, Base: base}}
	return &SDK{project: project, hc: hc}, nil
}

func (s *SDK) Project() string { return s.project }

func (s *SDK) ProjectNumber(ctx context.Context) (string, error) {
	var out struct {
		ProjectNumber string `json:"projectNumber"`
	}
	if err := s.do(ctx, "GET", "https://cloudresourcemanager.googleapis.com/v1/projects/"+s.project, nil, &out); err != nil {
		return "", fmt.Errorf("read project %s: %w", s.project, err)
	}
	return out.ProjectNumber, nil
}

// Assets pages through Cloud Asset Inventory's resource listing.
func (s *SDK) Assets(ctx context.Context) ([]Asset, error) {
	var out []Asset
	token := ""
	for {
		u := "https://cloudasset.googleapis.com/v1/projects/" + s.project + "/assets?contentType=RESOURCE&pageSize=1000"
		if token != "" {
			u += "&pageToken=" + url.QueryEscape(token)
		}
		var page struct {
			Assets []struct {
				Name      string `json:"name"`
				AssetType string `json:"assetType"`
				Resource  struct {
					Version              string `json:"version"`
					DiscoveryDocumentURI string `json:"discoveryDocumentUri"`
					DiscoveryName        string `json:"discoveryName"`
				} `json:"resource"`
			} `json:"assets"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := s.do(ctx, "GET", u, nil, &page); err != nil {
			return nil, fmt.Errorf("Cloud Asset Inventory: %w", err)
		}
		for _, a := range page.Assets {
			out = append(out, Asset{Name: a.Name, Type: a.AssetType, DiscoveryURI: a.Resource.DiscoveryDocumentURI,
				Version: a.Resource.Version, DiscoveryName: a.Resource.DiscoveryName})
		}
		if page.NextPageToken == "" {
			return out, nil
		}
		token = page.NextPageToken
	}
}

// Call sends a request; a long-running operation is polled until done and
// its result returned.
func (s *SDK) Call(ctx context.Context, method, u string, body any) (map[string]any, error) {
	var out map[string]any
	if err := s.do(ctx, method, u, body, &out); err != nil {
		return nil, err
	}
	if isComputeOperation(out) {
		return settleCompute(ctx, out, func(u string) (map[string]any, error) {
			var m map[string]any
			return m, s.do(ctx, "GET", u, nil, &m)
		}, 2*time.Second)
	}
	if !isOperation(out) {
		return out, nil
	}
	base := u[:strings.Index(u, "/v")+1] + strings.SplitN(u[strings.Index(u, "/v")+1:], "/", 2)[0] + "/"
	deadline := time.Now().Add(30 * time.Minute)
	for {
		if done, _ := out["done"].(bool); done {
			if e, ok := out["error"].(map[string]any); ok {
				return nil, fmt.Errorf("operation %v failed: %v", out["name"], e["message"])
			}
			res, _ := out["response"].(map[string]any)
			return res, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("operation %v still running after 30m; it may yet complete", out["name"])
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
		if err := s.do(ctx, "GET", base+fmt.Sprint(out["name"]), nil, &out); err != nil {
			return nil, err
		}
	}
}

// isComputeOperation recognises Compute's own operation, which answers
// every Compute write: no done field and no name under operations/, so
// isOperation misses it, and a restore would have recorded the
// operation's name ("operation-1730...") as the new resource's.
func isComputeOperation(m map[string]any) bool {
	k, _ := m["kind"].(string)
	return k == "compute#operation"
}

// settleCompute polls a Compute operation through its selfLink until its
// status is DONE, then reads the resource it names (targetLink). An
// operation can finish with errors; those are the result, not the
// resource.
func settleCompute(ctx context.Context, op map[string]any, get func(string) (map[string]any, error), every time.Duration) (map[string]any, error) {
	deadline := time.Now().Add(30 * time.Minute)
	for {
		if op["status"] == "DONE" {
			if e, ok := op["error"].(map[string]any); ok {
				var msgs []string
				errs, _ := e["errors"].([]any)
				for _, x := range errs {
					if m, ok := x.(map[string]any); ok {
						msgs = append(msgs, fmt.Sprint(m["code"], ": ", m["message"]))
					}
				}
				return nil, fmt.Errorf("operation %v failed: %s", op["name"], strings.Join(msgs, "; "))
			}
			target, _ := op["targetLink"].(string)
			if target == "" {
				return nil, fmt.Errorf("operation %v finished without naming its resource", op["name"])
			}
			return get(target)
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("operation %v still %v after 30m; it may yet complete", op["name"], op["status"])
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(every):
		}
		self, _ := op["selfLink"].(string)
		next, err := get(self)
		if err != nil {
			return nil, err
		}
		op = next
	}
}

// isOperation recognises a google.longrunning.Operation in place of the
// resource: its name is under operations/ and it carries done or metadata.
func isOperation(m map[string]any) bool {
	n, _ := m["name"].(string)
	_, hasDone := m["done"]
	_, hasMeta := m["metadata"]
	return strings.Contains(n, "operations/") && (hasDone || hasMeta)
}

func (s *SDK) do(ctx context.Context, method, u string, body, out any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		// User credentials need a quota project, or several APIs (Cloud
		// Asset Inventory among them) refuse the call.
		req.Header.Set("X-Goog-User-Project", s.project)
		resp, err := s.hc.Do(req)
		if err != nil {
			return err
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusNotFound:
			return fmt.Errorf("%s %s: %w", method, u, ErrNotFound)
		case retryable(method, resp.StatusCode, b) && attempt < maxAttempts-1:
			if err := sleepCtx(ctx, backoff(attempt, resp)); err != nil {
				// Cancelled: said as such, not as the throttling (review of #38).
				return fmt.Errorf("%s %s: HTTP %d: %s: %w", method, u, resp.StatusCode, apiError(b), err)
			}
			continue
		case resp.StatusCode >= 300:
			msg := apiError(b)
			if strings.Contains(msg, "SERVICE_DISABLED") || strings.Contains(msg, "has not been used in project") || strings.Contains(msg, "requires billing") {
				return fmt.Errorf("%w: %s", ErrUnsupported, msg)
			}
			return fmt.Errorf("%s %s: HTTP %d: %s", method, u, resp.StatusCode, msg)
		}
		if out == nil || len(b) == 0 {
			return nil
		}
		return json.Unmarshal(b, out)
	}
}

// How Google says "slow down", as it documents it: 429 RESOURCE_EXHAUSTED
// on most APIs (ErrorInfo reason RATE_LIMIT_EXCEEDED), and on Compute 403
// with reason rateLimitExceeded or userRateLimitExceeded, which refills at
// the next minute. Google asks for truncated exponential backoff with
// jitter, up to 32 or 64 seconds a wait (IAM's retry strategy), and says a
// quota that is exhausted for the day should not be retried (AIP-194).
const (
	maxAttempts = 8
	maxBackoff  = 64 * time.Second
)

var (
	sleepCtx = func(ctx context.Context, d time.Duration) error {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-t.C:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	jitter = func() time.Duration { return time.Duration(rand.Int64N(int64(time.Second))) }
	rateRE = regexp.MustCompile(`\b(?:user)?[Rr]ateLimitExceeded\b|\bRATE_LIMIT_EXCEEDED\b`)
	// A quota by its name ("limit 'Queries per day'", QueriesPerDay,
	// dailyLimitExceeded), never a bare "daily": a bucket named
	// daily-backups is not a daily quota (review of #38).
	perDayRE = regexp.MustCompile(`(?i)\bper ?day\b|PerDay|dailyLimitExceeded`)
)

// retryable reports a refusal Google documents as one to send again. A
// server error (500, 502, 503, 504) is retried only for a read: a write Google may have started can
// collide with itself. A 429 or a rate limit was refused before anything
// was done, so a write is sent again too. A quota spent for the day is not.
func retryable(method string, status int, body []byte) bool {
	if perDayRE.Match(body) {
		return false
	}
	switch {
	case status == http.StatusTooManyRequests:
		return true
	case status == http.StatusForbidden:
		return rateRE.Match(body)
	case status == http.StatusInternalServerError, status == http.StatusBadGateway,
		status == http.StatusServiceUnavailable, status == http.StatusGatewayTimeout:
		// Google retries these for idempotent calls; a write Google may
		// have started could collide with itself (review of #38).
		return method == http.MethodGet
	}
	return false
}

// backoff is 2^attempt seconds plus up to a second of jitter, at most
// maxBackoff; a Retry-After, which Google does not document but a front
// end may send, is honoured up to the same bound.
func backoff(attempt int, resp *http.Response) time.Duration {
	if s, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && s > 0 {
		return min(time.Duration(s)*time.Second, maxBackoff)
	}
	return min(time.Duration(1<<attempt)*time.Second+jitter(), maxBackoff)
}

func apiError(b []byte) string {
	var e struct {
		Error struct {
			Status  string `json:"status"`
			Message string `json:"message"`
			Details []struct {
				Reason string `json:"reason"`
			} `json:"details"`
			// Compute's older envelope names the reason here.
			Errors []struct {
				Reason string `json:"reason"`
			} `json:"errors"`
		} `json:"error"`
	}
	if json.Unmarshal(b, &e) != nil || e.Error.Message == "" {
		return strings.TrimSpace(string(b))
	}
	msg := e.Error.Message
	if e.Error.Status != "" { // Compute's envelope has none
		msg = e.Error.Status + ": " + msg
	}
	for _, d := range e.Error.Details {
		if d.Reason != "" {
			msg += " (" + d.Reason + ")"
		}
	}
	// Named, so the reason says "rate limit" to check and the report,
	// not just "403" (which reads as a denial).
	for _, d := range e.Error.Errors {
		if d.Reason != "" {
			msg += " (" + d.Reason + ")"
		}
	}
	return msg
}

var _ API = (*SDK)(nil)
