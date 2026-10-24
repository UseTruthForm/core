// Package readonly refuses, at the HTTP transport, every request that could
// change a system.
//
// Capture and diff run behind it on every platform, so a capture can be
// promised to a client as read-only: not because each adapter is careful,
// but because a write cannot leave the machine. Even a bug that reached a
// create or update call would be stopped here, before any byte is sent.
//
// The rule is an allow-list. A request is let through only if it is a read
// (GET, HEAD), a credential exchange (tokens, STS), or an API whose reads
// are POSTs and whose operation is named as a read. Anything unrecognised
// is refused, so a new endpoint fails loudly instead of writing quietly.
package readonly

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ErrWrite is returned for every refused request.
var ErrWrite = errors.New("refused by StackDNA's read-only guard")

// Transport wraps base with the guard. A nil base uses http.DefaultTransport.
func Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &guard{base: base}
}

// Client returns an http.Client behind the guard.
func Client() *http.Client { return &http.Client{Transport: Transport(nil)} }

type guard struct{ base http.RoundTripper }

func (g *guard) RoundTrip(req *http.Request) (*http.Response, error) {
	if ok, why := Allowed(req); !ok {
		return nil, fmt.Errorf("%w: %s %s (%s)", ErrWrite, req.Method, redact(req.URL), why)
	}
	return g.base.RoundTrip(req)
}

// readTargets are AWS JSON-RPC operations (X-Amz-Target) that only read.
// Cloud Control sends every call as POST /; the operation is in the header.
var readTargets = map[string]bool{
	"CloudApiService.ListResources":            true,
	"CloudApiService.GetResource":              true,
	"CloudApiService.GetResourceRequestStatus": true,
	"CloudApiService.ListResourceRequests":     true,
}

// iamReads are IAM Query API actions that only read. IAM sends every call
// as a POST with the action in the form body, so it cannot be told apart by
// method; these two are named because stackdna check needs them, and every
// other IAM action stays refused. SimulatePrincipalPolicy evaluates the
// caller's policies against a list of actions and changes nothing.
var iamReads = map[string]bool{
	"GetRole":                 true,
	"SimulatePrincipalPolicy": true,
}

// tokenHosts exchange credentials for tokens; they change no resource.
var tokenHosts = []string{
	"login.microsoftonline.com",
	"oauth2.googleapis.com",
	"accounts.google.com",
	"sts.googleapis.com",
	"iamcredentials.googleapis.com",
}

// Allowed reports whether a request may pass, and why not if it may not.
func Allowed(req *http.Request) (bool, string) {
	switch req.Method {
	case http.MethodGet, http.MethodHead:
		return true, ""
	}
	host := strings.ToLower(req.URL.Hostname())
	for _, h := range tokenHosts {
		if host == h {
			return true, ""
		}
	}
	// AWS STS (GetCallerIdentity, AssumeRole for profiles) and SSO
	// credential exchange.
	if strings.HasPrefix(host, "sts.") && strings.HasSuffix(host, ".amazonaws.com") ||
		(strings.HasPrefix(host, "portal.sso.") || strings.HasPrefix(host, "oidc.")) && strings.HasSuffix(host, ".amazonaws.com") {
		return true, ""
	}
	// "aws login" sessions refresh at the sign-in service's token
	// endpoint. Without this a profile from aws login worked until its
	// cached credentials expired, then every capture failed with
	// "refused by StackDNA's read-only guard" (2026-10-23).
	if (host == "signin.aws.amazon.com" || strings.HasSuffix(host, ".signin.aws.amazon.com")) && req.Method == http.MethodPost && req.URL.Path == "/v1/token" {
		return true, ""
	}
	// The EC2 instance metadata service: a PUT for its session token.
	if host == "169.254.169.254" && req.Method == http.MethodPut && req.URL.Path == "/latest/api/token" {
		return true, ""
	}
	if req.Method == http.MethodPost {
		if t := req.Header.Get("X-Amz-Target"); t != "" {
			if readTargets[t] {
				return true, ""
			}
			return false, "AWS operation " + t + " is not a known read"
		}
		if isIAMHost(host) {
			action, err := formAction(req)
			if err != nil {
				return false, "IAM request body unreadable: " + err.Error()
			}
			if iamReads[action] {
				return true, ""
			}
			return false, "IAM action " + action + " is not a known read"
		}
		// Google's reads that are POSTs by design: Resource Manager's
		// getIamPolicy reads a policy. Google's hosts only: the suffix
		// alone let a POST to any host through (review of #23).
		if strings.HasSuffix(host, ".googleapis.com") && strings.HasSuffix(req.URL.Path, ":getIamPolicy") {
			return true, ""
		}
	}
	return false, "only reads may pass"
}

func isIAMHost(h string) bool {
	return h == "iam.amazonaws.com" || strings.HasPrefix(h, "iam.") && (strings.HasSuffix(h, ".amazonaws.com") || strings.HasSuffix(h, ".amazonaws.com.cn"))
}

// maxBody bounds the body read to find an IAM action. IAM's reads are a
// few hundred bytes; a larger body is refused, never cut short.
const maxBody = 1 << 20

// formAction is the one Action of a Query API request, read from the body.
// Any second Action, in the body or the query string, in any letter case
// or percent-encoding, makes it "": which one IAM would act on is not the
// guard's to guess, and taking the first let "Action=GetRole&action=
// CreateUser" through (review of #23). The body is put back for sending.
func formAction(req *http.Request) (string, error) {
	n := 0
	for k, vs := range req.URL.Query() {
		if strings.EqualFold(k, "action") {
			n += len(vs)
		}
	}
	if n > 0 || req.Body == nil {
		return "", nil
	}
	b, err := io.ReadAll(io.LimitReader(req.Body, maxBody+1))
	req.Body.Close()
	if err != nil {
		return "", err
	}
	if len(b) > maxBody {
		return "", fmt.Errorf("body over %d bytes", maxBody)
	}
	req.Body = io.NopCloser(bytes.NewReader(b))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
	v, err := url.ParseQuery(string(b))
	if err != nil {
		return "", err
	}
	action := ""
	for k, vs := range v {
		if strings.EqualFold(k, "action") {
			n += len(vs)
			action = vs[0]
		}
	}
	if n != 1 {
		return "", nil
	}
	return action, nil
}

// redact drops the query string, which can carry tokens.
func redact(u *url.URL) string {
	c := *u
	c.RawQuery = ""
	return c.String()
}
