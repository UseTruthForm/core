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
	"errors"
	"fmt"
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
		strings.HasPrefix(host, "portal.sso.") || strings.HasPrefix(host, "oidc.") && strings.HasSuffix(host, ".amazonaws.com") {
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
		// Google's reads that are POSTs by design: Resource Manager's
		// getIamPolicy reads a policy.
		if strings.HasSuffix(req.URL.Path, ":getIamPolicy") {
			return true, ""
		}
	}
	return false, "only reads may pass"
}

// redact drops the query string, which can carry tokens.
func redact(u *url.URL) string {
	c := *u
	c.RawQuery = ""
	return c.String()
}
