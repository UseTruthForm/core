package saas

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"
)

// A webhook URL can be a credential: Slack's /services/T…/B…/<token>,
// Discord's /api/webhooks/<id>/<token>, a ?token= or user:pass@. GitHub
// returns it in clear (only config.secret is masked), so it was written to
// snapshots, and since a webhook is named by its URL, into file names too
// (review of #12, 2026-10-22). Such a URL is treated as a secret: kept out
// of the snapshot, named in its secrets annotation, given back at restore
// with --values.

// tokenHost is a service whose incoming-webhook URL carries its token in
// the path: anyone holding the URL can post. Matched on the host (any
// subdomain, any port) and, where the host serves more than webhooks, on a
// path segment. A first version matched host and path as one prefix, and
// missed Slack's Workflow Builder URLs, canary.discord.com, Discord's
// versioned /api/v10/webhooks/, an explicit :443 and an upper-case scheme
// (review of #22).
type tokenHost struct {
	host string // the host or a parent domain
	path string // a path segment that marks a webhook; "" for any path
}

var tokenHosts = []tokenHost{
	{"hooks.slack.com", ""},
	{"discord.com", "/webhooks/"},
	{"discordapp.com", "/webhooks/"},
	{"webhook.office.com", ""},
	{"outlook.office.com", "/webhook"},
	{"api.telegram.org", "/bot"},
	{"hooks.zapier.com", ""},
	{"chat.googleapis.com", "/spaces/"},
}

// credentialParams are query parameters that carry a credential.
var credentialParams = map[string]bool{
	"token": true, "access_token": true, "auth": true, "key": true, "apikey": true, "api_key": true,
	"secret": true, "client_secret": true, "password": true, "pass": true, "sig": true, "signature": true, "code": true,
}

func parseHTTP(s string) (*url.URL, bool) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, false
	}
	sc := strings.ToLower(u.Scheme)
	return u, (sc == "https" || sc == "http") && u.Host != ""
}

// tokenInPath reports a URL of a service that puts its token in the path.
func tokenInPath(u *url.URL) bool {
	h := strings.ToLower(u.Hostname())
	p := strings.ToLower(u.Path)
	for _, t := range tokenHosts {
		if (h == t.host || strings.HasSuffix(h, "."+t.host)) && (t.path == "" || strings.Contains(p, t.path)) {
			return true
		}
	}
	return false
}

// secretURL reports a string that is a URL carrying a credential.
func secretURL(s string) bool {
	u, ok := parseHTTP(s)
	if !ok {
		return false
	}
	if u.User != nil || tokenInPath(u) {
		return true
	}
	for k := range u.Query() {
		if credentialParams[strings.ToLower(k)] {
			return true
		}
	}
	return false
}

// urlName names an item whose name would be a secret URL, the same in every
// capture and account so a restore still recognises it. Where the
// credential is only in the user info or the query, the URL without it is
// the name. Where the token is the path (Slack, Discord), the host and a
// hash of the URL are: such tokens are long and random, so the hash gives
// nothing back. A hash of a URL holding a password could be tested against
// guesses offline, so a password is never hashed (review of #22).
func urlName(s string) string {
	u, ok := parseHTTP(s)
	if !ok {
		return s
	}
	if tokenInPath(u) {
		h := sha256.Sum256([]byte(s))
		return strings.ToLower(u.Hostname()) + "~" + hex.EncodeToString(h[:6])
	}
	u.User = nil
	q := u.Query()
	for k := range q {
		if credentialParams[strings.ToLower(k)] {
			q.Del(k)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}
