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

// credentialHosts are services whose incoming-webhook URL is itself the
// credential: anyone holding it can post. Data, by host and path prefix.
var credentialHosts = []string{
	"hooks.slack.com/services/",
	"discord.com/api/webhooks/",
	"discordapp.com/api/webhooks/",
	".webhook.office.com/",
	"outlook.office.com/webhook",
	"api.telegram.org/bot",
	"hooks.zapier.com/hooks/",
	"chat.googleapis.com/v1/spaces/",
}

// credentialParams are query parameters that carry a credential.
var credentialParams = map[string]bool{
	"token": true, "access_token": true, "auth": true, "key": true, "apikey": true, "api_key": true,
	"secret": true, "client_secret": true, "password": true, "pass": true, "sig": true, "signature": true, "code": true,
}

// secretURL reports a string that is a URL carrying a credential.
func secretURL(s string) bool {
	if !strings.HasPrefix(s, "https://") && !strings.HasPrefix(s, "http://") {
		return false
	}
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	if u.User != nil {
		return true
	}
	for k := range u.Query() {
		if credentialParams[strings.ToLower(k)] {
			return true
		}
	}
	hp := strings.ToLower(u.Host + u.Path)
	for _, h := range credentialHosts {
		if strings.HasPrefix(h, ".") {
			if i := strings.Index(hp, h); i > 0 && !strings.Contains(hp[:i], "/") {
				return true
			}
		} else if strings.HasPrefix(hp, h) {
			return true
		}
	}
	return false
}

// urlName names an item whose name would be a secret URL: its host and a
// short hash of the whole URL. The same URL names the same item in every
// capture and account, so a restore still recognises it; a hash prefix of a
// token-bearing URL gives nothing usable back.
func urlName(s string) string {
	h := sha256.Sum256([]byte(s))
	host := s
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		host = u.Hostname()
	}
	return host + "~" + hex.EncodeToString(h[:6])
}
