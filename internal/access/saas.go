package access

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"k8s.io/client-go/tools/clientcmd"

	"github.com/stackdna/core/internal/readonly"
)

func getJSON(ctx context.Context, u, token string, out any) (http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := readonly.Client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return resp.Header, fmt.Errorf("HTTP %d: %s", resp.StatusCode, firstLine(string(b)))
	}
	return resp.Header, json.Unmarshal(b, out)
}

// githubWriteScopes are classic-token scopes that write. A classic token
// needs repo and admin:org to capture an organisation at all, which is why
// a fine-grained read-only token is the recommendation.
var githubWriteScopes = []string{"repo", "admin:org", "write:org", "admin:repo_hook", "write:repo_hook", "admin:org_hook", "workflow", "delete_repo", "write:packages", "admin:enterprise"}

// GitHub reports the token's owner, kind and scopes. The token itself is
// never printed; its kind is told by its prefix.
func GitHub(ctx context.Context, token, access string) (Report, error) {
	r := Report{Platform: "github"}
	if token == "" {
		return r, fmt.Errorf("GITHUB_TOKEN is not set")
	}
	switch {
	case strings.HasPrefix(token, "github_pat_"):
		r.Kind = "fine-grained personal access token"
	case strings.HasPrefix(token, "ghp_"):
		r.Kind = "classic personal access token"
	case strings.HasPrefix(token, "gho_"), strings.HasPrefix(token, "ghu_"):
		r.Kind = "OAuth app token"
	case strings.HasPrefix(token, "ghs_"):
		r.Kind = "GitHub App installation token"
	default:
		r.Kind = "token of unknown kind"
	}
	var u struct {
		Login string `json:"login"`
	}
	h, err := getJSON(ctx, "https://api.github.com/user", token, &u)
	if err != nil {
		if r.Kind == "GitHub App installation token" {
			r.Who = "a GitHub App installation"
			r.unchecked("The installation's permissions: an installation token cannot ask")
			return r, nil
		}
		return r, fmt.Errorf("github: who am I: %w", err)
	}
	r.Who = u.Login
	if exp := h.Get("Github-Authentication-Token-Expiration"); exp != "" {
		r.fact("Expires " + exp)
	} else if r.Kind != "GitHub App installation token" {
		r.warn("The token does not expire. Give it an expiry: it can read the organisation's configuration until someone deletes it.")
	}
	if scopes, ok := h["X-Oauth-Scopes"]; ok {
		list := strings.Join(scopes, ",")
		r.fact("Scopes: " + list)
		var writes []string
		for _, s := range strings.Split(list, ",") {
			s = strings.TrimSpace(s)
			for _, w := range githubWriteScopes {
				if s == w {
					writes = append(writes, s)
				}
			}
		}
		if len(writes) > 0 && access != "restore" {
			r.warn("Scopes that write (" + strings.Join(writes, ", ") + "). A classic token cannot read an organisation's settings without them; a fine-grained token with read-only permissions can (stackdna permissions --platform github).")
		}
	} else {
		r.unchecked("The token's permissions: GitHub does not show a fine-grained token its own; the reads below show what it can read")
	}
	return r, nil
}

// Cloudflare reports whether the token is active and when it expires.
func Cloudflare(ctx context.Context, token, account string) (Report, error) {
	r := Report{Platform: "cloudflare", Kind: "API token"}
	if token == "" {
		return r, fmt.Errorf("CLOUDFLARE_API_TOKEN is not set")
	}
	var v struct {
		Result struct {
			ID        string `json:"id"`
			Status    string `json:"status"`
			ExpiresOn string `json:"expires_on"`
		} `json:"result"`
	}
	// A user's token verifies at /user, an account-owned one at its account.
	_, err := getJSON(ctx, "https://api.cloudflare.com/client/v4/user/tokens/verify", token, &v)
	if err != nil {
		if _, err2 := getJSON(ctx, "https://api.cloudflare.com/client/v4/accounts/"+account+"/tokens/verify", token, &v); err2 != nil {
			return r, fmt.Errorf("cloudflare: verify the token: %v; as an account token: %v", err, err2)
		}
		r.Kind = "account API token"
	}
	r.Who = "token " + v.Result.ID
	if v.Result.Status != "active" {
		r.warn("The token's status is " + v.Result.Status + ", not active")
	}
	if v.Result.ExpiresOn == "" {
		r.warn("The token does not expire. Give it an end date.")
	} else {
		r.fact("Expires " + v.Result.ExpiresOn)
	}
	r.unchecked("The token's permissions: Cloudflare shows them only to a token allowed to read API tokens; the reads below show what it can read")
	return r, nil
}

// Kubernetes reports the kubeconfig's view of the identity. The cluster's
// own view needs a SelfSubjectReview, which is a create request: the
// read-only guard refuses it, so it is reported as unchecked.
func Kubernetes(kubeconfig, context string) (Report, error) {
	r := Report{Platform: "kubernetes"}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	cfg, err := rules.Load()
	if err != nil {
		return r, err
	}
	name := context
	if name == "" {
		name = cfg.CurrentContext
	}
	kc, ok := cfg.Contexts[name]
	if !ok {
		return r, fmt.Errorf("kubeconfig has no context %q", name)
	}
	r.Who = kc.AuthInfo
	r.fact("Context " + name + ", cluster " + kc.Cluster)
	if ai, ok := cfg.AuthInfos[kc.AuthInfo]; ok {
		switch {
		case ai.Exec != nil:
			r.Kind = "exec plugin (" + ai.Exec.Command + ")"
		case ai.Token != "" || ai.TokenFile != "":
			r.Kind = "bearer token"
			r.warn("A bearer token in the kubeconfig: if it is a service account's long-lived token, it works until the secret holding it is deleted")
		case len(ai.ClientCertificateData) > 0 || ai.ClientCertificate != "":
			r.Kind = "client certificate"
			r.warn("A client certificate: Kubernetes cannot revoke one; it is valid until it expires")
		case ai.AuthProvider != nil:
			r.Kind = "auth provider (" + ai.AuthProvider.Name + ")"
		default:
			r.Kind = "kubeconfig user"
		}
	}
	r.unchecked("The cluster's view of who this is, and whether it may write: both need a create request (SelfSubjectReview, SelfSubjectRulesReview), which the read-only guard refuses. An administrator can ask with kubectl auth can-i --list --as and the identity's name.")
	return r, nil
}
