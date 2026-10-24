package access

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/stackdna/core/internal/readonly"
)

var gcpReadRoles = map[string]bool{"roles/viewer": true, "roles/cloudasset.viewer": true, "roles/browser": true, "roles/iam.securityReviewer": true}

// GCP reports the application-default identity and the roles it holds on
// a project directly.
func GCP(ctx context.Context, project, access string) (Report, error) {
	r := Report{Platform: "gcp"}
	creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform", "https://www.googleapis.com/auth/userinfo.email")
	if err != nil {
		return r, fmt.Errorf("google credentials (run: gcloud auth application-default login): %w", err)
	}
	var kind struct {
		Type        string `json:"type"`
		ClientEmail string `json:"client_email"`
	}
	_ = json.Unmarshal(creds.JSON, &kind)
	member := ""
	switch kind.Type {
	case "authorized_user":
		r.Kind = "user (application-default credentials)"
	case "service_account":
		r.Kind, r.Who, member = "service account", kind.ClientEmail, "serviceAccount:"+kind.ClientEmail
		r.warn("A service account key file: a long-lived secret that works until the key is deleted. Prefer impersonation (gcloud auth application-default login --impersonate-service-account) or workload identity.")
	case "impersonated_service_account":
		r.Kind = "impersonated service account"
	case "external_account":
		r.Kind = "workload identity federation"
	case "":
		r.Kind = "metadata server (the machine's service account)"
	default:
		r.Kind = kind.Type
	}
	tok, err := creds.TokenSource.Token()
	if err != nil {
		return r, fmt.Errorf("google token: %w", err)
	}
	hc := &http.Client{Transport: &oauth2.Transport{Source: oauth2.StaticTokenSource(tok), Base: readonly.Transport(nil)}}
	do := func(method, u string, out any) error {
		var body io.Reader
		if method == "POST" {
			body = bytes.NewReader([]byte("{}"))
		}
		req, err := http.NewRequestWithContext(ctx, method, u, body)
		if err != nil {
			return err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := hc.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, firstLine(string(b)))
		}
		return json.Unmarshal(b, out)
	}
	var info struct {
		Email string `json:"email"`
	}
	infoErr := do("GET", "https://oauth2.googleapis.com/tokeninfo?access_token="+url.QueryEscape(tok.AccessToken), &info)
	if infoErr == nil && info.Email != "" {
		r.Who = info.Email
		if member == "" {
			member = "user:" + info.Email
			if strings.HasSuffix(info.Email, ".gserviceaccount.com") {
				member = "serviceAccount:" + info.Email
			}
		}
	}
	if !tok.Expiry.IsZero() {
		r.fact("Token expires " + tok.Expiry.UTC().Format("2006-01-02 15:04 MST"))
	}
	if member == "" {
		why := "the token does not say whose it is"
		if infoErr != nil {
			why = "asking whose the token is failed: " + infoErr.Error()
		}
		r.unchecked("Roles held: " + why)
		return r, nil
	}
	var pol struct {
		Bindings []struct {
			Role    string   `json:"role"`
			Members []string `json:"members"`
		} `json:"bindings"`
	}
	if err := do("POST", "https://cloudresourcemanager.googleapis.com/v1/projects/"+project+":getIamPolicy", &pol); err != nil {
		r.unchecked("Roles held on project " + project + ": " + err.Error())
		return r, nil
	}
	var held, extra []string
	for _, b := range pol.Bindings {
		for _, m := range b.Members {
			if strings.EqualFold(m, member) {
				held = append(held, b.Role)
				if !gcpReadRoles[b.Role] {
					extra = append(extra, b.Role)
				}
			}
		}
	}
	sort.Strings(held)
	sort.Strings(extra)
	r.unchecked("Roles through groups, folders or the organization: the project's policy names only direct grants")
	if len(held) == 0 {
		r.fact("Holds no role on project " + project + " directly")
		return r, nil
	}
	r.fact("Roles on project " + project + ": " + strings.Join(held, ", "))
	has := map[string]bool{}
	for _, h := range held {
		has[h] = true
	}
	switch {
	case access == "restore":
		if !has["roles/owner"] && !has["roles/editor"] {
			r.warn("A restore needs roles/editor (with roles/iam.serviceAccountAdmin and roles/iam.roleAdmin for service accounts and custom roles), or roles/owner")
		}
	case len(extra) > 0:
		r.warn("Holds " + strings.Join(extra, ", ") + ": more than a capture needs (roles/viewer and roles/cloudasset.viewer). Capture as an identity holding only those, or at least with the capture-only binary.")
	}
	if access != "restore" && (!has["roles/cloudasset.viewer"] && !has["roles/owner"]) {
		r.warn("Does not hold roles/cloudasset.viewer directly: unless it comes through a group, the capture's asset listing will be refused (403)")
	}
	return r, nil
}
