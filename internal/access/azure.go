package access

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/stackdna/core/internal/readonly"
)

// azureReadRoles are built-in roles that only read. Any other role a
// capture identity holds is reported, by name and scope.
var azureReadRoles = map[string]bool{"Reader": true, "Monitoring Reader": true, "Security Reader": true}

// Azure reports the signed-in identity (the default credential chain, as
// capture uses) and its roles in a subscription.
func Azure(ctx context.Context, subscription, access string) (Report, error) {
	r := Report{Platform: "azure"}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return r, fmt.Errorf("azure credentials: %w", err)
	}
	tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{"https://management.azure.com/.default"}})
	if err != nil {
		return r, fmt.Errorf("azure sign-in: %w", err)
	}
	c := jwtClaims(tok.Token)
	oid := claim(c, "oid")
	if claim(c, "idtyp") == "app" {
		r.Kind = "service principal"
		r.Who = "application " + claim(c, "appid", "azp")
	} else {
		r.Kind = "user"
		r.Who = claim(c, "upn", "unique_name", "preferred_username", "email")
	}
	r.fact("Object ID " + oid + ", tenant " + claim(c, "tid"))
	r.fact("Token expires " + tok.ExpiresOn.UTC().Format("2006-01-02 15:04 MST"))
	if oid == "" {
		r.unchecked("Roles held: the token carries no object ID")
		return r, nil
	}

	hc := readonly.Client()
	get := func(u string, out any) error {
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok.Token)
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
	// assignedTo includes assignments through groups, at the subscription,
	// above it and below it.
	var list struct {
		Value []struct {
			Properties struct {
				RoleDefinitionID string `json:"roleDefinitionId"`
				Scope            string `json:"scope"`
			} `json:"properties"`
		} `json:"value"`
	}
	base := "https://management.azure.com/subscriptions/" + subscription
	if err := get(base+"/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter="+url.QueryEscape("assignedTo('"+oid+"')"), &list); err != nil {
		r.unchecked("Roles held in subscription " + subscription + ": " + err.Error())
		return r, nil
	}
	names := map[string]string{}
	var held, extra []string
	for _, a := range list.Value {
		id := a.Properties.RoleDefinitionID
		if _, ok := names[id]; !ok {
			var d struct {
				Properties struct {
					RoleName string `json:"roleName"`
				} `json:"properties"`
			}
			if err := get("https://management.azure.com"+id+"?api-version=2022-04-01", &d); err != nil {
				names[id] = id[strings.LastIndex(id, "/")+1:] + " (name unreadable)"
			} else {
				names[id] = d.Properties.RoleName
			}
		}
		h := names[id] + " at " + scopeName(a.Properties.Scope, subscription)
		held = append(held, h)
		if !azureReadRoles[names[id]] {
			extra = append(extra, h)
		}
	}
	sort.Strings(held)
	sort.Strings(extra)
	if len(held) == 0 {
		r.warn("Holds no role in subscription " + subscription + ": a capture will read nothing")
		return r, nil
	}
	r.fact("Roles (including through groups): " + strings.Join(held, "; "))
	switch {
	case access == "restore":
		has := strings.Join(held, ";")
		if !strings.Contains(has, "Owner at") && !(strings.Contains(has, "Contributor at") && strings.Contains(has, "User Access Administrator at")) {
			r.warn("A restore needs Contributor and User Access Administrator (or Owner) on the subscription")
		}
	case len(extra) > 0:
		r.warn("Holds roles beyond reading (" + strings.Join(extra, "; ") + "): more than a capture needs. Capture as an identity holding Reader only, or at least with the capture-only binary.")
	}
	return r, nil
}

func scopeName(scope, sub string) string {
	switch {
	case scope == "/":
		return "the tenant root"
	case strings.EqualFold(scope, "/subscriptions/"+sub):
		return "the subscription"
	case strings.HasPrefix(scope, "/providers/Microsoft.Management/managementGroups/"):
		return "management group " + scope[strings.LastIndex(scope, "/")+1:]
	}
	if i := strings.Index(strings.ToLower(scope), "/resourcegroups/"); i >= 0 {
		return "resource group " + strings.SplitN(scope[i+len("/resourcegroups/"):], "/", 2)[0]
	}
	return scope
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}
