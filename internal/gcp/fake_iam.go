package gcp

import (
	"fmt"
	neturl "net/url"
	"regexp"
	"strings"
)

// The fake's allow policies. Like the rest of the fake they are served
// from the Discovery documents: a call is a policy call when its URL and
// verb match a collection's getIamPolicy or setIamPolicy. What Google
// checks on a write is checked here, so a restore that would fail against
// Google fails against the fake:
//
//   - the resource exists;
//   - the etag is the one the policy was read with (409 ABORTED otherwise);
//   - a member is a principal of a known form, holds no unresolved token,
//     and, when it is a service account of this project, exists;
//   - a member of a workload identity pool needs the pool, which a GKE
//     cluster with a workloadPool makes;
//   - a version 3 policy read as version 1 cannot be written back.

type fakePolicy struct {
	etag     string
	version  int
	bindings []any
}

// iamCall serves a policy call, or reports that the URL is not one.
func (f *Fake) iamCall(method, u string, body any) (map[string]any, bool, error) {
	path, rawQuery, _ := strings.Cut(u, "?")
	for _, d := range f.w.docs.loaded() {
		prefix := d.RootURL + d.ServicePath
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		rest := strings.TrimPrefix(path, prefix)
		for _, c := range d.collections() {
			for _, name := range []string{"getIamPolicy", "setIamPolicy"} {
				m := c.methods[name]
				if m == nil || m.HTTPMethod != method {
					continue
				}
				re := policyPathRE(m.Path)
				sm := re.FindStringSubmatch(rest)
				if sm == nil {
					continue
				}
				rel := sm[1]
				if _, ok := f.res[rel]; !ok {
					return nil, true, fmt.Errorf("%s: %w", u, ErrNotFound)
				}
				if name == "getIamPolicy" {
					q, _ := neturl.ParseQuery(rawQuery)
					v := 1
					for k, vs := range q {
						if strings.HasSuffix(strings.ToLower(strings.ReplaceAll(k, ".", "")), "requestedpolicyversion") && len(vs) > 0 && vs[0] == "3" {
							v = 3
						}
					}
					return f.policyOut(rel, v), true, nil
				}
				b, _ := body.(map[string]any)
				if m.Request != nil && m.Request.Ref != "Policy" {
					b, _ = b["policy"].(map[string]any)
					if b == nil {
						return nil, true, fmt.Errorf("INVALID_ARGUMENT: %s needs policy", m.Request.Ref)
					}
				}
				out, err := f.setPolicy(rel, b)
				return out, true, err
			}
		}
	}
	return nil, false, nil
}

// policyPathRE matches a policy method's path, its one parameter being
// the resource's name.
func policyPathRE(tmpl string) *regexp.Regexp {
	var b strings.Builder
	last := 0
	for _, loc := range pathParamRE.FindAllStringIndex(tmpl, -1) {
		b.WriteString(regexp.QuoteMeta(tmpl[last:loc[0]]) + "(.+)")
		last = loc[1]
	}
	return regexp.MustCompile("^" + b.String() + regexp.QuoteMeta(tmpl[last:]) + "$")
}

func (f *Fake) policyOut(rel string, version int) map[string]any {
	p := f.iam[rel]
	if p == nil {
		f.w.seq++
		p = &fakePolicy{etag: fmt.Sprintf("p%d", f.w.seq), version: 1}
		f.iam[rel] = p
	}
	out := map[string]any{"etag": p.etag, "version": p.version}
	var bs []any
	for _, x := range p.bindings {
		b := deepCopy(x.(map[string]any))
		if b["condition"] != nil && version < 3 {
			// A conditional binding read below version 3 comes back
			// without its condition, its role renamed.
			b["role"] = fmt.Sprint(b["role"]) + "_withcond_0000"
			delete(b, "condition")
		}
		bs = append(bs, b)
	}
	if len(bs) > 0 {
		out["bindings"] = bs
	}
	return out
}

var memberRE = regexp.MustCompile(`^(user|group|domain|serviceAccount|principal|principalSet|deleted:[a-zA-Z]+):.+$|^(allUsers|allAuthenticatedUsers)$`)

func (f *Fake) setPolicy(rel string, p map[string]any) (map[string]any, error) {
	cur := f.iam[rel]
	if cur == nil {
		f.w.seq++
		cur = &fakePolicy{etag: fmt.Sprintf("p%d", f.w.seq), version: 1}
		f.iam[rel] = cur
	}
	if e, _ := p["etag"].(string); e != "" && e != cur.etag {
		return nil, fmt.Errorf("HTTP 409: ABORTED: There were concurrent policy changes. Please retry the whole read-modify-write with exponential backoff.")
	}
	var bs []any
	for _, x := range anyList(p["bindings"]) {
		b, _ := x.(map[string]any)
		role, _ := b["role"].(string)
		if !strings.HasPrefix(role, "roles/") || strings.Contains(role, "_withcond_") {
			return nil, fmt.Errorf("INVALID_ARGUMENT: Role %s is not supported for this resource.", role)
		}
		for _, mx := range anyList(b["members"]) {
			m, _ := mx.(string)
			switch {
			case strings.Contains(m, "{{truthform"):
				return nil, fmt.Errorf("INVALID_ARGUMENT: unresolved TruthForm reference %q sent to Google", m)
			case !memberRE.MatchString(m):
				return nil, fmt.Errorf("INVALID_ARGUMENT: Invalid member %q", m)
			}
			for other := range f.w.projects {
				if other != f.id && (strings.Contains(m, "@"+other+".") || strings.Contains(m, ":"+other+".svc.id.goog")) {
					return nil, fmt.Errorf("INVALID_ARGUMENT: %q refers to project %s, which this one cannot see", m, other)
				}
			}
			if email, ok := strings.CutPrefix(m, "serviceAccount:"); ok {
				switch {
				case strings.HasSuffix(email, "@"+f.id+".iam.gserviceaccount.com"):
					_, byEmail := f.res["projects/"+f.id+"/serviceAccounts/"+email]
					_, byID := f.res["projects/"+f.id+"/serviceAccounts/"+strings.TrimSuffix(email, "@"+f.id+".iam.gserviceaccount.com")]
					if !byEmail && !byID {
						return nil, fmt.Errorf("INVALID_ARGUMENT: Service account %s does not exist.", email)
					}
				case strings.HasPrefix(email, f.id+".svc.id.goog["):
					if !f.hasWorkloadPool() {
						return nil, fmt.Errorf("INVALID_ARGUMENT: Identity Pool does not exist (%s.svc.id.goog). Please check that you specified a valid resource name as returned in the `name` attribute in the configuration API.", f.id)
					}
				}
			}
		}
		bs = append(bs, deepCopy(b))
	}
	f.w.seq++
	v := cur.version
	if n, ok := p["version"].(int); ok && n > v {
		v = n
	}
	if n, ok := p["version"].(float64); ok && int(n) > v {
		v = int(n)
	}
	f.iam[rel] = &fakePolicy{etag: fmt.Sprintf("p%d", f.w.seq), version: v, bindings: bs}
	f.PolicyWrites++
	return f.policyOut(rel, 3), nil
}

// hasWorkloadPool reports a cluster that made the project's workload
// identity pool.
func (f *Fake) hasWorkloadPool() bool {
	for _, r := range f.res {
		if wi, _ := r.data["workloadIdentityConfig"].(map[string]any); wi != nil && wi["workloadPool"] == f.id+".svc.id.goog" {
			return true
		}
	}
	return false
}

func anyList(v any) []any { l, _ := v.([]any); return l }

// Policy returns the bindings of a resource's allow policy, as
// role -> members, conditional bindings under "role (conditional)".
func (f *Fake) Policy(rel string) map[string][]string {
	f.w.mu.Lock()
	defer f.w.mu.Unlock()
	out := map[string][]string{}
	if p := f.iam[rel]; p != nil {
		for _, x := range p.bindings {
			b := x.(map[string]any)
			role := fmt.Sprint(b["role"])
			if b["condition"] != nil {
				role += " (conditional)"
			}
			for _, m := range anyList(b["members"]) {
				out[role] = append(out[role], fmt.Sprint(m))
			}
		}
	}
	return out
}

// SetPolicy puts a policy on a resource as someone else would have, for
// test setup: bindings as IAM holds them.
func (f *Fake) SetPolicy(rel string, bindings ...map[string]any) {
	f.w.mu.Lock()
	defer f.w.mu.Unlock()
	f.w.seq++
	p := &fakePolicy{etag: fmt.Sprintf("p%d", f.w.seq), version: 1}
	for _, b := range bindings {
		if b["condition"] != nil {
			p.version = 3
		}
		p.bindings = append(p.bindings, deepCopy(b))
	}
	f.iam[rel] = p
}
