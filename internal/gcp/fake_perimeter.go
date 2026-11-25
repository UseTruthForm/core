package gcp

import (
	"fmt"
	"regexp"
	"strings"
)

// fakeResourceRules is what Google holds one type to beyond its document,
// by schema: rel is the resource's name and data what it would become.
var fakeResourceRules = map[string]func(f *Fake, rel string, data map[string]any) error{
	"ServicePerimeter": fakePerimeter,
}

var (
	perimeterIDRE  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)
	projectNumRE   = regexp.MustCompile(`^projects/[0-9]+$`)
	servicesHostRE = regexp.MustCompile(`^[a-z0-9-]+\.googleapis\.com$`)
	principalRE    = regexp.MustCompile(`^(user:|serviceAccount:|group:|principal://|principalSet://)\S+$`)
)

// fakePerimeter holds a service perimeter to what Access Context Manager
// documents (https://accesscontextmanager.googleapis.com/$discovery/rest?version=v1,
// https://docs.cloud.google.com/vpc-service-controls/docs/ingress-egress-rules):
// its ID "must begin with a letter, followed by alphanumeric characters or
// _"; a project is named by its number ("If you specify projects, only
// project numbers are supported"); "a single Google Cloud project ... is
// allowed to be a member of a single regular perimeter"; an ingress rule's
// sources are "Required", and it names identities or an identity type.
func fakePerimeter(f *Fake, rel string, data map[string]any) error {
	if id := rel[strings.LastIndex(rel, "/")+1:]; !perimeterIDRE.MatchString(id) {
		return fmt.Errorf("INVALID_ARGUMENT: %q is not a service perimeter ID", id)
	}
	if t, _ := data["title"].(string); t == "" {
		return fmt.Errorf("INVALID_ARGUMENT: a service perimeter needs a title")
	}
	st, _ := data["status"].(map[string]any)
	for _, x := range anyList(st["resources"]) {
		r, _ := x.(string)
		if !projectNumRE.MatchString(r) {
			return fmt.Errorf("INVALID_ARGUMENT: %q: a project is named by its number (projects/<number>)", r)
		}
		known := false
		for _, n := range f.w.projects {
			known = known || "projects/"+n == r
		}
		if !known {
			return fmt.Errorf("INVALID_ARGUMENT: %s is not a project of this organization", r)
		}
		for other, o := range f.w.outside {
			ost, _ := o.data["status"].(map[string]any)
			if other == rel || !strings.HasSuffix(o.asset.Type, "/ServicePerimeter") {
				continue
			}
			for _, y := range anyList(ost["resources"]) {
				if y == r {
					return fmt.Errorf("INVALID_ARGUMENT: %s is already in service perimeter %s; a project can be in one regular perimeter only", r, other)
				}
			}
		}
	}
	for _, x := range anyList(st["restrictedServices"]) {
		if s, _ := x.(string); !servicesHostRE.MatchString(s) {
			return fmt.Errorf("INVALID_ARGUMENT: %q is not a service (pubsub.googleapis.com)", s)
		}
	}
	for _, x := range anyList(st["ingressPolicies"]) {
		p, _ := x.(map[string]any)
		from, _ := p["ingressFrom"].(map[string]any)
		to, _ := p["ingressTo"].(map[string]any)
		ids := anyList(from["identities"])
		switch {
		case len(anyList(from["sources"])) == 0:
			return fmt.Errorf("INVALID_ARGUMENT: an ingress rule needs sources")
		case len(ids) == 0 && from["identityType"] == nil:
			return fmt.Errorf("INVALID_ARGUMENT: an ingress rule needs identities or an identityType")
		case len(anyList(to["operations"])) == 0 || len(anyList(to["resources"])) == 0:
			return fmt.Errorf("INVALID_ARGUMENT: an ingress rule needs operations and resources")
		}
		for _, id := range ids {
			if s, _ := id.(string); !principalRE.MatchString(s) {
				return fmt.Errorf("INVALID_ARGUMENT: %q is not an identity an ingress rule takes (user:, serviceAccount:)", s)
			}
		}
		for _, o := range anyList(to["operations"]) {
			op, _ := o.(map[string]any)
			if op["serviceName"] != "*" && len(anyList(op["methodSelectors"])) == 0 {
				return fmt.Errorf("INVALID_ARGUMENT: methodSelectors are required for %v", op["serviceName"])
			}
		}
	}
	return nil
}

// perimeterMethods names a call as VPC Service Controls does, for the
// services whose ingress rules take method restrictions
// (https://docs.cloud.google.com/vpc-service-controls/docs/supported-method-restrictions),
// by the collection in the URL: %s is Create, Get or Update. A call that
// is not here passes only a rule that admits the whole service.
var perimeterMethods = map[string]map[string]string{
	"pubsub.googleapis.com": {"topics": "Publisher.%sTopic", "subscriptions": "Subscriber.%sSubscription"},
}

// perimeterRefuses is VPC Service Controls: a call to a service a
// perimeter restricts for this project is refused unless it comes from
// inside (one of the project's networks) or an ingress rule admits the
// caller for it. "Access from the internet to managed resources within a
// service perimeter is denied by default", management calls included
// (https://docs.cloud.google.com/vpc-service-controls/docs/overview).
func (f *Fake) perimeterRefuses(method, url string) error {
	if f.Inside {
		return nil
	}
	host := strings.TrimPrefix(url, "https://")
	host, path, _ := strings.Cut(host, "/")
	path, _, _ = strings.Cut(path, "?")
	for rel, r := range f.w.outside {
		st, _ := r.data["status"].(map[string]any)
		if !strings.HasSuffix(r.asset.Type, "/ServicePerimeter") || !holds(st["resources"], "projects/"+f.number) || !holds(st["restrictedServices"], host) {
			continue
		}
		name := ""
		verb := map[string]string{"GET": "Get", "POST": "Create", "PUT": "Create", "PATCH": "Update"}[method]
		segs := strings.Split(path, "/")
		for i := len(segs) - 1; i >= 0 && name == ""; i-- {
			if tmpl := perimeterMethods[host][segs[i]]; tmpl != "" {
				name = fmt.Sprintf(tmpl, verb)
			}
		}
		for _, x := range anyList(st["ingressPolicies"]) {
			if f.admitted(x.(map[string]any), host, name) {
				return nil
			}
		}
		return fmt.Errorf("PERMISSION_DENIED: Request is prohibited by organization's policy (service perimeter %s restricts %s)", rel, host)
	}
	return nil
}

// admitted reports an ingress rule that lets the fake's caller call a
// method of a service from anywhere.
func (f *Fake) admitted(p map[string]any, host, method string) bool {
	from, _ := p["ingressFrom"].(map[string]any)
	to, _ := p["ingressTo"].(map[string]any)
	if !(holds(from["identities"], f.Caller) && f.Caller != "") && from["identityType"] != "ANY_IDENTITY" {
		return false
	}
	anywhere := false
	for _, s := range anyList(from["sources"]) {
		m, _ := s.(map[string]any)
		anywhere = anywhere || m["accessLevel"] == "*"
	}
	if !anywhere || !(holds(to["resources"], "*") || holds(to["resources"], "projects/"+f.number)) {
		return false
	}
	for _, o := range anyList(to["operations"]) {
		op, _ := o.(map[string]any)
		if op["serviceName"] != host && op["serviceName"] != "*" {
			continue
		}
		if op["serviceName"] == "*" {
			return true
		}
		for _, s := range anyList(op["methodSelectors"]) {
			m, _ := s.(map[string]any)
			if m["method"] == "*" || (method != "" && m["method"] == method) {
				return true
			}
		}
	}
	return false
}

func holds(list any, v string) bool {
	for _, x := range anyList(list) {
		if x == v {
			return true
		}
	}
	return false
}
