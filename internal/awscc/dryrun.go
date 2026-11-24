package awscc

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// globalNames are the types whose names every AWS account shares, so that
// one free in this account can be another's: "Bucket names must be unique
// across all AWS accounts in all the AWS Regions within a partition"
// (docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html).
// The value is the property that holds the name.
var globalNames = map[string]string{"AWS::S3::Bucket": "BucketName"}

var roleARNRE = regexp.MustCompile(`arn:aws[a-z-]*:iam::(\d{12}):role/([A-Za-z0-9+=,.@_/-]+)`)

// dryChecks looks, by reading only, for what would refuse a create the dry
// run planned and that the target's inventory does not show: a name taken
// in another account, and a role of this account that a resource names and
// that neither the account nor the snapshot holds. One refused here takes
// with it what refers to it. What could not be checked is said through
// note, never passed over.
func dryChecks(ctx context.Context, api CloudControl, s snapshot.Snapshot, results []snapshot.Result, account string, note func(string)) {
	at := map[string]int{}
	for i, r := range results {
		at[r.Key] = i
	}
	inSnap := map[string]bool{}
	for _, o := range s.Objects {
		if o.Kind() == "AWS::IAM::Role" {
			inSnap[o.Name()] = true
			if n, _ := specOf(o)["RoleName"].(string); n != "" {
				inSnap[n] = true
			}
		}
	}
	// planned is one the dry run would write: an update that names a
	// missing role, or one that would not be created, fails as a create does.
	planned := func(o snapshot.Object) (int, bool) {
		i, ok := at[o.Key()]
		return i, ok && results[i].OK && strings.HasPrefix(results[i].Detail, "would ")
	}
	roles := map[string]string{} // role name -> "" when there, else why not
	refused := map[string]string{}
	for _, o := range s.Objects {
		i, ok := planned(o)
		if !ok {
			continue
		}
		fail := func(why string) {
			results[i].OK, results[i].Detail = false, why
			refused[o.Kind()+"/"+o.Name()] = why
		}
		if prop := globalNames[o.Kind()]; prop != "" && strings.HasPrefix(results[i].Detail, "would create") {
			if name, _ := specOf(o)[prop].(string); name != "" && !strings.Contains(name, "{{") {
				switch _, err := api.Get(ctx, o.Kind(), name); {
				case err == nil:
					fail("the name " + name + " is taken by one this account does not hold (these names are shared by every AWS account): the create would be refused")
					continue
				case !errors.Is(err, ErrNotFound):
					note("could not check whether the name " + name + " is free in every account: " + err.Error())
				}
			}
		}
		var missing []string
		for _, m := range rolesNamed(o.Body["spec"], account) {
			name := m[2][strings.LastIndex(m[2], "/")+1:]
			if m[1] != account || strings.HasPrefix(m[2], "aws-service-role/") || inSnap[name] || name == "" {
				continue
			}
			why, seen := roles[name]
			if !seen {
				switch _, err := api.Get(ctx, "AWS::IAM::Role", name); {
				case errors.Is(err, ErrNotFound):
					why = "missing"
				case err != nil:
					note("could not check that role " + name + " exists: " + err.Error())
				}
				roles[name] = why
			}
			if why != "" {
				missing = append(missing, name)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			fail("names role " + strings.Join(dedupeSorted(missing), ", ") + ", which is neither in the account nor in the snapshot: the create would be refused")
		}
	}
	// What refers to one that would not be created would not be either.
	// The snapshot's objects are in no order, so this runs until settled.
	for changed := len(refused) > 0; changed; {
		changed = false
		for _, o := range s.Objects {
			i, ok := planned(o)
			if !ok {
				continue
			}
			for _, m := range tokenRE.FindAllStringSubmatch(canon(o.Body["spec"]), -1) {
				if _, bad := refused[m[1]+"/"+m[2]]; bad {
					results[i].OK, results[i].Detail = false, "depends on "+m[1]+"/"+m[2]+", which would not be created"
					refused[o.Kind()+"/"+o.Name()] = results[i].Detail
					changed = true
					break
				}
			}
		}
	}
}

// rolesNamed are the role ARNs a spec names where AWS looks the role up:
// a property that takes a role, or a policy's principal. What a policy
// allows on (its Resource) is a pattern AWS never resolves, and so is any
// ARN with a wildcard or a policy variable. A policy held as JSON text is
// read as the policy it is.
func rolesNamed(v any, account string) [][]string {
	var out [][]string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				if k != "Resource" && k != "NotResource" {
					walk(e)
				}
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		case string:
			if t := strings.TrimSpace(x); strings.HasPrefix(t, "{") {
				var doc map[string]any
				if json.Unmarshal([]byte(t), &doc) == nil {
					walk(doc)
					return
				}
			}
			x = strings.ReplaceAll(x, "{{truthform|account|self|id}}", account)
			for _, loc := range roleARNRE.FindAllStringSubmatchIndex(x, -1) {
				if loc[1] < len(x) && strings.ContainsRune("*?$", rune(x[loc[1]])) {
					continue
				}
				out = append(out, []string{x[loc[0]:loc[1]], x[loc[2]:loc[3]], x[loc[4]:loc[5]]})
			}
		}
	}
	walk(v)
	return out
}

func dedupeSorted(in []string) []string {
	out := in[:0]
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}
