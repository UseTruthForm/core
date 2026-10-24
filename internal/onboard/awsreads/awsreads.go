// Package awsreads works out the reads a capture needs that AWS's managed
// ReadOnlyAccess policy does not grant.
//
// ReadOnlyAccess alone was refused 87 of about 1,500 types in a sandbox
// capture (2026-10-23): AWS has not added some newer services to it. The
// CloudFormation registry names, for every type, the IAM actions its list
// and read handlers need; those predicted all 80 types refused directly.
// So the add-on is derived from the schemas, never written by hand.
//
// A schema's read handler sometimes names writes and data reads too
// (kms:Decrypt, cloudwatch:PutMetricAlarm, ec2:CreateLaunchTemplate), so
// each action is judged before it is kept, by AWS's own classification
// first (the Service Reference: write, permissions management, tagging,
// data plane), by name only where AWS does not list the action, and never
// for secrets: AWS classifies secretsmanager:GetSecretValue as an ordinary
// read. A name-only first version let through bedrock:GetSession and
// ListSessions, which AWS marks as data plane (2026-10-24).
package awsreads

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/stackdna/core/internal/awscc"
)

// readVerb is an action named as a read; used only for actions the
// Service Reference does not list.
var readVerb = regexp.MustCompile(`^[a-z0-9-]+:(Get|List|Describe|BatchGet|Search|View|Lookup)`)

// secretOrData returns secrets or data, not configuration, whatever AWS's
// classification says: a snapshot never holds them, so the role is not
// given them.
var secretOrData = regexp.MustCompile(`(?i):(GetSecretValue|BatchGetSecretValue|GetObject|GetItem|BatchGetItem|GetParameter|GetParameters|GetParametersByPath|GetRecords|GetShardIterator|GetDataAccess|GetAccessToken|GetWebIdentityToken|GetCredentials|GetAuthorizationToken|GetQueryResults|GetLogEvents|GetFederationToken|GetSessionToken|GetDataset|GetMedia|GetClip|GetBlob|GetFile|GetSnapshotBlock|ListSnapshotBlocks|ListChangedBlocks|GetRecoveryPoint|GetJobOutput|GetObjectAcl|GetPlaintext|Decrypt|GenerateDataKey)`)

// Policy is the part of an IAM policy document this reads.
type Policy struct {
	Statement []struct {
		Effect    string `json:"Effect"`
		Action    any    `json:"Action"`
		NotAction any    `json:"NotAction"`
	} `json:"Statement"`
}

// Grants reports whether a policy's Allow statements match an action.
type Grants struct{ res []*regexp.Regexp }

// ParsePolicy reads a policy document. A NotAction statement is refused:
// what it grants cannot be listed, and guessing would put a gap back.
func ParsePolicy(b []byte) (*Grants, error) {
	var p Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	g := &Grants{}
	for _, st := range p.Statement {
		if st.Effect != "Allow" {
			continue
		}
		if st.NotAction != nil {
			return nil, fmt.Errorf("the policy has a NotAction statement; this cannot list what it grants")
		}
		var acts []string
		switch a := st.Action.(type) {
		case string:
			acts = []string{a}
		case []any:
			for _, x := range a {
				if s, ok := x.(string); ok {
					acts = append(acts, s)
				}
			}
		}
		for _, a := range acts {
			g.res = append(g.res, glob(a))
		}
	}
	if len(g.res) == 0 {
		return nil, fmt.Errorf("the policy grants nothing")
	}
	return g, nil
}

func glob(p string) *regexp.Regexp {
	q := regexp.QuoteMeta(strings.ToLower(p))
	q = strings.ReplaceAll(q, `\*`, `.*`)
	q = strings.ReplaceAll(q, `\?`, `.`)
	return regexp.MustCompile("^" + q + "$")
}

func (g *Grants) Allows(action string) bool {
	a := strings.ToLower(action)
	for _, re := range g.res {
		if re.MatchString(a) {
			return true
		}
	}
	return false
}

// Flags are an action's properties in AWS's Service Reference.
type Flags struct {
	IsWrite                bool `json:"IsWrite"`
	IsPermissionManagement bool `json:"IsPermissionManagement"`
	IsTaggingOnly          bool `json:"IsTaggingOnly"`
	IsDataPlane            bool `json:"IsDataPlane"`
	IsList                 bool `json:"IsList"`
}

// Reference is the Service Reference's flags, by lower-case action.
type Reference struct {
	Actions map[string]Flags
	Names   map[string]string // lower-case -> as AWS writes it
}

// Verdict is how one action was judged.
type Verdict struct {
	Keep bool
	// Why: "read" (named as a read, and AWS agrees), "read by name" (AWS
	// does not list it), or why it was refused.
	Why string
}

// Judge decides one concrete action. Neither source is trusted alone:
// AWS's flags call quicksight:DescribeSpacePermissions and
// glue:ListConnectionTypes writes (they are filed under permissions
// management), and flag nothing on cleanrooms:PassMembership or
// cassandra:SelectMultiRegionResource; names alone let through
// bedrock:GetSession, which AWS marks as data plane (2026-10-24). So an
// action is kept only when it is named as a read and AWS does not say
// otherwise, and secrets never.
func (r *Reference) Judge(a string) Verdict {
	switch {
	case strings.ContainsAny(a, "*?"):
		return Verdict{false, "wildcard (expanded, not granted as is)"}
	case secretOrData.MatchString(a):
		return Verdict{false, "secret or data"}
	case !readVerb.MatchString(a):
		return Verdict{false, "not named as a read"}
	}
	f, known := r.Actions[strings.ToLower(a)]
	switch {
	case !known:
		return Verdict{true, "read by name"}
	case f.IsDataPlane:
		return Verdict{false, "AWS: data plane"}
	// AWS marks every action in its permissions and tagging categories as
	// a write, reads of them included; a write outside them is a write.
	case f.IsWrite && !f.IsPermissionManagement && !f.IsTaggingOnly:
		return Verdict{false, "AWS: write"}
	}
	return Verdict{true, "read"}
}

// Expand turns a schema's wildcard into the concrete actions AWS lists
// that match it, so the role holds only actions that exist today: a
// wildcard would also grant whatever AWS adds under it later. Nil when
// AWS lists no such service.
func (r *Reference) Expand(pattern string) []string {
	prefix, _, _ := strings.Cut(strings.ToLower(pattern), ":")
	re := glob(pattern)
	var out []string
	for a := range r.Actions {
		if strings.HasPrefix(a, prefix+":") && re.MatchString(a) {
			out = append(out, r.Names[a])
		}
	}
	sort.Strings(out)
	return out
}

// Missing is, per type, the actions its list and read handlers need that
// base does not grant.
func Missing(regs []*awscc.Registry, base *Grants) (map[string][]string, error) {
	need := map[string]map[string]bool{}
	for _, reg := range regs {
		for name, t := range reg.Types {
			var s struct {
				Handlers map[string]struct {
					Permissions []string `json:"permissions"`
				} `json:"handlers"`
			}
			if err := json.Unmarshal(t.Raw, &s); err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			for _, h := range []string{"list", "read"} {
				for _, p := range s.Handlers[h].Permissions {
					if base.Allows(p) {
						continue
					}
					if need[name] == nil {
						need[name] = map[string]bool{}
					}
					need[name][p] = true
				}
			}
		}
	}
	out := map[string][]string{}
	for name, ps := range need {
		for p := range ps {
			out[name] = append(out[name], p)
		}
		sort.Strings(out[name])
	}
	return out, nil
}

// Result is the add-on and what it was made from.
type Result struct {
	Actions []string `json:"actions"`
	// Unverified are kept actions AWS's Service Reference does not list:
	// kept by name, and listed so a reviewer can see them.
	Unverified []string `json:"unverified"`
	// Types the add-on completes, and types that still need an action it
	// does not grant (with each action and why).
	Completed []string                     `json:"completed"`
	Short     map[string]map[string]string `json:"short"`
}

// Decide judges every missing action.
func Decide(missing map[string][]string, ref *Reference) Result {
	keep := map[string]bool{}
	unverified := map[string]bool{}
	r := Result{Short: map[string]map[string]string{}}
	for name, acts := range missing {
		refused := map[string]string{}
		for _, a := range acts {
			concrete := []string{a}
			if strings.ContainsAny(a, "*?") {
				if concrete = ref.Expand(a); len(concrete) == 0 {
					refused[a] = "wildcard for actions AWS does not list"
					continue
				}
			}
			for _, c := range concrete {
				v := ref.Judge(c)
				if !v.Keep {
					// Expanding a wildcard finds writes too (Get* includes
					// GetSecretValue-like actions in some services): only
					// a concrete action named in the schema is a shortfall.
					if c == a {
						refused[a] = v.Why
					}
					continue
				}
				keep[c] = true
				if v.Why == "read by name" {
					unverified[c] = true
				}
			}
		}
		if len(refused) == 0 {
			r.Completed = append(r.Completed, name)
		} else {
			r.Short[name] = refused
		}
	}
	for a := range keep {
		r.Actions = append(r.Actions, a)
	}
	for a := range unverified {
		r.Unverified = append(r.Unverified, a)
	}
	sort.Strings(r.Actions)
	sort.Strings(r.Unverified)
	sort.Strings(r.Completed)
	return r
}

// MaxPolicyChars is IAM's limit for a customer managed policy, counted
// without whitespace.
const MaxPolicyChars = 6144

// Chunks splits actions into lists that each fit one managed policy, with
// room for the statement around them.
func Chunks(actions []string) [][]string {
	const room = MaxPolicyChars - 200
	var out [][]string
	var cur []string
	size := 0
	for _, a := range actions {
		n := len(a) + 3 // quotes and a comma
		if size+n > room && len(cur) > 0 {
			out = append(out, cur)
			cur, size = nil, 0
		}
		cur = append(cur, a)
		size += n
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// IsConfigurationRead reports whether an action may be in the add-on at
// all, whatever any classification says: no wildcard, no secret or data.
func IsConfigurationRead(a string) bool {
	return !strings.ContainsAny(a, "*?") && !secretOrData.MatchString(a) && strings.Contains(a, ":")
}
