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
// (kms:Decrypt, secretsmanager:GetSecretValue, cloudwatch:PutMetricAlarm,
// ec2:CreateLaunchTemplate), so only actions named as reads are kept, and
// reads that return data or secrets are dropped. A type that needs one of
// those stays refused, and stackdna check says so.
package awsreads

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/stackdna/core/internal/awscc"
)

// readVerb is an action named as a read.
var readVerb = regexp.MustCompile(`^[a-z0-9-]+:(Get|List|Describe|BatchGet|Search|View|Lookup)`)

// dataRead returns data or secrets, not configuration: a snapshot never
// holds them, so the role is not given them.
var dataRead = regexp.MustCompile(`(?i):(GetSecretValue|BatchGetSecretValue|GetObject|GetItem|BatchGetItem|GetParameter|GetParameters|GetParametersByPath|GetRecords|GetShardIterator|GetDataAccess|GetAccessToken|GetWebIdentityToken|GetCredentials|GetAuthorizationToken|GetQueryResults|GetLogEvents|GetFederationToken|GetSessionToken|GetDataset|GetMedia|GetClip|GetBlob|GetFile|GetSnapshotBlock|ListSnapshotBlocks|ListChangedBlocks|GetRecoveryPoint|GetJobOutput|GetObjectAcl|GetPlaintext)`)

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

// Result is the add-on and what it was made from.
type Result struct {
	Actions []string `json:"actions"`
	// Types the add-on completes, and types that would still need an
	// action it does not grant (with those actions).
	Completed []string            `json:"completed"`
	Short     map[string][]string `json:"short"`
}

// Compute is the reads every capturable type's list and read handlers
// need that base does not grant, kept to reads of configuration.
func Compute(regs []*awscc.Registry, base *Grants) (Result, error) {
	need := map[string]map[string]bool{}
	for _, reg := range regs {
		for name, t := range reg.Types {
			var s struct {
				Handlers map[string]struct {
					Permissions []string `json:"permissions"`
				} `json:"handlers"`
			}
			if err := json.Unmarshal(t.Raw, &s); err != nil {
				return Result{}, fmt.Errorf("%s: %w", name, err)
			}
			for _, h := range []string{"list", "read"} {
				for _, p := range s.Handlers[h].Permissions {
					if need[name] == nil {
						need[name] = map[string]bool{}
					}
					need[name][p] = true
				}
			}
		}
	}
	keep := map[string]bool{}
	r := Result{Short: map[string][]string{}}
	for name, perms := range need {
		var missing, refused []string
		for p := range perms {
			if base.Allows(p) {
				continue
			}
			missing = append(missing, p)
			if readVerb.MatchString(p) && !dataRead.MatchString(p) {
				keep[p] = true
			} else {
				refused = append(refused, p)
			}
		}
		switch {
		case len(missing) == 0:
		case len(refused) == 0:
			r.Completed = append(r.Completed, name)
		default:
			sort.Strings(refused)
			r.Short[name] = refused
		}
	}
	for a := range keep {
		r.Actions = append(r.Actions, a)
	}
	sort.Strings(r.Actions)
	sort.Strings(r.Completed)
	return r, nil
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

// IsRead reports whether an action is one the add-on may hold.
func IsRead(a string) bool { return readVerb.MatchString(a) && !dataRead.MatchString(a) }
