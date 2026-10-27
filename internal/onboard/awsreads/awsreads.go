// Package awsreads works out the reads a capture needs that AWS's managed
// ReadOnlyAccess policy does not grant.
//
// ReadOnlyAccess alone was refused 87 of about 1,500 types in a sandbox
// capture (2026-10-23): AWS has not added some newer services to it. The
// CloudFormation registry names, for every type, the IAM actions its list
// and read handlers need; those predicted all 80 types refused directly.
// So the add-on is derived from the schemas, never written by hand.
//
// That a schema names an action is not a reason to grant it. Schemas name
// writes and data reads under "read" (kms:Decrypt, cloudwatch:
// PutMetricAlarm), and some reads return secrets: ReadOnlyAccess leaves
// out ivs:GetStreamKey, glue:GetConnection and datazone:GetConnection on
// purpose, and the first add-on granted them back (review of #24). Each
// action is therefore judged against several sources, none trusted alone:
//
//   - its name: named as a read, and not named like a secret or data read;
//   - an explicit deny list, for secrets no other source marks;
//   - AWS's Service Reference: not data plane, not a write (bar a short
//     reviewed list of reads AWS files under permissions or tagging);
//   - AWS's API models: no output field AWS marks sensitive that is named
//     like a secret (a password, credential, token, key value, URL).
//
// What none of them could check, and what ReadOnlyAccess leaves out of a
// service it otherwise covers, is kept but listed for review: the weekly
// pull request shows it to a person.
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

// secretName is an action whose name says it returns a secret or data,
// whatever any classification says. A prefix match on purpose: it also
// catches ssm:GetParameterHistory and s3:GetObjectVersion.
var secretName = regexp.MustCompile(`(?i):(\w*(Password|Credential|Secret|ApiKey|StreamKey|AccessKey|PrivateKey|LoginPage|DownloadUrl|LoginUrl|PortalLoginUrl|SignedUrl|PresignedUrl|BearerToken|ChangeToken|AuthToken|AccessToken|ConnectionToken|OAuth2Token|ChallengePassword)|GetSecretValue|BatchGetSecretValue|GetObject|GetItem|BatchGetItem|GetParameter|GetRecords|GetShardIterator|GetDataAccess|GetAccessToken|GetWebIdentityToken|GetCredentials|GetAuthorizationToken|GetQueryResults|GetLogEvents|GetFederationToken|GetSessionToken|GetDataset$|GetMedia|GetClip|GetBlob|GetFile|GetSnapshotBlock|ListSnapshotBlocks|ListChangedBlocks|GetRecoveryPoint|GetJobOutput|GetPlaintext|Decrypt|GenerateDataKey|GetDecrypted)`)

// denied are reads that return secrets or data without any source saying
// so. Each was checked against AWS's API documentation (review of #24).
var denied = map[string]string{
	"glue:getconnection":                 "returns the connection's password unless the caller asks to hide it, which IAM cannot require",
	"glue:getconnections":                "returns connection passwords unless the caller asks to hide them",
	"managedblockchain:getaccessor":      "returns the accessor's billing token",
	"cases:getcase":                      "returns case fields and comments: customer data",
	"cases:searchcases":                  "returns case fields: customer data",
	"cases:searchrelateditems":           "returns case comments and contacts: customer data",
	"pi:getperformanceanalysisreport":    "returns a report of database activity: data",
	"billing:getbillingviewdata":         "returns billing data",
	"datazone:getenvironmentcredentials": "returns credentials",
	// Second review of #24: an unmarked secret, licence keys in a field
	// the name rules missed, free-form configuration AWS marks sensitive,
	// and contact details ReadOnlyAccess leaves out on purpose.
	"invoicing:getprocurementportalpreference": "returns the procurement portal's shared secret, which AWS does not mark sensitive in the output",
	"evs:getenvironment":                       "returns VMware licence keys (solutionKey, vsanKey)",
	"airflow:getenvironment":                   "returns Airflow configuration options, which AWS marks sensitive and can hold connection strings",
	"bedrock-agentcore:getpaymentconnector":    "returns an OAuth consent URL",
	"lightsail:getcontactmethods":              "returns contact email addresses and phone numbers",
	// Refused by AWS's Service Reference or API models: named here too, so
	// the committed add-on is held to it by the tests even if a source
	// changes or cannot be read (the second review re-added these to the
	// file by hand and the tests passed).
	"bedrock:getsession":                                    "AWS: data plane (agent session state)",
	"bedrock:listsessions":                                  "AWS: data plane (agent sessions)",
	"datazone:getconnection":                                "returns connection credentials and OAuth tokens",
	"datazone:listconnections":                              "returns connection credentials",
	"geo:describekey":                                       "returns the API key value",
	"thinclient:getenvironment":                             "returns the environment's activation code",
	"thinclient:listenvironments":                           "returns activation codes",
	"wisdom:getcontent":                                     "returns a download URL to the content",
	"workspaces-web:listsessions":                           "returns session usernames",
	"inspector2:getcodesecurityintegration":                 "returns an OAuth authorization URL",
	"application-signals:listinstrumentationconfigurations": "AWS: data plane",
}

// readsFiledAsWrites are reads AWS files under permissions management or
// tagging, which marks them as writes. Each was looked at: it returns the
// permissions or tags of one resource, and changes nothing. The list is
// explicit because the category is not a guarantee: across AWS's
// catalogue it also holds datazone:GetIamPortalLoginUrl, which hands out
// a login (review of #24).
var readsFiledAsWrites = map[string]bool{
	"glue:describeconnectiontype":                 true,
	"glue:listconnectiontypes":                    true,
	"quicksight:describeknowledgebasepermissions": true,
	"quicksight:describespacepermissions":         true,
	"quicksight:describetopicpermissions":         true,
	"bcm-pricing-calculator:listtagsforresource":  true,
}

// Policy is the part of an IAM policy document this reads.
type Policy struct {
	Statement []struct {
		Effect    string `json:"Effect"`
		Action    any    `json:"Action"`
		NotAction any    `json:"NotAction"`
	} `json:"Statement"`
}

// Grants reports whether a policy's Allow statements match an action.
type Grants struct {
	res      []*regexp.Regexp
	services map[string]bool // prefixes the policy names at all
}

// ParsePolicy reads a policy document. A NotAction statement is refused:
// what it grants cannot be listed, and guessing would put a gap back.
func ParsePolicy(b []byte) (*Grants, error) {
	var p Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	g := &Grants{services: map[string]bool{}}
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
			if p, _, ok := strings.Cut(strings.ToLower(a), ":"); ok {
				g.services[p] = true
			}
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

// Covers reports whether the policy names the action's service at all.
func (g *Grants) Covers(action string) bool {
	p, _, _ := strings.Cut(strings.ToLower(action), ":")
	return g.services[p]
}

// Flags are an action's properties in AWS's Service Reference.
type Flags struct {
	IsWrite                bool `json:"IsWrite"`
	IsPermissionManagement bool `json:"IsPermissionManagement"`
	IsTaggingOnly          bool `json:"IsTaggingOnly"`
	IsDataPlane            bool `json:"IsDataPlane"`
	IsList                 bool `json:"IsList"`
}

// Reference is what AWS publishes about actions, by lower-case action.
type Reference struct {
	Actions map[string]Flags
	Names   map[string]string // lower-case -> as AWS writes it
	// SecretFields are, per action whose API operation's output was
	// checked, the output fields AWS marks sensitive that are named like
	// a secret. An action absent from it had no output checked.
	SecretFields map[string][]string
	ops          map[string][]operation
}

// Verdict is how one action was judged.
type Verdict struct {
	Keep bool
	Why  string
	// Unverified: kept, but AWS does not list it, or its output could not
	// be checked.
	Unverified string
}

// Judge decides one concrete action.
func (r *Reference) Judge(a string) Verdict {
	low := strings.ToLower(a)
	switch {
	case strings.ContainsAny(a, "*?"):
		return Verdict{Why: "wildcard (expanded, not granted as is)"}
	case !readVerb.MatchString(a):
		return Verdict{Why: "not named as a read"}
	case secretName.MatchString(a):
		return Verdict{Why: "named like a secret or data read"}
	case denied[low] != "":
		return Verdict{Why: denied[low]}
	}
	f, known := r.Actions[low]
	switch {
	case !known:
		return Verdict{Keep: true, Why: "read by name", Unverified: "AWS's Service Reference does not list it"}
	case f.IsDataPlane:
		return Verdict{Why: "AWS: data plane"}
	case f.IsWrite && !readsFiledAsWrites[low]:
		return Verdict{Why: "AWS: write"}
	}
	fields, checked := r.SecretFields[low]
	switch {
	case len(fields) > 0:
		return Verdict{Why: "AWS marks its output sensitive: " + strings.Join(fields, ", ")}
	case !checked:
		return Verdict{Keep: true, Why: "read", Unverified: "its output could not be checked against AWS's API models"}
	}
	return Verdict{Keep: true, Why: "read"}
}

// Candidates are the concrete actions Decide will judge: the missing
// actions, with wildcards expanded. Their outputs are what is checked.
func Candidates(missing map[string][]string, ref *Reference) []string {
	seen := map[string]bool{}
	var out []string
	for _, acts := range missing {
		for _, a := range acts {
			cs := []string{a}
			if strings.ContainsAny(a, "*?") {
				cs = ref.Expand(a)
			}
			for _, c := range cs {
				if !seen[c] {
					seen[c] = true
					out = append(out, c)
				}
			}
		}
	}
	sort.Strings(out)
	return out
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
// base does not grant. A wildcard is kept as named; Decide expands it.
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
	Actions []string
	// Unverified are kept actions a source could not vouch for, with why.
	Unverified map[string]string
	// OmittedByReadOnlyAccess are kept actions of services ReadOnlyAccess
	// covers, which it leaves out. Often only because AWS has not caught
	// up; sometimes on purpose. Listed for a person to look at.
	OmittedByReadOnlyAccess []string
	// Types the add-on completes, and types that still need an action it
	// does not grant (with each action and why).
	Completed []string
	Short     map[string]map[string]string
}

// Decide judges every missing action.
func Decide(missing map[string][]string, ref *Reference, base *Grants) Result {
	keep := map[string]bool{}
	r := Result{Short: map[string]map[string]string{}, Unverified: map[string]string{}}
	for name, acts := range missing {
		refused := map[string]string{}
		for _, a := range acts {
			concrete := []string{a}
			if strings.ContainsAny(a, "*?") {
				concrete = nil
				for _, c := range ref.Expand(a) {
					// What ReadOnlyAccess grants needs no add-on: an
					// expansion took 15 such actions (review of #24).
					if !base.Allows(c) {
						concrete = append(concrete, c)
					}
				}
				if len(concrete) == 0 && len(ref.Expand(a)) == 0 {
					refused[a] = "wildcard for actions AWS does not list"
					continue
				}
			}
			for _, c := range concrete {
				v := ref.Judge(c)
				if !v.Keep {
					// A wildcard's refused expansion is a shortfall too:
					// the handler may need it, and saying the type is
					// complete would be a guess (review of #24).
					refused[c] = v.Why
					continue
				}
				keep[c] = true
				if v.Unverified != "" {
					r.Unverified[c] = v.Unverified
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
		if base.Covers(a) {
			r.OmittedByReadOnlyAccess = append(r.OmittedByReadOnlyAccess, a)
		}
	}
	sort.Strings(r.Actions)
	sort.Strings(r.OmittedByReadOnlyAccess)
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

// Allowed reports whether an action may be in the add-on at all, whatever
// any classification says: concrete, named as a read, not named like a
// secret or data read, not denied. The committed file is checked with it,
// so a hand edit that slips in a write fails the tests; a first version
// left out the read-verb check and let iam:CreateAccessKey through
// (review of #24).
func Allowed(a string) bool {
	return !strings.ContainsAny(a, "*?") && readVerb.MatchString(a) && !secretName.MatchString(a) && denied[strings.ToLower(a)] == ""
}
