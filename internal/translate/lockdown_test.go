package translate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

// lockFixture is peFixture with one object's properties changed, or the
// private endpoints left out.
func lockFixture(keepPE bool, change map[string]func(p map[string]any)) snapshot.Snapshot {
	s := peFixture()
	var objs []snapshot.Object
	for _, o := range s.Objects {
		if !keepPE && strings.HasPrefix(o.Kind(), "Microsoft.Network/privateEndpoints") {
			continue
		}
		if f := change[o.Kind()+" "+o.Name()]; f != nil {
			f(o.Body["spec"].(map[string]any)["properties"].(map[string]any))
		}
		objs = append(objs, o)
	}
	s.Objects = objs
	return s
}

const (
	lockBus = "Microsoft.ServiceBus/namespaces shopbus"
	lockKV  = "Microsoft.KeyVault/vaults shopkv"
	lockACR = "Microsoft.ContainerRegistry/registries shopacr"
	lockSt  = "Microsoft.Storage/storageAccounts shopfiles"
)

func vpce(names ...string) string {
	var ids []string
	for _, n := range names {
		ids = append(ids, `"{{truthform|AWS::EC2::VPCEndpoint|`+n+`|Id}}"`)
	}
	return `"StringNotEquals":{"aws:SourceVpce":[` + strings.Join(ids, ",") + `]}`
}

const (
	notService = `"BoolIfExists":{"aws:PrincipalIsAWSService":"false"}`
	notVia     = `"BoolIfExists":{"aws:PrincipalIsAWSService":"false","aws:ViaAWSService":"false"}`
	sqsActions = `["sqs:SendMessage","sqs:ReceiveMessage","sqs:DeleteMessage","sqs:ChangeMessageVisibility","sqs:PurgeQueue","sqs:StartMessageMoveTask","sqs:CancelMessageMoveTask"]`
	ecrActions = `["ecr:BatchGetImage","ecr:GetDownloadUrlForLayer","ecr:BatchCheckLayerAvailability","ecr:InitiateLayerUpload","ecr:UploadLayerPart","ecr:CompleteLayerUpload","ecr:PutImage"]`
)

func statements(t *testing.T, doc any) []string {
	t.Helper()
	if s, ok := doc.(string); ok {
		var m map[string]any
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatal(err)
		}
		doc = m
	}
	var out []string
	for _, st := range list(obj(doc)["Statement"]) {
		out = append(out, canonJSON(st))
	}
	return out
}

func secretPolicy(t *testing.T, r Result) map[string]any {
	t.Helper()
	for _, o := range r.Snapshots["aws"].Objects {
		if o.Kind() == awsSecretPolicy {
			return o.Body["spec"].(map[string]any)
		}
	}
	t.Fatal("no secret policy")
	return nil
}

// A service that answered only on its private endpoints answers on AWS
// only through the interface endpoints written for those: a policy that
// denies its data actions to everything else, and grants nothing.
func TestLockdownOnAWS(t *testing.T) {
	r := runPE(t, peFixture(), peMaps()["aws"])
	queue := func(name string) string {
		return `{"Action":` + sqsActions + `,"Condition":{` + notService + `,` + vpce("core-sqs") + `},"Effect":"Deny","Principal":"*","Resource":"{{truthform|AWS::SQS::Queue|` + name + `|Arn}}","Sid":"DenyOutsidePrivateAccess"}`
	}
	// A queue and its dead-letter queue.
	for _, q := range []string{"orders", "orders-dlq", "events-audit-dlq"} {
		p := object(t, r, "aws", awsPolicy, q)
		if got := statements(t, p["PolicyDocument"]); !reflect.DeepEqual(got, []string{queue(q)}) || p["Queue"] != awsRef(awsQueue, q, "QueueUrl") {
			t.Errorf("%s: %v", q, got)
		}
	}
	// A subscription's queue has one policy: the topic's delivery still
	// stands beside the deny, which lets SNS itself through.
	allow := `{"Action":"sqs:SendMessage","Condition":{"ArnEquals":{"aws:SourceArn":"{{truthform|AWS::SNS::Topic|events|TopicArn}}"}},"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Resource":"{{truthform|AWS::SQS::Queue|events-audit|Arn}}"}`
	if got := statements(t, object(t, r, "aws", awsPolicy, "events-audit")["PolicyDocument"]); !reflect.DeepEqual(got, []string{allow, queue("events-audit")}) {
		t.Errorf("subscription queue: %v", got)
	}
	topic := `{"Action":["sns:Publish"],"Condition":{` + notService + `,` + vpce("core-sns") + `},"Effect":"Deny","Principal":"*","Resource":"{{truthform|AWS::SNS::Topic|events|TopicArn}}","Sid":"DenyOutsidePrivateAccess"}`
	tp := object(t, r, "aws", awsTopicPolicy, "events")
	if got := statements(t, tp["PolicyDocument"]); !reflect.DeepEqual(got, []string{topic}) || tp["TopicArn"] != awsRef(awsTopic, "events", "TopicArn") {
		t.Errorf("topic: %v", got)
	}
	// A secret: writing its value is denied outright, reading it unless
	// an AWS service asks with the caller's credentials, as Cloud Control
	// does to read the secret.
	arn := `"{{truthform|AWS::SecretsManager::Secret|shopkv/db-password|Id}}"`
	sp := secretPolicy(t, r)
	want := []string{
		`{"Action":["secretsmanager:PutSecretValue"],"Condition":{` + notService + `,` + vpce("core-secretsmanager") + `},"Effect":"Deny","Principal":"*","Resource":` + arn + `,"Sid":"DenyOutsidePrivateAccess"}`,
		`{"Action":["secretsmanager:GetSecretValue"],"Condition":{` + notVia + `,` + vpce("core-secretsmanager") + `},"Effect":"Deny","Principal":"*","Resource":` + arn + `,"Sid":"DenyOutsidePrivateAccessButThroughAWS"}`,
	}
	if got := statements(t, sp["ResourcePolicy"]); !reflect.DeepEqual(got, want) || `"`+sp["SecretId"].(string)+`"` != arn {
		t.Errorf("secret: %v", got)
	}
	// A bucket: the TLS denies it had, then objects, listings, and the
	// one listing its own handlers need.
	b := `{{truthform|AWS::S3::Bucket|shopfiles-docs|Arn}}`
	got := statements(t, object(t, r, "aws", awsBucketPolicy, "shopfiles-docs")["PolicyDocument"])
	if len(got) != 5 || !strings.Contains(got[0], "DenyPlainHTTP") || !strings.Contains(got[1], "DenyOldTLS") {
		t.Fatalf("bucket: %v", got)
	}
	got = got[1:]
	if !strings.HasPrefix(got[1], `{"Action":["s3:GetObject","s3:GetObjectVersion",`) || !strings.Contains(got[1], `"s3:PutObject"`) || !strings.Contains(got[1], `"s3:DeleteObjectVersion"`) ||
		!strings.HasSuffix(got[1], `"Condition":{`+notService+`,`+vpce("core-s3")+`},"Effect":"Deny","Principal":"*","Resource":"`+b+`/*","Sid":"DenyOutsidePrivateAccess"}`) {
		t.Errorf("bucket objects: %s", got[1])
	}
	if got[2] != `{"Action":["s3:ListBucketVersions","s3:ListBucketMultipartUploads"],"Condition":{`+notService+`,`+vpce("core-s3")+`},"Effect":"Deny","Principal":"*","Resource":"`+b+`","Sid":"DenyOutsidePrivateAccess"}` {
		t.Errorf("bucket listings: %s", got[2])
	}
	if got[3] != `{"Action":["s3:ListBucket"],"Condition":{`+notVia+`,`+vpce("core-s3")+`},"Effect":"Deny","Principal":"*","Resource":"`+b+`","Sid":"DenyOutsidePrivateAccessButThroughAWS"}` {
		t.Errorf("bucket list: %s", got[3])
	}
	// A registry's repositories: pulls and pushes, through either ECR
	// endpoint. A repository policy names no resource.
	ecr := `{"Action":` + ecrActions + `,"Condition":{` + notService + `,` + vpce("core-ecr-api", "core-ecr-dkr") + `},"Effect":"Deny","Principal":"*","Sid":"DenyOutsidePrivateAccess"}`
	if got := statements(t, object(t, r, "aws", awsRepoTmpl, "shopacr")["RepositoryPolicy"]); !reflect.DeepEqual(got, []string{ecr}) {
		t.Errorf("registry: %v", got)
	}
	// What is closed no longer widens. What stays: a secret's value and a
	// bucket's object names, through AWS's own services, where no Azure
	// service passed the source's firewall.
	wantW := []string{"Microsoft.KeyVault/vaults shop/shopkv properties.networkAcls", "Microsoft.Storage/storageAccounts shop/shopfiles properties.publicNetworkAccess"}
	if got := widening(r); !reflect.DeepEqual(got, wantW) {
		t.Errorf("widening: %v", got)
	}
	for src, about := range map[string]string{"Microsoft.KeyVault/vaults shop/shopkv": "CloudFormation resolving a reference", "Microsoft.Storage/storageAccounts shop/shopfiles": "names can still be listed"} {
		if l := lossAbout(entry(t, r, src), about); l == nil || !l.Widens || !strings.Contains(l.Why, "no Azure service passed it") {
			t.Errorf("%s: %+v", src, entry(t, r, src).Losses)
		}
	}
	for _, s := range []string{"Service Bus namespace shop/shopbus's queues and topics answer only through the interface endpoint(s) core-sqs, core-sns", "Key Vault shop/shopkv's secrets answer only", "Registry shop/shopacr's repositories under shopacr/ answer pulls and pushes only", "Storage account shop/shopfiles's buckets answer only", "does not get the template's policy"} {
		if !anyRequirement(r, s) {
			t.Errorf("no requirement about %q", s)
		}
	}
}

// The policies deny data actions only. Nothing the types' own Cloud
// Control handlers call to read, update, list or delete them is denied
// outright, so the restore, a later capture and the console keep working
// from outside the network, as Azure's management plane did; what a
// handler does call passes through AWS's services. Every deny lets AWS's
// own service principals through, and none grants or uses a wildcard.
func TestLockdownLeavesManagementAlone(t *testing.T) {
	handlers := func(file string) map[string]bool {
		var s struct {
			Handlers map[string]struct {
				Permissions []string `json:"permissions"`
			} `json:"handlers"`
		}
		b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "aws", "schemas", file+".json"))
		if os.IsNotExist(err) {
			b, err = os.ReadFile(filepath.Join("testdata", "aws", file+".json"))
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &s); err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, h := range []string{"read", "update", "list", "delete"} {
			for _, p := range s.Handlers[h].Permissions {
				out[p] = true
			}
		}
		if len(out) == 0 {
			t.Fatalf("%s: no handler permissions", file)
		}
		return out
	}
	guarded := map[string][]string{
		awsPolicy:       {"aws-sqs-queue", "aws-sqs-queueinlinepolicy"},
		awsTopicPolicy:  {"aws-sns-topic", "aws-sns-topicinlinepolicy", "aws-sns-subscription"},
		awsSecretPolicy: {"aws-secretsmanager-secret", "aws-secretsmanager-resourcepolicy"},
		awsBucketPolicy: {"aws-s3-bucket", "aws-s3-bucketpolicy"},
		awsRepoTmpl:     {"aws-ecr-repository", "aws-ecr-repositorycreationtemplate"},
	}
	field := map[string]string{awsPolicy: "PolicyDocument", awsTopicPolicy: "PolicyDocument", awsSecretPolicy: "ResourcePolicy", awsBucketPolicy: "PolicyDocument", awsRepoTmpl: "RepositoryPolicy"}
	r := runPE(t, peFixture(), peMaps()["aws"])
	seen, managed := map[string]int{}, 0
	for _, o := range r.Snapshots["aws"].Objects {
		files := guarded[o.Kind()]
		if files == nil {
			continue
		}
		needs := map[string]bool{}
		for _, f := range files {
			for p := range handlers(f) {
				needs[p] = true
			}
		}
		doc := o.Body["spec"].(map[string]any)[field[o.Kind()]]
		if s, ok := doc.(string); ok {
			var m map[string]any
			if err := json.Unmarshal([]byte(s), &m); err != nil {
				t.Fatal(err)
			}
			doc = m
		}
		for _, x := range list(obj(doc)["Statement"]) {
			st := obj(x)
			sid, _ := st["Sid"].(string)
			if sid != lockSid && sid != lockSidManaged {
				continue
			}
			seen[o.Kind()]++
			cond := obj(obj(st["Condition"])["BoolIfExists"])
			if st["Effect"] != "Deny" || cond["aws:PrincipalIsAWSService"] != "false" {
				t.Errorf("%s %s: %v", o.Key(), sid, st)
			}
			if sid == lockSidManaged {
				managed++
				if cond["aws:ViaAWSService"] != "false" {
					t.Errorf("%s: a handler's action is denied to AWS's services too: %v", o.Key(), st)
				}
			} else if _, ok := cond["aws:ViaAWSService"]; ok {
				t.Errorf("%s: a data action passes through AWS's services: %v", o.Key(), st)
			}
			for _, a := range list(st["Action"]) {
				act := a.(string)
				if strings.Contains(act, "*") {
					t.Errorf("%s: wildcard action %s", o.Key(), act)
				}
				if needs[act] != (sid == lockSidManaged) {
					t.Errorf("%s %s: %s; its handlers call it: %v", o.Key(), sid, act, needs[act])
				}
			}
		}
	}
	if !reflect.DeepEqual(seen, map[string]int{awsPolicy: 4, awsTopicPolicy: 1, awsSecretPolicy: 2, awsBucketPolicy: 3, awsRepoTmpl: 1}) || managed != 2 {
		t.Errorf("deny statements: %v, %d managed", seen, managed)
	}
}

// A private service with no private endpoint in the snapshot, and no
// public range, has nothing to be locked to: it stays reported as less
// protected, and no policy is invented for it.
func TestLockdownNeedsAPrivatePath(t *testing.T) {
	r := runPE(t, lockFixture(false, nil), peMaps()["aws"])
	want := []string{
		"Microsoft.ContainerRegistry/registries shop/shopacr properties.networkRuleSet",
		"Microsoft.KeyVault/vaults shop/shopkv properties.networkAcls",
		"Microsoft.ServiceBus/namespaces shop/shopbus properties.publicNetworkAccess",
		"Microsoft.Storage/storageAccounts shop/shopfiles properties.publicNetworkAccess",
	}
	if got := widening(r); !reflect.DeepEqual(got, want) {
		t.Errorf("widening: %v", got)
	}
	for _, w := range want {
		e := entry(t, r, w[:strings.LastIndex(w, " ")])
		if l := hasLoss(e, w[strings.LastIndex(w, " ")+1:]); l == nil || !strings.Contains(l.Why, "there is no private path to lock it to") {
			t.Errorf("%s: %+v", w, e.Losses)
		}
	}
	for _, o := range r.Snapshots["aws"].Objects {
		s := canonJSON(o.Body)
		if strings.Contains(s, lockSid) || strings.Contains(s, "aws:SourceVpce") || o.Kind() == awsTopicPolicy || o.Kind() == awsSecretPolicy {
			t.Errorf("a lock with nothing to lock to: %s", o.Key())
		}
	}
	// The subscription's queue keeps its delivery policy, alone.
	if got := statements(t, object(t, r, "aws", awsPolicy, "events-audit")["PolicyDocument"]); len(got) != 1 || !strings.Contains(got[0], `"Effect":"Allow"`) {
		t.Errorf("subscription queue: %v", got)
	}
	// A private endpoint that is refused (its network is not translated)
	// is no path either.
	m := peMaps()["aws"]
	m.Destinations.Network, m.Network = "", nil
	if got := widening(runPE(t, peFixture(), m)); !reflect.DeepEqual(got, want) {
		t.Errorf("widening with no network: %v", got)
	}
	// On GCP the bucket admits no network, which is narrower, not wider.
	g := runPE(t, lockFixture(false, nil), peMaps()["gcp"])
	if got := canonJSON(object(t, g, "gcp", gcsBucket, "shopfiles-docs")["ipFilter"]); got != `{"allowAllServiceAgentAccess":false,"allowCrossOrgVpcs":false,"mode":"Enabled"}` {
		t.Errorf("gcp bucket: %s", got)
	}
	if l := hasLoss(entry(t, g, "Microsoft.Storage/storageAccounts shop/shopfiles"), "properties.publicNetworkAccess"); l == nil || l.Widens || !strings.Contains(l.Why, "admits no network") {
		t.Errorf("gcp account: %+v", l)
	}
}

func lockFirewalls() map[string]func(map[string]any) {
	rules := []any{map[string]any{"value": "203.0.113.0/24", "action": "Allow"}, map[string]any{"value": "198.51.100.7"}}
	return map[string]func(map[string]any){
		lockBus: func(p map[string]any) { p["publicNetworkAccess"] = "Enabled" },
		lockKV: func(p map[string]any) {
			p["publicNetworkAccess"] = "Enabled"
			p["networkAcls"] = map[string]any{"defaultAction": "Deny", "bypass": "AzureServices", "ipRules": rules,
				"virtualNetworkRules": []any{map[string]any{"id": "x"}}}
		},
		lockACR: func(p map[string]any) {
			p["publicNetworkAccess"] = "Enabled"
			p["networkRuleSet"] = map[string]any{"defaultAction": "Deny", "ipRules": rules}
		},
		lockSt: func(p map[string]any) {
			p["publicNetworkAccess"] = "Enabled"
			p["networkAcls"] = map[string]any{"defaultAction": "Deny", "bypass": "AzureServices", "ipRules": rules}
		},
	}
}

// A firewall that denied by default and allowed public ranges: the ranges
// are let through beside the endpoints, in the same statement, and alone
// where there is no endpoint.
func TestLockdownHonoursAllowedRanges(t *testing.T) {
	s := lockFixture(true, lockFirewalls())
	s.Objects = append(s.Objects, az("Microsoft.ServiceBus/namespaces/networkRuleSets", "shop", "shopbus/default", pr(map[string]any{
		"defaultAction": "Deny", "publicNetworkAccess": "Enabled", "ipRules": []any{map[string]any{"ipMask": "203.0.113.0/24", "action": "Allow"}, map[string]any{"ipMask": "198.51.100.7", "action": "Allow"}},
		"virtualNetworkRules": []any{map[string]any{"subnet": map[string]any{"id": "x"}}}})))
	r := runPE(t, s, peMaps()["aws"])
	ranges := `"NotIpAddress":{"aws:SourceIp":["203.0.113.0/24","198.51.100.7/32"]}`
	cond := func(st string, endpoints ...string) {
		t.Helper()
		if !strings.Contains(st, `"Condition":{"BoolIfExists":{"aws:PrincipalIsAWSService":"false"`) || !strings.Contains(st, ranges) || !strings.Contains(st, vpce(endpoints...)) {
			t.Errorf("%v: %s", endpoints, st)
		}
	}
	cond(statements(t, object(t, r, "aws", awsPolicy, "orders")["PolicyDocument"])[0], "core-sqs")
	cond(statements(t, object(t, r, "aws", awsTopicPolicy, "events")["PolicyDocument"])[0], "core-sns")
	for _, st := range statements(t, secretPolicy(t, r)["ResourcePolicy"]) {
		cond(st, "core-secretsmanager")
	}
	for _, st := range statements(t, object(t, r, "aws", awsBucketPolicy, "shopfiles-docs")["PolicyDocument"])[2:] {
		cond(st, "core-s3")
	}
	cond(statements(t, object(t, r, "aws", awsRepoTmpl, "shopacr")["RepositoryPolicy"])[0], "core-ecr-api", "core-ecr-dkr")
	// Azure's trusted services passed the vault's and the account's
	// firewalls, as AWS's pass the policies: nothing widens.
	if got := widening(r); len(got) != 0 {
		t.Errorf("widening: %v", got)
	}
	for src, about := range map[string]string{"Microsoft.KeyVault/vaults shop/shopkv": "Azure's trusted services passed it", "Microsoft.Storage/storageAccounts shop/shopfiles": "Azure's trusted services passed it"} {
		if l := lossAbout(entry(t, r, src), about); l == nil || l.Widens {
			t.Errorf("%s: %+v", src, entry(t, r, src).Losses)
		}
	}
	// Subnets let in by service endpoint are narrowed, and said so.
	for src, f := range map[string]string{"Microsoft.KeyVault/vaults shop/shopkv": "properties.networkAcls.virtualNetworkRules", "Microsoft.ServiceBus/namespaces shop/shopbus": "networkRuleSets.properties.virtualNetworkRules"} {
		if l := hasLoss(entry(t, r, src), f); l == nil || l.Widens {
			t.Errorf("%s: %+v", src, entry(t, r, src).Losses)
		}
	}
	// With no endpoint, the ranges alone: a request through any VPC
	// endpoint has no aws:SourceIp, and is denied.
	n := lockFixture(false, lockFirewalls())
	rn := runPE(t, n, peMaps()["aws"])
	st := statements(t, secretPolicy(t, rn)["ResourcePolicy"])[0]
	if !strings.Contains(st, `"Condition":{`+notService+`,`+ranges+`}`) {
		t.Errorf("ranges alone: %s", st)
	}
	if got := widening(rn); len(got) != 0 {
		t.Errorf("widening with ranges alone: %v", got)
	}
	// With public network access disabled Azure ignored the firewall's
	// ranges: so does the bucket's policy.
	fw := lockFirewalls()
	shut := fw[lockSt]
	fw[lockSt] = func(p map[string]any) { shut(p); p["publicNetworkAccess"] = "Disabled" }
	for _, st := range statements(t, object(t, runPE(t, lockFixture(true, fw), peMaps()["aws"]), "aws", awsBucketPolicy, "shopfiles-docs")["PolicyDocument"])[2:] {
		if strings.Contains(st, "aws:SourceIp") || !strings.Contains(st, vpce("core-s3")) {
			t.Errorf("a closed account's ranges: %s", st)
		}
	}
	// On GCP the bucket admits the ranges and the network.
	g := runPE(t, s, peMaps()["gcp"])
	if got := canonJSON(object(t, g, "gcp", gcsBucket, "shopfiles-docs")["ipFilter"]); got != `{"allowAllServiceAgentAccess":false,"allowCrossOrgVpcs":false,"mode":"Enabled","publicNetworkSource":{"allowedIpCidrRanges":["203.0.113.0/24","198.51.100.7/32"]},"vpcNetworkSources":[{"allowedIpCidrRanges":["10.30.0.0/16"],"network":"projects/{{truthform|project}}/global/networks/core"}]}` {
		t.Errorf("gcp bucket: %s", got)
	}
}

// A service that answered the internet gets no deny, private endpoint or
// not, on either target.
func TestLockdownLeavesPublicServicesOpen(t *testing.T) {
	open := func(p map[string]any) { p["publicNetworkAccess"] = "Enabled" }
	s := lockFixture(true, map[string]func(map[string]any){
		lockBus: func(p map[string]any) {
			open(p)
			p["privateEndpointConnections"] = []any{map[string]any{"id": "x"}}
		},
		lockKV: open, lockACR: open, lockSt: open})
	r := runPE(t, s, peMaps()["aws"])
	for _, o := range r.Snapshots["aws"].Objects {
		if b := canonJSON(o.Body); strings.Contains(b, lockSid) || strings.Contains(b, "aws:SourceVpce") || strings.Contains(b, "aws:SourceIp") || o.Kind() == awsTopicPolicy || o.Kind() == awsSecretPolicy {
			t.Errorf("a public service is locked: %s", o.Key())
		}
	}
	if object(t, r, "aws", awsRepoTmpl, "shopacr")["RepositoryPolicy"] != nil {
		t.Error("a public registry's repositories have a policy")
	}
	if got := widening(r); len(got) != 0 {
		t.Errorf("aws widening: %v", got)
	}
	g := runPE(t, s, peMaps()["gcp"])
	if f := object(t, g, "gcp", gcsBucket, "shopfiles-docs")["ipFilter"]; f != nil {
		t.Errorf("a public account's bucket has an IP filter: %v", f)
	}
	for _, w := range widening(g) {
		if !strings.HasSuffix(w, "properties.minimumTlsVersion") && !strings.HasSuffix(w, "properties.enableSoftDelete") {
			t.Errorf("gcp widening: %s", w)
		}
	}
	if anyRequirement(g, "VPC Service Controls") || anyRequirement(r, "resource policy denies") {
		t.Error("a requirement to close a public service")
	}
}

// On GCP a bucket's IP filter names the networks that had a private
// endpoint to its account, with their own ranges. Pub/Sub, Secret Manager
// and Artifact Registry have no such setting: where the map names no
// access policy they stay less protected, and the report names the map
// keys that have their perimeter written (perimeter_test.go).
func TestLockdownOnGCP(t *testing.T) {
	r := runPE(t, peFixture(), peMaps()["gcp"])
	if got := canonJSON(object(t, r, "gcp", gcsBucket, "shopfiles-docs")["ipFilter"]); got != `{"allowAllServiceAgentAccess":false,"allowCrossOrgVpcs":false,"mode":"Enabled","vpcNetworkSources":[{"allowedIpCidrRanges":["10.30.0.0/16"],"network":"projects/{{truthform|project}}/global/networks/core"}]}` {
		t.Errorf("bucket: %s", got)
	}
	acct := entry(t, r, "Microsoft.Storage/storageAccounts shop/shopfiles")
	if l := hasLoss(acct, "properties.publicNetworkAccess"); l != nil {
		t.Errorf("a closed account whose network is admitted loses: %+v", l)
	}
	want := []string{
		"Microsoft.ContainerRegistry/registries shop/shopacr properties.networkRuleSet",
		"Microsoft.KeyVault/vaults shop/shopkv properties.enableSoftDelete",
		"Microsoft.KeyVault/vaults shop/shopkv properties.networkAcls",
		"Microsoft.ServiceBus/namespaces shop/shopbus properties.minimumTlsVersion",
		"Microsoft.ServiceBus/namespaces shop/shopbus properties.publicNetworkAccess",
		"Microsoft.Storage/storageAccounts shop/shopfiles properties.minimumTlsVersion",
	}
	if got := widening(r); !reflect.DeepEqual(got, want) {
		t.Errorf("widening: %v", got)
	}
	for src, api := range map[string]string{
		"Microsoft.ContainerRegistry/registries shop/shopacr properties.networkRuleSet": "artifactregistry.googleapis.com",
		"Microsoft.KeyVault/vaults shop/shopkv properties.networkAcls":                  "secretmanager.googleapis.com",
		"Microsoft.ServiceBus/namespaces shop/shopbus properties.publicNetworkAccess":   "pubsub.googleapis.com",
	} {
		i := strings.LastIndex(src, " ")
		l := hasLoss(entry(t, r, src[:i]), src[i+1:])
		if l == nil || !l.Widens || !strings.Contains(l.Why, "VPC Service Controls perimeter") || !strings.Contains(l.Why, api+", for the whole project") || !strings.Contains(l.Why, "written only into an access policy the map names (privateAccess.accessPolicy)") {
			t.Errorf("%s: %+v", src, l)
		}
		if !anyRequirement(r, "a VPC Service Controls perimeter is then written that restricts "+api+" for the whole target project") {
			t.Errorf("no perimeter named for %s: %v", api, r.Report.Requirements)
		}
	}
	for _, s := range []string{"storage.buckets.exemptFromIpFilter", "admit the VPC network(s) core by their own address ranges", "privateAccess.restoreIdentity: serviceAccount:<email>, or privateAccess.restoreFromInside: true"} {
		if !anyRequirement(r, s) {
			t.Errorf("no requirement about %q", s)
		}
	}
	// No object of Access Context Manager is written.
	for _, o := range r.Snapshots["gcp"].Objects {
		if strings.Contains(o.Kind(), "accesscontextmanager") {
			t.Errorf("a perimeter is written: %s", o.Key())
		}
	}
}

// A filter takes 25 networks at most: with more, none is admitted, which
// is said and is not wider.
func TestLockdownBucketFilterLimits(t *testing.T) {
	o := &out{private: map[string]*privatePath{}}
	p := o.privatePathFor(azStorage, "shop/big")
	for i := 0; i < gcsMaxFilterNetworks+1; i++ {
		p.networks["n"+string(rune('a'+i))] = []string{"10.0.0.0/8"}
	}
	a := &stAccount{group: "shop", name: "big", private: "closed", closed: true}
	if nets, over := a.gcsNetworks(o); nets != nil || !strings.Contains(over, "25 networks") {
		t.Errorf("%v %q", nets, over)
	}
	delete(p.networks, "na")
	if nets, over := a.gcsNetworks(o); len(nets) != gcsMaxFilterNetworks || over != "" {
		t.Errorf("%d %q", len(nets), over)
	}
}

// A firewall rule that is not an address allows nothing, and is named.
func TestLockdownRanges(t *testing.T) {
	rs, bad := lockRanges([]any{map[string]any{"value": "203.0.113.9"}, map[string]any{"value": "2001:db8::/32", "action": "Allow"},
		map[string]any{"value": "10.0.0.1/8"}, map[string]any{"value": "office"}, map[string]any{"value": "192.0.2.0/24", "action": "Deny"}}, "value")
	if !reflect.DeepEqual(rs, []string{"203.0.113.9/32", "2001:db8::/32", "10.0.0.0/8"}) || !reflect.DeepEqual(bad, []string{"office", "192.0.2.0/24 (Deny)"}) {
		t.Errorf("%v %v", rs, bad)
	}
}
