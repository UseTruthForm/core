package awscc

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Messages from the full us-east-2 capture (2026-10-21), trimmed. Account
// state and schema gaps must not read as a broken run; permissions,
// throttling and anything unrecognised must.
func TestClassifyList(t *testing.T) {
	cases := []struct {
		msg  string
		want error // nil: stays a failure
	}{
		{"api error AccessDeniedException: AWS::AuditManager::Assessment Handler returned status FAILED: Please complete AWS Audit Manager setup from home page to enable this action in this account (HandlerErrorCode: AccessDenied, RequestToken: 2b57)", ErrNotSetUp},
		{"InvalidRequestException: AWS::AWSExternalAnthropic::Workspace Handler returned status FAILED: Invalid request provided: Your account has not subscribed to this service yet.", ErrNotSetUp},
		{"ResourceNotFoundException: AWS::ControlTower::EnabledControl Handler returned status FAILED: AWS Control Tower cannot complete the operation, because you must create a landing zone first. (Service: ControlTower, Status Code: 404)", ErrNotSetUp},
		{"InvalidRequestException: AWS::AutoScaling::LifecycleHook Handler returned status FAILED: AutoScalingGroupName is required to list LifecycleHooks. (HandlerErrorCode: InvalidRequest)", ErrNeedsInput},
		{"InvalidRequestException: Missing Or Invalid ResourceModel property in AWS::ApiGatewayV2::ApiMapping list handler request input. Required property: [DomainName]", ErrNeedsInput},
		{"HandlerInternalFailureException: AWS::ApiGatewayV2::RouteResponse Handler returned status FAILED: Unable to marshall request to JSON: Parameter 'apiId' must not be null", ErrNeedsInput},
		{"ThrottlingException: Rate exceeded\nfailed to get rate limit token, retry quota exceeded, 0 available, 5 requested", nil},
		{"AccessDenied: User: arn:aws:iam::1:user/x is not authorized to perform: iam:GetRole on resource: role y", nil},
		{"GeneralServiceException: something AWS has never said before", nil},
	}
	for _, c := range cases {
		got := classifyList(errors.New(c.msg))
		switch {
		case c.want == nil && (errors.Is(got, ErrNotSetUp) || errors.Is(got, ErrNeedsInput)):
			t.Errorf("must stay a failure, got %v\n  %s", got, c.msg)
		case c.want != nil && !errors.Is(got, c.want):
			t.Errorf("want %v, got %v\n  %s", c.want, got, c.msg)
		}
	}
}

// Request IDs change on every run; left in a reason they would make
// coverage.yaml differ between two captures of an unchanged account.
func TestCleanMessageDropsRequestIDs(t *testing.T) {
	got := cleanMessage("operation error CloudControl: GetResource, https response error StatusCode: 500, RequestID: 44f5, HandlerInternalFailureException: AWS::CodePipeline::CustomActionType Handler returned status FAILED: Service returned error code ResourceNotFoundException (Service: CodePipeline, Status Code: 400, Request ID: 9cd7) (SDK Attempt Count: 1) (HandlerErrorCode: InternalFailure, RequestToken: 4450)")
	if got != "Service returned error code ResourceNotFoundException" {
		t.Errorf("got %q", got)
	}
}

func TestAccountIDIsNeverAReference(t *testing.T) {
	if refable("AccountId", "999988887777") {
		t.Error("an account ID must not become a reference")
	}
	reg := fixtures(t)
	sub := normalize(reg.Types["AWS::SQS::Queue"], "q", map[string]any{"QueueName": "q", "QueueUrl": "https://x/123456789012/q", "Arn": "arn:aws:sqs:r:123456789012:q"})
	sub.stat["AccountId"] = "123456789012"
	// An AWS-generated identifier equal to the account ID, as
	// Organizations::Account's is. (A user-chosen one could never match.)
	other := normalize(reg.Types["AWS::EC2::VPC"], "123456789012", map[string]any{"VpcId": "123456789012", "CidrBlock": "10.0.0.0/16"})
	markCreatedBy([]*resource{sub, other})
	if other.createdBy != nil {
		t.Errorf("resource marked as created by the queue through the account ID")
	}
}

// The VPC's main route-table association is listed but unreadable; it is
// AWS's, created with the VPC, and must not make every capture incomplete.
func TestMainRouteTableAssociationIsAWS(t *testing.T) {
	e := newEnv(t)
	e.src.Unreadable = map[string]bool{}
	for _, id := range e.src.IDs("AWS::SQS::Queue") {
		e.src.Unreadable["AWS::SQS::Queue|"+id] = true
	}
	e.src.UnreadableMsg = "The RouteTableAssociation does not belong to a subnet"
	snap, err := e.adapter(e.src).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range snap.Skips {
		if s.Resource == "AWS::SQS::Queue" && !strings.HasPrefix(s.Reason, OwnedByAWS) {
			t.Errorf("main association recorded as %q", s.Reason)
		}
	}
}

// A resource that is listed but cannot be read is recorded by identifier;
// the rest of its type is still captured.
func TestUnreadableResourceKeepsItsType(t *testing.T) {
	e := newEnv(t)
	bad := ""
	for _, id := range e.src.IDs("AWS::S3::Bucket") {
		if id == "shop-assets" {
			bad = id
		}
	}
	e.src.Unreadable = map[string]bool{"AWS::S3::Bucket|" + bad: true}
	snap, err := e.adapter(e.src).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range snap.Skips {
		if s.Resource == "AWS::S3::Bucket" && s.Name == bad {
			found = strings.HasPrefix(s.Reason, Unreadable) && !strings.Contains(s.Reason, "Request ID")
		}
	}
	if !found {
		t.Errorf("unreadable bucket not recorded cleanly: %+v", snap.Skips)
	}
	for _, c := range snap.Coverage {
		if c.Resource == "AWS::S3::Bucket" && c.NotCaptured != "" {
			t.Errorf("one unreadable bucket dropped the type: %s", c.NotCaptured)
		}
	}
}

// More messages from the full capture: services not offered in the region
// are not available there; not-onboarded services hold nothing.
func TestClassifyListRegionAndOnboarding(t *testing.T) {
	for msg, want := range map[string]error{
		"AWS::GameLift::MatchmakingConfiguration Handler returned status FAILED: This region is not supported.":                                             ErrUnsupported,
		"AWS::IoTAnalytics::Channel Handler returned status FAILED: Received an UnknownHostException when attempting to interact with a service.":           ErrUnsupported,
		"AWS::ODB::OdbNetwork Handler returned status FAILED: Can't process the request because the account isn't onboarded to the service.":                ErrNotSetUp,
		"AWS::Shield::Protection Handler returned status FAILED: The subscription does not exist.":                                                          ErrNotSetUp,
		"AWS::SecurityHub::ConnectorV2 Handler returned status FAILED: Security Hub V2 is not enabled for 123456789012":                                     ErrNotSetUp,
		"AWS::Macie::AllowList Handler returned status FAILED: The request failed because Macie isn’t enabled in the specified AWS Region.":                 ErrNotSetUp,
		"AWS::FMS::Policy Handler returned status FAILED: No default admin could be found for account 1 in Region us-east-2":                                ErrNotSetUp,
		"AWS::GlobalAccelerator::Listener Handler returned status FAILED: AcceleratorArn is required argument":                                              ErrNeedsInput,
		"AWS::EC2::EnclaveCertificateIamRoleAssociation Handler returned status FAILED: Invalid request provided: Property CertificateArn cannot be empty.": ErrNeedsInput,
	} {
		if got := classifyList(errors.New(msg)); !errors.Is(got, want) {
			t.Errorf("want %v, got %v\n  %s", want, got, msg)
		}
	}
}

// A child of a parent that cannot be captured by design is itself a gap,
// not a failure: ClientVpnRoute under the legacy ClientVpnEndpoint failed
// the whole capture before.
func TestInheritParentReason(t *testing.T) {
	for parent, prefix := range map[string]string{
		"legacy type: CloudFormation only, Cloud Control has no handlers for it": NeedsInput,
		NotSetUp + "x": NotSetUp,
		"not available in this account or region": NotSetUp,
		"list failed: boom":                       "list failed: ",
	} {
		if got := inherit("AWS::X::Parent", parent); !strings.HasPrefix(got, prefix) {
			t.Errorf("parent %q: got %q, want prefix %q", parent, got, prefix)
		}
	}
}

// WAFv2 lists per Scope, and AWS rejects CLOUDFRONT outside us-east-1. The
// rejected value is skipped; REGIONAL resources are still captured.
func TestRejectedEnumValueIsSkipped(t *testing.T) {
	str := map[string]any{"type": "string"}
	ipset := &TypeInfo{Name: "AWS::WAFv2::IPSet", PrimaryIdentifier: []string{"Name", "Id", "Scope"}, ListRequires: []string{"Scope"},
		Handlers:   map[string]bool{"list": true, "read": true, "create": true},
		Properties: map[string]any{"Name": str, "Id": str, "Scope": map[string]any{"type": "string", "enum": []any{"CLOUDFRONT", "REGIONAL"}}}}
	reg := &Registry{Types: map[string]*TypeInfo{ipset.Name: ipset}}
	f := NewWorld(reg).Account(srcAccount, "us-east-2")
	f.Seed(ipset.Name, map[string]any{"Name": "office", "Id": "abc123", "Scope": "REGIONAL"})
	f.ListError = func(_ string, m map[string]any) error {
		if m["Scope"] == "CLOUDFRONT" {
			return errors.New("InvalidRequestException: Error reason: The scope is not valid., field: SCOPE_VALUE, parameter: CLOUDFRONT")
		}
		return nil
	}
	snap, err := Capture(context.Background(), f, reg, "us-east-2", Policy{}, Tuning{})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Objects) != 1 || snap.Coverage[0].NotCaptured != "" {
		t.Fatalf("objects %d, coverage %+v", len(snap.Objects), snap.Coverage)
	}
}

// A throttled list is retried by the inventory (with its slot released)
// until AWS answers, and the type is captured, not reported failed.
func TestThrottledListIsRetried(t *testing.T) {
	e := newEnv(t)
	throttles := 2
	e.src.ListError = func(typ string, _ map[string]any) error {
		if typ == "AWS::SQS::Queue" && throttles > 0 {
			throttles--
			return errors.New("ThrottlingException: Rate exceeded")
		}
		return nil
	}
	a := e.adapter(e.src)
	a.Tuning = Tuning{Parallel: 1}
	snap, err := a.Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if throttles != 0 {
		t.Fatalf("retries not exhausted the throttles: %d left", throttles)
	}
	for _, c := range snap.Coverage {
		if c.Resource == "AWS::SQS::Queue" && (c.NotCaptured != "" || c.Captured != 1) {
			t.Errorf("queue coverage %+v", c)
		}
	}
}
