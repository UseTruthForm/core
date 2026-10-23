package awscc

import (
	"strings"
	"testing"

	"github.com/stackdna/core/internal/describe"
)

func field(d describe.Type, path string) describe.Field {
	for _, f := range d.Fields {
		if f.Path == path {
			return f
		}
	}
	return describe.Field{}
}

// What an agent is told about a type is what the registry schema marks.
func TestDescribe(t *testing.T) {
	reg := fixtures(t)
	q, err := reg.Describe("AWS::SQS::Queue")
	if err != nil {
		t.Fatal(err)
	}
	if !field(q, "FifoQueue").CreateOnly || !field(q, "QueueName").CreateOnly || !field(q, "Arn").ReadOnly || field(q, "VisibilityTimeout").CreateOnly {
		t.Errorf("SQS flags wrong: %+v", q.Fields)
	}
	if q.Docs[0] != "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-sqs-queue.html" {
		t.Errorf("docs %v", q.Docs)
	}
	sg, _ := reg.Describe("AWS::EC2::SecurityGroup")
	if !field(sg, "SecurityGroupIngress[].SourceSecurityGroupName").WriteOnly || field(sg, "SecurityGroupIngress").WriteOnly {
		t.Error("only the nested field is write-only")
	}
	if !field(sg, "GroupDescription").Required {
		t.Error("GroupDescription is required")
	}
	if _, err := reg.Describe("AWS::Nope::Thing"); err == nil || !strings.Contains(err.Error(), "not in the registry") {
		t.Errorf("unknown type: %v", err)
	}
}
