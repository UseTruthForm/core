package awscc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"

	"github.com/usetruthform/core/internal/readonly"
)

// The real Cloud Control client behind the guard: a list reaches the
// server, a create is refused before a byte is sent. Every Cloud Control
// call is POST /, so only the operation header tells them apart; this
// proves the guard reads it the way the SDK writes it.
func TestReadOnlyCloudControl(t *testing.T) {
	var mu sync.Mutex
	var targets []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		targets = append(targets, r.Header.Get("X-Amz-Target"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		w.Write([]byte(`{"ResourceDescriptions":[],"TypeName":"AWS::S3::Bucket"}`))
	}))
	defer srv.Close()
	s := &SDK{c: cloudcontrol.New(cloudcontrol.Options{
		Region: "us-east-2", BaseEndpoint: aws.String(srv.URL), HTTPClient: readonly.Client(),
		Credentials: credentials.NewStaticCredentialsProvider("AKID", "SECRET", ""),
	})}
	if _, _, err := s.List(context.Background(), "AWS::S3::Bucket", nil, ""); err != nil {
		t.Fatalf("list: %v", err)
	}
	_, err := s.Create(context.Background(), "AWS::S3::Bucket", map[string]any{"BucketName": "x"})
	if err == nil || !strings.Contains(err.Error(), "read-only guard") {
		t.Fatalf("create not refused: %v", err)
	}
	if strings.Join(targets, ",") != "CloudApiService.ListResources" {
		t.Fatalf("server saw %v; only the list may arrive", targets)
	}
}
