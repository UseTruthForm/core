// Package kubetest starts a real Kubernetes API server (etcd plus
// kube-apiserver, no nodes, no Docker) for tests. Truthform only talks to the
// API, so this is enough to exercise capture, restore and diff against real
// discovery, real OpenAPI schemas and real validation, in seconds.
//
// It exists instead of controller-runtime's envtest because envtest's Go
// library does not compile on Windows at v0.25.2 ("signalProcess redeclared"),
// and the release that does (v0.23.3) pins older Kubernetes libraries than
// Truthform uses. The binaries are the same ones envtest uses; fetch them with
// scripts/envtest-assets.sh.
package kubetest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// AssetsEnv names the directory holding etcd and kube-apiserver.
// KUBEBUILDER_ASSETS is accepted too, as setup-envtest prints it.
const AssetsEnv = "TRUTHFORM_KUBE_ASSETS"

// RequireEnv, when set (CI does), turns a missing binary into a failure.
// Otherwise the test is skipped with a message: a silently skipped test
// reads as a pass, so CI must never be allowed to skip.
const RequireEnv = "TRUTHFORM_REQUIRE_KUBE_ASSETS"

// renamed says which variable is still set under the tool's old name, if
// one is. Builds before the rename read these under STACKDNA_. Left there
// they are read by nothing: the assets are not found, the "require" switch
// is off, and every test here skips, which CI shows as a pass. That holds
// with KUBEBUILDER_ASSETS set as well, for the "require" switch; a
// leftover is refused in every case so the rule stays one line.
func renamed() string {
	for _, env := range []string{AssetsEnv, RequireEnv} {
		old := "STACKDNA_" + strings.TrimPrefix(env, "TRUTHFORM_")
		if os.Getenv(old) != "" && os.Getenv(env) == "" {
			return fmt.Sprintf("%s is set, and this build reads %s: rename the variable, or unset it", old, env)
		}
	}
	return ""
}

// Server is a running API server and the kubeconfig that reaches it.
type Server struct {
	// Kubeconfig is a file with one context, named Context.
	Kubeconfig string
	Context    string
	stop       func()
}

// Start launches etcd and kube-apiserver for the duration of the test.
func Start(t *testing.T, name string) *Server {
	t.Helper()
	if msg := renamed(); msg != "" {
		t.Fatal(msg)
	}
	assets := os.Getenv(AssetsEnv)
	if assets == "" {
		assets = os.Getenv("KUBEBUILDER_ASSETS")
	}
	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	etcdBin := filepath.Join(assets, "etcd"+exe)
	apiBin := filepath.Join(assets, "kube-apiserver"+exe)
	if _, err := os.Stat(apiBin); assets == "" || err != nil {
		msg := fmt.Sprintf("kube-apiserver not found (set %s; run scripts/envtest-assets.sh)", AssetsEnv)
		if os.Getenv(RequireEnv) != "" {
			t.Fatal(msg)
		}
		t.Skip(msg)
	}

	dir := t.TempDir()
	etcdClient, etcdPeer, apiPort := freePort(t), freePort(t), freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	var logs bytes.Buffer

	etcd := exec.CommandContext(ctx, etcdBin,
		"--data-dir", filepath.Join(dir, "etcd"),
		"--listen-client-urls", "http://127.0.0.1:"+strconv.Itoa(etcdClient),
		"--advertise-client-urls", "http://127.0.0.1:"+strconv.Itoa(etcdClient),
		"--listen-peer-urls", "http://127.0.0.1:"+strconv.Itoa(etcdPeer),
		"--unsafe-no-fsync",
	)
	etcd.Stdout, etcd.Stderr = &logs, &logs
	if err := etcd.Start(); err != nil {
		cancel()
		t.Fatalf("start etcd: %v", err)
	}

	saKey := filepath.Join(dir, "sa.key")
	writeKey(t, saKey)
	token := randomHex(t)
	tokens := filepath.Join(dir, "tokens.csv")
	// A static admin token in system:masters: enough authority for a test
	// cluster, and no client certificates to generate.
	if err := os.WriteFile(tokens, []byte(token+",truthform-test,truthform-test,system:masters\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	api := exec.CommandContext(ctx, apiBin,
		"--etcd-servers", "http://127.0.0.1:"+strconv.Itoa(etcdClient),
		"--bind-address", "127.0.0.1",
		"--secure-port", strconv.Itoa(apiPort),
		"--cert-dir", filepath.Join(dir, "certs"), // self-signed serving cert
		"--token-auth-file", tokens,
		"--authorization-mode", "RBAC",
		"--service-account-key-file", saKey,
		"--service-account-signing-key-file", saKey,
		"--service-account-issuer", "https://kubernetes.default.svc",
		"--service-cluster-ip-range", "10.0.0.0/24",
		"--disable-admission-plugins", "ServiceAccount",
		"--allow-privileged",
	)
	api.Stdout, api.Stderr = &logs, &logs
	if err := api.Start(); err != nil {
		cancel()
		t.Fatalf("start kube-apiserver: %v", err)
	}
	stop := func() {
		cancel()
		_ = api.Wait()
		_ = etcd.Wait()
	}

	url := "https://127.0.0.1:" + strconv.Itoa(apiPort)
	if err := waitReady(url, token, 60*time.Second); err != nil {
		stop()
		t.Fatalf("API server %s never became ready: %v\n--- logs ---\n%s", name, err, tail(logs.String(), 4000))
	}
	t.Cleanup(stop)

	kc := filepath.Join(dir, "kubeconfig")
	cfg := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: %[1]s
  cluster: {server: "%[2]s", insecure-skip-tls-verify: true}
users:
- name: %[1]s
  user: {token: "%[3]s"}
contexts:
- name: %[1]s
  context: {cluster: %[1]s, user: %[1]s}
current-context: %[1]s
`, name, url, token)
	if err := os.WriteFile(kc, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Server{Kubeconfig: kc, Context: name, stop: stop}
}

func waitReady(url, token string, timeout time.Duration) error {
	// The serving certificate is self-signed per run; the test only ever talks
	// to the process it just started on loopback.
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(http.MethodGet, url+"/readyz", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			last = fmt.Errorf("readyz returned %d", resp.StatusCode)
		} else {
			last = err
		}
		time.Sleep(200 * time.Millisecond)
	}
	return last
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func writeKey(t *testing.T, path string) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func randomHex(t *testing.T) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}
