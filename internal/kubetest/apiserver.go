// Package kubetest starts a real Kubernetes API server (etcd plus
// kube-apiserver, no nodes, no Docker) for tests. TruthForm only talks to the
// API, so this is enough to exercise capture, restore and diff against real
// discovery, real OpenAPI schemas and real validation, in seconds.
//
// It exists instead of controller-runtime's envtest because envtest's Go
// library does not compile on Windows at v0.25.2 ("signalProcess redeclared"),
// and the release that does (v0.23.3) pins older Kubernetes libraries than
// TruthForm uses. The binaries are the same ones envtest uses; fetch them with
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
	"sync"
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

	s, err := start(name, etcdBin, apiBin, t.TempDir(), readyTimeout)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.stop)
	return s
}

// readyTimeout is how long etcd and kube-apiserver together have to start.
const readyTimeout = 60 * time.Second

// start launches the two and waits for both to answer. A failure says which
// stage it reached and what each process was doing: under load (a full
// parallel run on Windows) a start once failed only with "API server never
// became ready" and empty logs, which told nothing of why.
func start(name, etcdBin, apiBin, dir string, timeout time.Duration) (*Server, error) {
	deadline := time.Now().Add(timeout)
	ports, err := freePorts(3)
	if err != nil {
		return nil, err
	}
	etcdClient, etcdPeer, apiPort := ports[0], ports[1], ports[2]
	saKey := filepath.Join(dir, "sa.key")
	if err := writeKey(saKey); err != nil {
		return nil, err
	}
	token, err := randomHex()
	if err != nil {
		return nil, err
	}
	tokens := filepath.Join(dir, "tokens.csv")
	// A static admin token in system:masters: enough authority for a test
	// cluster, and no client certificates to generate.
	if err := os.WriteFile(tokens, []byte(token+",truthform-test,truthform-test,system:masters\n"), 0o600); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	etcdURL := "http://127.0.0.1:" + strconv.Itoa(etcdClient)
	etcd, err := launch(ctx, "etcd", etcdBin,
		"--data-dir", filepath.Join(dir, "etcd"),
		"--listen-client-urls", etcdURL,
		"--advertise-client-urls", etcdURL,
		"--listen-peer-urls", "http://127.0.0.1:"+strconv.Itoa(etcdPeer),
		"--unsafe-no-fsync",
	)
	if err != nil {
		cancel()
		return nil, err
	}
	api, err := launch(ctx, "kube-apiserver", apiBin,
		"--etcd-servers", etcdURL,
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
	if err != nil {
		cancel()
		<-etcd.done
		return nil, err
	}
	// Should this binary be killed, a watcher stops the two.
	dismiss, err := watch(api.cmd.Process.Pid, etcd.cmd.Process.Pid)
	if err != nil {
		cancel()
		<-api.done
		<-etcd.done
		return nil, fmt.Errorf("start the watcher of the API server: %w", err)
	}
	stop := func() {
		cancel()
		<-api.done
		<-etcd.done
		dismiss()
	}

	url := "https://127.0.0.1:" + strconv.Itoa(apiPort)
	err = waitFor(deadline, "answered /health", httpOK(etcdURL+"/health", ""), etcd, api)
	if err == nil {
		err = waitFor(deadline, "answered /readyz", httpOK(url+"/readyz", token), api, etcd)
	}
	if err != nil {
		// What each was doing is taken before stop, which ends both.
		state := etcd.state() + "\n" + api.state()
		stop()
		return nil, fmt.Errorf("API server %s never became ready: %w\n%s\n--- etcd output ---\n%s\n--- kube-apiserver output ---\n%s",
			name, err, state, etcd.out.tail(4000), api.out.tail(4000))
	}

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
		stop()
		return nil, err
	}
	return &Server{Kubeconfig: kc, Context: name, stop: stop}, nil
}

// proc is one of the two processes: its output, and how it ended.
type proc struct {
	name    string
	cmd     *exec.Cmd
	out     output
	started time.Time
	done    chan struct{} // closed once it has exited
	err     error         // how it exited, set before done closes
	ended   time.Time
}

func launch(ctx context.Context, name, bin string, args ...string) (*proc, error) {
	p := &proc{name: name, done: make(chan struct{})}
	p.cmd = exec.CommandContext(ctx, bin, args...)
	p.cmd.Stdout, p.cmd.Stderr = &p.out, &p.out
	if err := p.cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", name, err)
	}
	p.started = time.Now()
	go func() {
		err := p.cmd.Wait()
		p.err, p.ended = err, time.Now()
		close(p.done)
	}()
	return p, nil
}

func (p *proc) exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// how says how it exited: os/exec gives no error for a status of 0.
func (p *proc) how() string {
	if p.err == nil {
		return "exit status 0"
	}
	return p.err.Error()
}

// state is a line on what it was doing: running or exited, and whether it
// had written anything, and when it first did.
func (p *proc) state() string {
	n, first := p.out.written()
	wrote := "no output"
	if n > 0 {
		wrote = fmt.Sprintf("%d bytes of output, the first after %.1fs", n, first.Sub(p.started).Seconds())
	}
	if p.exited() {
		return fmt.Sprintf("%s: exited after %.1fs (%s), %s", p.name, p.ended.Sub(p.started).Seconds(), p.how(), wrote)
	}
	return fmt.Sprintf("%s: running for %.1fs, %s", p.name, time.Since(p.started).Seconds(), wrote)
}

// output is one process's standard output and error. Each process has one
// of its own, and it is locked: os/exec copies output from a goroutine per
// process, and two processes once wrote to one buffer at the same time.
type output struct {
	mu    sync.Mutex
	b     bytes.Buffer
	first time.Time
}

func (o *output) Write(b []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.first.IsZero() && len(b) > 0 {
		o.first = time.Now()
	}
	return o.b.Write(b)
}

func (o *output) written() (int, time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.b.Len(), o.first
}

func (o *output) tail(n int) string {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.b.Len() == 0 {
		return "(none)"
	}
	return tail(o.b.String(), n)
}

// waitFor polls check until it passes or the deadline passes. A process
// that exits meanwhile ends the wait at once: what has exited will not
// start.
func waitFor(deadline time.Time, stage string, check func() error, procs ...*proc) error {
	for {
		for _, p := range procs {
			if p.exited() {
				who := procs[0].name
				if p == procs[0] {
					who = "it"
				}
				return fmt.Errorf("%s exited (%s) before %s %s", p.name, p.how(), who, stage)
			}
		}
		err := check()
		if err == nil {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("%s never %s: %w", procs[0].name, stage, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// httpOK checks that a GET of url answers 200.
func httpOK(url, token string) func() error {
	// The serving certificate is self-signed per run; the test only ever talks
	// to the process it just started on loopback.
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec
	return func() error {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s returned %d", url, resp.StatusCode)
		}
		return nil
	}
}

// handedOut are the ports this process has given a server, so two servers
// started side by side are not given one.
var (
	portMu    sync.Mutex
	handedOut = map[int]bool{}
)

// freePorts finds n ports nothing listens on, all different. Each is found
// by listening on port 0, and all the listeners are held open until the
// last is found: asked one at a time, each closed before the next was
// opened, the system gave the same port twice now and then, and etcd
// failed to start with "address already in use" on its own two listeners
// (seen on a CI run).
func freePorts(n int) ([]int, error) {
	portMu.Lock()
	defer portMu.Unlock()
	var held []net.Listener
	defer func() {
		for _, l := range held {
			l.Close()
		}
	}()
	var ports []int
	for tries := 0; len(ports) < n; tries++ {
		if tries > n+100 {
			return nil, fmt.Errorf("no %d free ports found in %d tries", n, tries)
		}
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		held = append(held, l)
		if p := l.Addr().(*net.TCPAddr).Port; !handedOut[p] {
			handedOut[p] = true
			ports = append(ports, p)
		}
	}
	return ports, nil
}

func writeKey(path string) error {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	return os.WriteFile(path, b, 0o600)
}

func randomHex() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}
