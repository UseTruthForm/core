package saas

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/usetruthform/core/internal/readonly"
)

// memStore is a keychain in memory.
type memStore struct {
	mu sync.Mutex
	m  map[string]string
}

func (s *memStore) Get(p string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[p]
	if !ok {
		return "", ErrNotSignedIn
	}
	return v, nil
}
func (s *memStore) Set(p, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]string{}
	}
	s.m[p] = v
	return nil
}
func (s *memStore) Delete(p string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, p)
	return nil
}

// authServer is a provider's sign-in: it hands out a code for a PKCE
// challenge and gives a token only for the verifier that made it.
type authServer struct {
	*httptest.Server
	mu        sync.Mutex
	challenge map[string]string // code -> challenge
	refreshes int
	exchanged []url.Values
}

func newAuthServer(t *testing.T) *authServer {
	a := &authServer{challenge: map[string]string{}}
	a.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		switch r.URL.Path {
		case "/oauth2/auth":
			q := r.URL.Query()
			if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
				http.Error(w, "PKCE required", 400)
				return
			}
			code := fmt.Sprintf("code-%d", len(a.challenge))
			a.challenge[code] = q.Get("code_challenge")
			http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
		case "/oauth2/token":
			_ = r.ParseForm()
			a.exchanged = append(a.exchanged, r.PostForm)
			w.Header().Set("Content-Type", "application/json")
			switch r.PostForm.Get("grant_type") {
			case "authorization_code":
				sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
				if a.challenge[r.PostForm.Get("code")] != base64.RawURLEncoding.EncodeToString(sum[:]) {
					http.Error(w, `{"error":"invalid_grant"}`, 400)
					return
				}
				fmt.Fprint(w, `{"access_token":"access-1","refresh_token":"refresh-1","token_type":"bearer","expires_in":3600,"scope":"zone:read dns_records:edit"}`)
			case "refresh_token":
				a.refreshes++
				if r.PostForm.Get("refresh_token") != fmt.Sprintf("refresh-%d", a.refreshes) {
					http.Error(w, `{"error":"invalid_grant"}`, 400)
					return
				}
				fmt.Fprintf(w, `{"access_token":"access-%d","refresh_token":"refresh-%d","token_type":"bearer","expires_in":3600}`, a.refreshes+1, a.refreshes+1)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(a.Close)
	return a
}

func (a *authServer) oauth(port int) *OAuth {
	return &OAuth{ClientID: "client", AuthURL: a.URL + "/oauth2/auth", TokenURL: a.URL + "/oauth2/token",
		Scopes: []string{"zone:read"}, Ports: []int{port}}
}

func freePort(t *testing.T) int {
	s := httptest.NewServer(http.NotFoundHandler())
	u, _ := url.Parse(s.URL)
	s.Close()
	var p int
	fmt.Sscan(u.Port(), &p)
	return p
}

// browser follows the sign-in page's redirect back to Truthform, as a person
// approving the sign-in does.
func browser(t *testing.T) func(string) {
	return func(u string) {
		go func() {
			resp, err := http.Get(u)
			if err != nil {
				t.Errorf("browser: %v", err)
				return
			}
			resp.Body.Close()
		}()
	}
}

func TestASignInIsAPKCECodeExchange(t *testing.T) {
	a := newAuthServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tok, err := a.oauth(freePort(t)).Login(ctx, http.DefaultClient, browser(t), true)
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "access-1" || tok.RefreshToken != "refresh-1" {
		t.Fatalf("token = %+v", tok)
	}
	if got := a.exchanged[0]; got.Get("client_secret") != "" || got.Get("client_id") != "client" {
		t.Fatalf("a public client sends its ID and no secret: %v", got)
	}
}

// A redirect carrying another state is not the sign-in's answer: it is
// refused, and the real one still completes it.
func TestASignInRefusesAnotherState(t *testing.T) {
	a := newAuthServer(t)
	port := freePort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tok, err := a.oauth(port).Login(ctx, http.DefaultClient, func(u string) {
		go func() {
			forged, err := http.Get(fmt.Sprintf("http://localhost:%d/oauth/callback?code=forged&state=other", port))
			if err != nil {
				t.Errorf("forged: %v", err)
				return
			}
			forged.Body.Close()
			if forged.StatusCode != http.StatusBadRequest {
				t.Errorf("a forged redirect got %d, want 400", forged.StatusCode)
			}
			browser(t)(u)
		}()
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "access-1" {
		t.Fatalf("token = %+v", tok)
	}
}

func TestTheEnvironmentTokenComesFirst(t *testing.T) {
	t.Setenv("TRUTHFORM_TEST_TOKEN", "from-env")
	store := &memStore{}
	_ = store.Set("p", `{"access_token":"stored"}`)
	src, how, err := Tokens(Provider{Name: "p", TokenEnv: "TRUTHFORM_TEST_TOKEN", OAuth: &OAuth{ClientID: "c"}}, store, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := src.Token()
	if tok.AccessToken != "from-env" || how != "TRUTHFORM_TEST_TOKEN" {
		t.Fatalf("got %q from %q, want the environment's", tok.AccessToken, how)
	}
}

// A sign-in that expires is refreshed, and the refreshed token is stored:
// a provider that rotates refresh tokens refuses the old one next run.
func TestAnExpiredSignInIsRefreshedAndKept(t *testing.T) {
	a := newAuthServer(t)
	p := Provider{Name: "p", TokenEnv: "TRUTHFORM_TEST_UNSET", OAuth: a.oauth(0)}
	store := &memStore{}
	if err := Save(store, "p", &oauth2.Token{AccessToken: "access-1", RefreshToken: "refresh-1", Expiry: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	src, how, err := Tokens(p, store, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := src.Token()
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "access-2" || how != "sign-in" {
		t.Fatalf("got %q from %q, want the refreshed sign-in", tok.AccessToken, how)
	}
	s, _ := store.Get("p")
	var kept oauth2.Token
	_ = json.Unmarshal([]byte(s), &kept)
	if kept.RefreshToken != "refresh-2" {
		t.Fatalf("stored refresh token = %q, want the rotated refresh-2", kept.RefreshToken)
	}
	// The next run starts from what was kept, and does not refresh again.
	src, _, err = Tokens(p, store, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	if tok, err = src.Token(); err != nil || tok.AccessToken != "access-2" || a.refreshes != 1 {
		t.Fatalf("next run: %v %v after %d refreshes, want the kept access-2 and no new refresh", tok, err, a.refreshes)
	}
}

// The client asks the source for each request's token, so a long run picks
// up a refresh instead of failing at the hour.
func TestEachRequestTakesTheCurrentToken(t *testing.T) {
	var seen []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
		fmt.Fprint(w, `{"result":[],"result_info":{"total_pages":1}}`)
	}))
	defer api.Close()
	n := 0
	c := &Client{P: Provider{Base: api.URL, Envelope: "result"}, HTTP: http.DefaultClient, pace: &pacer{},
		Tokens: tokenFunc(func() (*oauth2.Token, error) { n++; return &oauth2.Token{AccessToken: fmt.Sprintf("t%d", n)}, nil })}
	for range 2 {
		if _, _, err := c.do(context.Background(), "GET", "/zones", nil); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Join(seen, ",") != "Bearer t1,Bearer t2" {
		t.Fatalf("Authorization headers = %v", seen)
	}
}

type tokenFunc func() (*oauth2.Token, error)

func (f tokenFunc) Token() (*oauth2.Token, error) { return f() }

func TestNoSignInSaysHowToSignIn(t *testing.T) {
	_, _, err := Tokens(Provider{Name: "cloudflare", TokenEnv: "TRUTHFORM_TEST_UNSET", OAuth: &OAuth{ClientID: "c"}}, &memStore{}, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "truthform login cloudflare") || !strings.Contains(err.Error(), "TRUTHFORM_TEST_UNSET") {
		t.Fatalf("err = %v, want both ways to authenticate", err)
	}
	// A build with no registered client offers only the token.
	_, _, err = Tokens(Provider{Name: "cloudflare", TokenEnv: "TRUTHFORM_TEST_UNSET", OAuth: &OAuth{}}, &memStore{}, http.DefaultClient)
	if err == nil || strings.Contains(err.Error(), "login") {
		t.Fatalf("err = %v, want the token only", err)
	}
}

// The read-only guard lets a Cloudflare sign-in refresh through and nothing
// else on the dashboard's host.
func TestTheGuardPassesOnlyTheCloudflareTokenEndpoint(t *testing.T) {
	for _, c := range []struct {
		method, url string
		ok          bool
	}{
		{"POST", "https://dash.cloudflare.com/oauth2/token", true},
		{"POST", "https://dash.cloudflare.com/oauth2/revoke", false},
		{"POST", "https://dash.cloudflare.com/api/v4/zones", false},
		{"POST", "https://api.cloudflare.com/client/v4/zones", false},
	} {
		req, _ := http.NewRequest(c.method, c.url, nil)
		if ok, _ := readonly.Allowed(req); ok != c.ok {
			t.Errorf("%s %s allowed = %v, want %v", c.method, c.url, ok, c.ok)
		}
	}
}

// Cloudflare's scope IDs are dotted (zone.read); it refuses colon-delimited
// names, so a sign-in asking for them never reaches the consent screen.
// DNS write is a write scope, asked for only by a build that can write.
func TestCloudflareAsksForItsOwnScopeIDs(t *testing.T) {
	o := Providers["cloudflare"].OAuth
	if got := strings.Join(o.Scopes, " ") + " | " + strings.Join(o.WriteScopes, " "); got != "zone.read dns.read offline_access | dns.write" {
		t.Fatalf("scopes | write scopes = %s", got)
	}
}

// A build signs in as the client in its environment variable when one is
// set: a development build, or an organisation's own registered client.
func TestTheEnvironmentNamesTheClient(t *testing.T) {
	a := newAuthServer(t)
	o := a.oauth(freePort(t))
	o.ClientID, o.IDEnv = "", "TRUTHFORM_TEST_CLIENT_ID"
	t.Setenv("TRUTHFORM_TEST_CLIENT_ID", "from-env")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := o.Login(ctx, http.DefaultClient, browser(t), true); err != nil {
		t.Fatal(err)
	}
	if got := a.exchanged[0].Get("client_id"); got != "from-env" {
		t.Fatalf("client_id = %q, want the environment's", got)
	}
}

// A sign-in keeps the tokens and their expiry and nothing else: Windows
// Credential Manager holds at most 2560 bytes.
func TestASignInKeepsOnlyTheTokens(t *testing.T) {
	store := &memStore{}
	tok := (&oauth2.Token{AccessToken: strings.Repeat("a", 1000), RefreshToken: strings.Repeat("r", 1000), TokenType: "bearer",
		Expiry: time.Now().Add(time.Hour), ExpiresIn: 3600}).WithExtra(map[string]any{"scope": strings.Repeat("s ", 400)})
	if err := Save(store, "p", tok); err != nil {
		t.Fatal(err)
	}
	s, _ := store.Get("p")
	var kept map[string]any
	_ = json.Unmarshal([]byte(s), &kept)
	var keys []string
	for k := range kept {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != "access_token,expiry,refresh_token,token_type" || len(s) > 2560 {
		t.Fatalf("kept %v in %d bytes", keys, len(s))
	}
}

// Without the envelope the provider puts items in, the check could not
// look; that is said, not reported as nothing unreadable.
func TestAMissingEnvelopeIsAGapNotAClearCheck(t *testing.T) {
	sp := &Spec{doc: map[string]any{"paths": map[string]any{
		"/things": map[string]any{
			"get":  map[string]any{"responses": map[string]any{"200": map[string]any{"content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object", "properties": map[string]any{"items": map[string]any{"type": "array"}}}}}}}},
			"post": map[string]any{"requestBody": map[string]any{"content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object", "properties": map[string]any{"ttl": map[string]any{"type": "integer"}}}}}}},
		},
	}}}
	c := &Client{P: Provider{Envelope: "result"}, Spec: sp}
	if u, why := c.unreadableChecked(&Collection{List: "/things", Create: "/things"}); len(u) != 0 || !strings.Contains(why, `no "result" envelope`) {
		t.Fatalf("unreadable %v, why %q", u, why)
	}
}

// The redirect names localhost, which a browser may send to ::1; the
// sign-in answers there too.
func TestASignInAnswersOnTheIPv6Loopback(t *testing.T) {
	if l, err := net.Listen("tcp", "[::1]:0"); err != nil {
		t.Skip("no IPv6 loopback here")
	} else {
		l.Close()
	}
	a := newAuthServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	tok, err := a.oauth(freePort(t)).Login(ctx, http.DefaultClient, func(u string) {
		go func() {
			resp, err := noFollow.Get(u)
			if err != nil {
				t.Errorf("auth: %v", err)
				return
			}
			resp.Body.Close()
			back := strings.Replace(resp.Header.Get("Location"), "//localhost:", "//[::1]:", 1)
			if r, err := http.Get(back); err != nil {
				t.Errorf("callback on ::1: %v", err)
			} else {
				r.Body.Close()
			}
		}()
	}, true)
	if err != nil || tok.AccessToken != "access-1" {
		t.Fatalf("token %v, err %v", tok, err)
	}
}

// The snapshot says so too: a capture over a spec without the envelope
// writes the gap on each object, rather than leaving it looking checked.
func TestACaptureWritesTheUncheckedGap(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"result":[{"name":"a","ttl":1}],"result_info":{"total_pages":1}}`)
	}))
	defer api.Close()
	sp := &Spec{doc: map[string]any{"paths": map[string]any{
		"/things": map[string]any{
			"get":  map[string]any{"responses": map[string]any{"200": map[string]any{"content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object", "properties": map[string]any{"items": map[string]any{"type": "array"}}}}}}}},
			"post": map[string]any{"requestBody": map[string]any{"content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object", "properties": map[string]any{"ttl": map[string]any{"type": "integer"}}}}}}},
		},
	}}}
	p := Provider{Name: "t", Base: api.URL, Envelope: "result", Collections: []Collection{{Kind: "t/thing", List: "/things", Create: "/things", Name: []string{"name"}}}}
	c := &Client{P: p, Spec: sp, HTTP: http.DefaultClient, pace: &pacer{}, Tokens: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "t"})}
	snap, err := (&Adapter{Client: c}).Capture(context.Background())
	if err != nil || len(snap.Objects) != 1 {
		t.Fatalf("capture: %v, %d objects", err, len(snap.Objects))
	}
	ann, _ := snap.Objects[0].Body["metadata"].(map[string]any)["annotations"].(map[string]any)
	if why, _ := ann[annUnchecked].(string); !strings.Contains(why, `no "result" envelope`) {
		t.Fatalf("annotations %v, want the unchecked gap", ann)
	}
}

// answer is what a browser got back from the sign-in's callback.
type answer struct {
	status int
	body   string
	closed bool
	err    error
}

// get fetches a URL as a browser would and sends what came back.
func get(u string, to chan<- answer) {
	resp, err := http.Get(u)
	if err != nil {
		to <- answer{err: err}
		return
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	to <- answer{resp.StatusCode, string(b), resp.Close, err}
}

// The browser gets the page saying the sign-in worked, although Login closes
// its listener the moment it has its answer, and Login is not held up by a
// connection a browser opened and never used.
//
// Two failures are pinned here. The first: the page was only sent once the
// handler returned, and Login's Close could come first and cut it. In CI
// TestASignInRefusesAnotherState failed once with "dial tcp [::1]:41439:
// connect: connection refused", which fits a client retrying a cut request
// and finding nothing listening; that run was not reproduced, but with the
// handler held open the cut happens every time. The second came from the
// first attempt at a fix, a graceful Shutdown: it waited out its whole
// limit on an unused open connection, so a sign-in that worked sat for two
// seconds before returning.
func TestTheBrowserGetsItsAnswerAndLoginDoesNotWait(t *testing.T) {
	a := newAuthServer(t)
	port := freePort(t)
	o := a.oauth(port)
	o.answered = func() { time.Sleep(300 * time.Millisecond) }
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got := make(chan answer, 1)
	var spare net.Conn
	defer func() {
		if spare != nil {
			spare.Close()
		}
	}()
	start := time.Now()
	tok, err := o.Login(ctx, http.DefaultClient, func(u string) {
		// As a browser does: a second connection, opened and not used.
		spare, _ = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		go get(u, got)
	}, true)
	took := time.Since(start)
	if err != nil || tok.AccessToken != "access-1" {
		t.Fatalf("login: %v, token %+v", err, tok)
	}
	if spare == nil {
		t.Fatal("the spare connection was not opened, so the wait was not tested")
	}
	if took > time.Second {
		t.Errorf("Login took %v with an unused connection open; it must not wait for it", took)
	}
	select {
	case p := <-got:
		if p.err != nil || p.status != http.StatusOK || !strings.Contains(p.body, "Signed in to Truthform") {
			t.Errorf("the browser got status %d, body %q, error %v", p.status, p.body, p.err)
		}
		// The listener is gone by now: a browser that kept the connection
		// would send its next request into nothing.
		if !p.closed {
			t.Error("the page did not tell the browser to close the connection")
		}
	case <-time.After(5 * time.Second):
		t.Error("the browser never got an answer")
	}
}

// A sign-in the person refused tells the browser so. Login returns its
// error at once there, with no token exchange first, so the page has even
// less time: before it was sent whole, this path lost it every time the
// handler was still running.
func TestARefusedSignInStillAnswersTheBrowser(t *testing.T) {
	a := newAuthServer(t)
	port := freePort(t)
	o := a.oauth(port)
	o.answered = func() { time.Sleep(300 * time.Millisecond) }
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got := make(chan answer, 1)
	_, err := o.Login(ctx, http.DefaultClient, func(u string) {
		// The provider's redirect when the person says no: the sign-in's
		// own state, and an error in place of a code.
		au, _ := url.Parse(u)
		go get(fmt.Sprintf("http://127.0.0.1:%d/oauth/callback?error=access_denied&error_description=no&state=%s", port, url.QueryEscape(au.Query().Get("state"))), got)
	}, true)
	if err == nil || !strings.Contains(err.Error(), "sign-in refused: access_denied no") {
		t.Fatalf("login error %v, want the refusal", err)
	}
	select {
	case p := <-got:
		if p.err != nil || p.status != http.StatusOK || !strings.Contains(p.body, "Sign-in was not completed") || !p.closed {
			t.Errorf("the browser got status %d, body %q, closed %v, error %v", p.status, p.body, p.closed, p.err)
		}
	case <-time.After(5 * time.Second):
		t.Error("the browser never got an answer")
	}
}

// A client ID still set under the tool's old name is refused, by the sign-in
// and by a run that would use a stored sign-in.
//
// The failure this pins: after the rename STACKDNA_CLOUDFLARE_CLIENT_ID was
// read by nothing. A run with it set signed in as the built-in client and
// said nothing, which reads as the person's own client being in use.
func TestAClientIDUnderTheOldNameIsRefused(t *testing.T) {
	a := newAuthServer(t)
	o := a.oauth(freePort(t))
	o.IDEnv = "TRUTHFORM_TEST_RENAMED_ID"
	t.Setenv("STACKDNA_TEST_RENAMED_ID", "old-client")
	t.Setenv("TRUTHFORM_TEST_RENAMED_ID", "")
	want := "STACKDNA_TEST_RENAMED_ID is set, and this build reads TRUTHFORM_TEST_RENAMED_ID"

	opened := false
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := o.Login(ctx, http.DefaultClient, func(string) { opened = true }, true)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("Login error %v, want it to name both variables", err)
	}
	if opened {
		t.Error("Login opened the sign-in before refusing")
	}

	p := Provider{Name: "test", TokenEnv: "TRUTHFORM_TEST_RENAMED_TOKEN", OAuth: o}
	t.Setenv("TRUTHFORM_TEST_RENAMED_TOKEN", "")

	// With no sign-in stored there is no client to get wrong: the run is
	// told what it lacks, the token, as it was before.
	store := &memStore{}
	if _, _, err := Tokens(p, store, http.DefaultClient); err == nil || !strings.Contains(err.Error(), "TRUTHFORM_TEST_RENAMED_TOKEN is not set") || strings.Contains(err.Error(), "STACKDNA_") {
		t.Errorf("with nothing stored: error %v, want only the missing token", err)
	}

	if err := Save(store, "test", &oauth2.Token{AccessToken: "stored", RefreshToken: "r"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Tokens(p, store, http.DefaultClient); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("Tokens error %v, want it to name both variables", err)
	}

	// An API token needs no client, so the old variable does not matter.
	t.Setenv("TRUTHFORM_TEST_RENAMED_TOKEN", "api-token")
	if _, from, err := Tokens(p, store, http.DefaultClient); err != nil || from != "TRUTHFORM_TEST_RENAMED_TOKEN" {
		t.Errorf("with an API token set: from %q, error %v", from, err)
	}
	t.Setenv("TRUTHFORM_TEST_RENAMED_TOKEN", "")

	// With the new name set too, the new one is used.
	t.Setenv("TRUTHFORM_TEST_RENAMED_ID", "new-client")
	if err := o.renamed(); err != nil {
		t.Errorf("both names set: %v", err)
	}
	if o.id() != "new-client" {
		t.Errorf("client %q, want the one under the new name", o.id())
	}
}
