package saas

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/stackdna/core/internal/readonly"
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

// browser follows the sign-in page's redirect back to StackDNA, as a person
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
	tok, err := a.oauth(freePort(t)).Login(ctx, http.DefaultClient, browser(t))
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
	})
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "access-1" {
		t.Fatalf("token = %+v", tok)
	}
}

func TestTheEnvironmentTokenComesFirst(t *testing.T) {
	t.Setenv("STACKDNA_TEST_TOKEN", "from-env")
	store := &memStore{}
	_ = store.Set("p", `{"access_token":"stored"}`)
	src, how, err := Tokens(Provider{Name: "p", TokenEnv: "STACKDNA_TEST_TOKEN", OAuth: &OAuth{ClientID: "c"}}, store, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := src.Token()
	if tok.AccessToken != "from-env" || how != "STACKDNA_TEST_TOKEN" {
		t.Fatalf("got %q from %q, want the environment's", tok.AccessToken, how)
	}
}

// A sign-in that expires is refreshed, and the refreshed token is stored:
// a provider that rotates refresh tokens refuses the old one next run.
func TestAnExpiredSignInIsRefreshedAndKept(t *testing.T) {
	a := newAuthServer(t)
	p := Provider{Name: "p", TokenEnv: "STACKDNA_TEST_UNSET", OAuth: a.oauth(0)}
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
	_, _, err := Tokens(Provider{Name: "cloudflare", TokenEnv: "STACKDNA_TEST_UNSET", OAuth: &OAuth{ClientID: "c"}}, &memStore{}, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "stackdna login cloudflare") || !strings.Contains(err.Error(), "STACKDNA_TEST_UNSET") {
		t.Fatalf("err = %v, want both ways to authenticate", err)
	}
	// A build with no registered client offers only the token.
	_, _, err = Tokens(Provider{Name: "cloudflare", TokenEnv: "STACKDNA_TEST_UNSET", OAuth: &OAuth{}}, &memStore{}, http.DefaultClient)
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
