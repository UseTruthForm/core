package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/usetruthform/core/internal/saas"
)

// No test reaches the OS keychain.
func init() { keychain = &memKeychain{m: map[string]string{}} }

type memKeychain struct{ m map[string]string }

func (k *memKeychain) Get(p string) (string, error) {
	if v, ok := k.m[p]; ok {
		return v, nil
	}
	return "", saas.ErrNotSignedIn
}
func (k *memKeychain) Set(p, v string) error { k.m[p] = v; return nil }
func (k *memKeychain) Delete(p string) error { delete(k.m, p); return nil }

// login keeps the sign-in where the next run reads it, and logout forgets
// it, so the next run says how to sign in again.
func TestLoginKeepsTheSignInAndLogoutForgetsIt(t *testing.T) {
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/auth":
			q := r.URL.Query()
			http.Redirect(w, r, q.Get("redirect_uri")+"?code=c&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
		case "/oauth2/token":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"signed-in","refresh_token":"r","token_type":"bearer","expires_in":3600}`)
		}
	}))
	defer auth.Close()
	l := httptest.NewServer(http.NotFoundHandler())
	port := l.Listener.Addr().(*net.TCPAddr).Port
	l.Close()

	p := saas.Providers["cloudflare"]
	saved := p
	p.OAuth = &saas.OAuth{ClientID: "client", AuthURL: auth.URL + "/oauth2/auth", TokenURL: auth.URL + "/oauth2/token", Ports: []int{port},
		Scopes: []string{"zone.read"}, WriteScopes: []string{"dns.write"}}
	saas.Providers["cloudflare"] = p
	defer func() { saas.Providers["cloudflare"] = saved }()
	keychain = &memKeychain{m: map[string]string{}}
	opened := ""
	savedOpen := openBrowser
	defer func() { openBrowser = savedOpen }()
	openBrowser = func(u string) error {
		opened = u
		go func() {
			if resp, err := http.Get(u); err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	// The read-only guard sends the exchange; the fake's token endpoint is
	// not Cloudflare's, so login's own client is swapped for this test.
	loginHTTP = http.DefaultClient
	defer func() { loginHTTP = nil }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if code := loginCmd(ctx, []string{"cloudflare"}); code != 0 {
		t.Fatalf("login exit %d", code)
	}
	if !strings.Contains(opened, "code_challenge_method=S256") {
		t.Fatalf("opened %q, want a PKCE sign-in", opened)
	}
	// The capture-only edition asks for no write: the token it keeps grants
	// none to anything that later reads it from the keychain.
	u, _ := url.Parse(opened)
	if got, want := u.Query().Get("scope"), map[bool]string{true: "zone.read", false: "zone.read dns.write"}[captureOnly]; got != want {
		t.Fatalf("captureOnly=%v asked for scope %q, want %q", captureOnly, got, want)
	}
	src, how, err := saas.Tokens(saas.Providers["cloudflare"], keychain, http.DefaultClient)
	if err != nil || how != "sign-in" {
		t.Fatalf("after login: %v %q", err, how)
	}
	if tok, _ := src.Token(); tok.AccessToken != "signed-in" {
		t.Fatalf("token after login = %q", tok.AccessToken)
	}
	if code := logoutCmd([]string{"cloudflare"}); code != 0 {
		t.Fatalf("logout exit %d", code)
	}
	if _, _, err := saas.Tokens(saas.Providers["cloudflare"], keychain, http.DefaultClient); err == nil || !strings.Contains(err.Error(), "truthform login cloudflare") {
		t.Fatalf("after logout: %v, want how to sign in", err)
	}
}

func TestOnlyAProviderWithASignInHasLogin(t *testing.T) {
	if code := loginCmd(context.Background(), []string{"github"}); code == 0 {
		t.Fatal("github has no sign-in; login must refuse it")
	}
}
