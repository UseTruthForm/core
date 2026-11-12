package saas

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"
)

// OAuth is a provider's sign-in for a person: the authorization code flow
// with PKCE, redirected to a port on this machine. The client is public (no
// secret ships in the binary); the provider holds its registration.
type OAuth struct {
	ClientID string
	// IDEnv, when set in the environment, replaces ClientID: a development
	// build, or an organisation's own registered client.
	IDEnv             string
	AuthURL, TokenURL string
	Scopes            []string
	// WriteScopes are asked for only by a build that can write: the
	// capture-only edition's sign-in grants no write to anything that
	// later reads the stored token.
	WriteScopes []string
	// Ports are the redirect ports registered with the provider, tried in
	// order; the redirect is http://localhost:<port>/oauth/callback.
	Ports []int
	// answered, when set, runs in the callback's handler once the sign-in
	// has its answer, before the handler returns. Only a test sets it, to
	// keep the handler running past the moment Login closes the listener.
	// It is a field, not a package variable: a variable was read by one
	// test's handler while the next test wrote it, which the race
	// detector reported.
	answered func()
}

// TokenStore keeps a signed-in person's token. The OS keychain in use, a
// map in tests.
type TokenStore interface {
	Get(provider string) (string, error)
	Set(provider, secret string) error
	Delete(provider string) error
}

// Keychain is the OS keychain: Secret Service on Linux, Keychain on macOS,
// Credential Manager on Windows. No file is written in its place: where no
// keychain runs, login says so and the token comes from the environment.
type Keychain struct{}

const keychainService = "truthform"

// legacyService is where a sign-in made before the tool was renamed is kept.
// It is never read, so that sign-in is made again. It is removed whenever a
// sign-in is stored or forgotten: left behind, `logout` would report the
// sign-in gone while a working refresh token stayed in the keychain.
const legacyService = "stackdna"

func (Keychain) Get(p string) (string, error) {
	s, err := keyring.Get(keychainService, p)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", ErrNotSignedIn
	}
	return s, err
}
func (Keychain) Set(p, s string) error {
	if err := keyring.Set(keychainService, p, s); err != nil {
		return err
	}
	// The new sign-in is stored by now, so say so: a bare error here
	// would read as a sign-in that failed.
	if err := forget(legacyService, p); err != nil {
		return fmt.Errorf("the sign-in is stored, but the one an earlier build stored could not be removed from the keychain: %w", err)
	}
	return nil
}
func (Keychain) Delete(p string) error {
	return errors.Join(forget(keychainService, p), forget(legacyService, p))
}

func forget(service, p string) error {
	if err := keyring.Delete(service, p); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return err
	}
	return nil
}

// page sends the whole of the browser's page before it returns. Login closes
// its listener as soon as the handler hands it the answer, and a response
// is otherwise only sent once the handler has returned: the close cut it,
// so a sign-in that worked could show the browser a connection error. With
// its length set and flushed, nothing of the page is left to send after.
func page(w http.ResponseWriter, text string) {
	text += "\n"
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(text)))
	// The listener is about to go; a browser must not keep this
	// connection for another request.
	w.Header().Set("Connection", "close")
	_, _ = io.WriteString(w, text)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// ErrNotSignedIn means no token is stored for the provider.
var ErrNotSignedIn = errors.New("not signed in")

// id is the client this run signs in as.
func (o *OAuth) id() string {
	if o.IDEnv != "" {
		if v := os.Getenv(o.IDEnv); v != "" {
			return v
		}
	}
	return o.ClientID
}

// renamed refuses a run whose environment still names the client under the
// tool's old name. Builds up to beta.20 read STACKDNA_...; this one reads
// TRUTHFORM_... and would otherwise ignore the old variable without a word,
// signing in as the built-in client while the person believes their own is
// in use. With the new name set as well, the new one is used and there is
// nothing to refuse.
func (o *OAuth) renamed() error {
	rest, ok := strings.CutPrefix(o.IDEnv, "TRUTHFORM_")
	if !ok {
		return nil
	}
	old := "STACKDNA_" + rest
	if os.Getenv(old) != "" && os.Getenv(o.IDEnv) == "" {
		return fmt.Errorf("%s is set, and this build reads %s: rename the variable, or unset it", old, o.IDEnv)
	}
	return nil
}

func (o *OAuth) config(redirect string) *oauth2.Config {
	return &oauth2.Config{ClientID: o.id(), Scopes: o.Scopes, RedirectURL: redirect,
		Endpoint: oauth2.Endpoint{AuthURL: o.AuthURL, TokenURL: o.TokenURL, AuthStyle: oauth2.AuthStyleInParams}}
}

// Login signs a person in. It listens on the first free registered port,
// hands open the address to visit (a browser, or a person told to), and
// exchanges the code the provider redirects back with. hc sends the
// exchange, so a read-only build sends it behind its guard.
func (o *OAuth) Login(ctx context.Context, hc *http.Client, open func(url string), write bool) (*oauth2.Token, error) {
	if err := o.renamed(); err != nil {
		return nil, err
	}
	if o.id() == "" {
		return nil, fmt.Errorf("this build has no sign-in registered for the provider; set the API token environment variable instead, or %s to a registered client", o.IDEnv)
	}
	var ln net.Listener
	var port int
	var err error
	for _, port = range o.Ports {
		if ln, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			break
		}
	}
	if ln == nil {
		return nil, fmt.Errorf("no registered sign-in port is free (%v): %w", o.Ports, err)
	}
	defer ln.Close()
	conf := o.config(fmt.Sprintf("http://localhost:%d/oauth/callback", port))
	if write {
		conf.Scopes = append(append([]string{}, conf.Scopes...), o.WriteScopes...)
	}
	state, verifier := random(), oauth2.GenerateVerifier()

	type result struct {
		code string
		err  error
	}
	done := make(chan result, 1)
	var once sync.Once
	finish := func(r result) { once.Do(func() { done <- r }) }
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/callback" {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		switch {
		// A redirect without this sign-in's state is not its answer: it is
		// refused, and the sign-in goes on waiting for the real one.
		case q.Get("state") != state:
			http.Error(w, "This is not the sign-in TruthForm started.", http.StatusBadRequest)
			return
		case q.Get("error") != "":
			page(w, "Sign-in was not completed. You can close this tab.")
			finish(result{err: fmt.Errorf("sign-in refused: %s %s", q.Get("error"), q.Get("error_description"))})
		default:
			page(w, "Signed in to TruthForm. You can close this tab and return to the terminal.")
			finish(result{code: q.Get("code")})
		}
		if o.answered != nil {
			o.answered()
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	// The redirect names localhost, which a browser may resolve to ::1
	// first; the IPv6 loopback answers too where it is free.
	if ln6, err := net.Listen("tcp", fmt.Sprintf("[::1]:%d", port)); err == nil {
		defer ln6.Close()
		go func() { _ = srv.Serve(ln6) }()
	}
	// Close, not Shutdown: by the time Login has its answer the page is
	// already sent (see page). Shutdown would also wait, up to its limit,
	// on a connection a browser opened and never used, and browsers open
	// those; a sign-in that worked then sat for seconds before returning.
	defer srv.Close()

	open(conf.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)))
	var r result
	select {
	case r = <-done:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if r.err != nil {
		return nil, r.err
	}
	return conf.Exchange(context.WithValue(ctx, oauth2.HTTPClient, hc), r.code, oauth2.VerifierOption(verifier))
}

func random() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// stored is what a sign-in keeps: the tokens and when the access token
// expires, nothing else. Windows Credential Manager holds at most 2560
// bytes, so the token's extras (scope, expires_in) are not kept.
type stored struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
}

// Save stores a token for the provider.
func Save(store TokenStore, provider string, t *oauth2.Token) error {
	b, err := json.Marshal(stored{t.AccessToken, t.TokenType, t.RefreshToken, t.Expiry})
	if err != nil {
		return err
	}
	return store.Set(provider, string(b))
}

// Tokens is where a provider's requests get their token, in order: the
// environment variable (a scoped API token, for CI), then the person's
// stored sign-in, refreshed when it expires and stored again. hc sends the
// refresh. The second value says which one it is, for the run to say.
func Tokens(p Provider, store TokenStore, hc *http.Client) (oauth2.TokenSource, string, error) {
	if t := os.Getenv(p.TokenEnv); t != "" {
		return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: t}), p.TokenEnv, nil
	}
	how := fmt.Sprintf("%s is not set; set it to an API token", p.TokenEnv)
	if p.OAuth != nil && p.OAuth.id() != "" {
		how += fmt.Sprintf(", or sign in with: truthform login %s", p.Name)
	}
	if p.OAuth == nil || store == nil {
		return nil, "", errors.New(how)
	}
	s, err := store.Get(p.Name)
	if errors.Is(err, ErrNotSignedIn) {
		return nil, "", errors.New(how)
	}
	if err != nil {
		return nil, "", fmt.Errorf("reading the %s sign-in from the keychain: %w (%s)", p.Name, err, how)
	}
	// Only once there is a sign-in to use: its refresh goes out under the
	// client ID. A run with no sign-in at all is told about the token
	// above, which is what it lacks. Not left to the refresh either: the
	// provider refuses the wrong client with an error that does not name
	// the variable.
	if err := p.OAuth.renamed(); err != nil {
		return nil, "", err
	}
	var t oauth2.Token
	if err := json.Unmarshal([]byte(s), &t); err != nil {
		return nil, "", fmt.Errorf("the stored %s sign-in is unreadable; sign in again with: truthform login %s", p.Name, p.Name)
	}
	src := p.OAuth.config("").TokenSource(context.WithValue(context.Background(), oauth2.HTTPClient, hc), &t)
	return &saving{src: src, store: store, name: p.Name, last: t.AccessToken}, "sign-in", nil
}

// saving stores a refreshed token, so the next run starts from it: a
// provider that rotates refresh tokens refuses the old one.
type saving struct {
	mu    sync.Mutex
	src   oauth2.TokenSource
	store TokenStore
	name  string
	last  string
}

func (s *saving) Token() (*oauth2.Token, error) {
	t, err := s.src.Token()
	if err != nil {
		return nil, fmt.Errorf("refreshing the %s sign-in: %w; sign in again with: truthform login %s", s.name, err, s.name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if t.AccessToken != s.last {
		s.last = t.AccessToken
		if err := Save(s.store, s.name, t); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: the refreshed %s sign-in could not be stored (%v); if the next run is refused, sign in again with: truthform login %s\n", s.name, err, s.name)
		}
	}
	return t, nil
}
