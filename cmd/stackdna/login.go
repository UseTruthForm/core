package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/stackdna/core/internal/readonly"
	"github.com/stackdna/core/internal/saas"
)

// keychain holds sign-ins; tests replace it.
var keychain saas.TokenStore = saas.Keychain{}

// loginHTTP sends the sign-in's exchange; nil is the read-only guard. Tests
// set it, since their token endpoint is not Cloudflare's.
var loginHTTP *http.Client

// openBrowser shows the sign-in page; tests replace it.
var openBrowser = func(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	}
	return exec.Command("xdg-open", url).Start()
}

// signInProvider is a provider a person can sign in to.
func signInProvider(args []string, verb string) (saas.Provider, []string, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return saas.Provider{}, nil, fmt.Errorf("usage: stackdna %s cloudflare", verb)
	}
	p, ok := saas.Providers[args[0]]
	if !ok || p.OAuth == nil {
		return saas.Provider{}, nil, fmt.Errorf("%s has no sign-in; it takes a token from its environment variable", args[0])
	}
	return p, args[1:], nil
}

// loginCmd signs a person in and keeps the sign-in in the OS keychain. The
// exchange goes behind the read-only guard, which lets the token endpoint
// through and nothing else, so a capture-only build can sign in too.
func loginCmd(ctx context.Context, args []string) int {
	p, rest, err := signInProvider(args, "login")
	if err != nil {
		return fail(err)
	}
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	noBrowser := fs.Bool("no-browser", false, "print the sign-in address instead of opening a browser")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	// A sign-in left unfinished ends, rather than holding the port.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	hc := loginHTTP
	if hc == nil {
		hc = readonly.Client()
	}
	tok, err := p.OAuth.Login(ctx, hc, func(url string) {
		fmt.Printf("Sign in to %s at:\n\n  %s\n\n", p.Name, url)
		if !*noBrowser {
			if err := openBrowser(url); err == nil {
				fmt.Println("(opened in your browser; waiting for the sign-in to finish)")
				return
			}
		}
		fmt.Println("Open it in a browser on this machine; waiting for the sign-in to finish.")
	})
	if err != nil {
		return fail(err)
	}
	if err := saas.Save(keychain, p.Name, tok); err != nil {
		return fail(fmt.Errorf("signed in, but the keychain refused the sign-in (%v); without a keychain, set %s instead", err, p.TokenEnv))
	}
	fmt.Printf("Signed in to %s; kept in the OS keychain.\n", p.Name)
	if s, _ := tok.Extra("scope").(string); s != "" {
		fmt.Printf("Granted: %s\n", s)
	}
	fmt.Printf("capture, diff and restore use this sign-in unless %s is set. Sign out with: stackdna logout %s\n", p.TokenEnv, p.Name)
	return 0
}

// logoutCmd forgets the sign-in on this machine.
func logoutCmd(args []string) int {
	p, _, err := signInProvider(args, "logout")
	if err != nil {
		return fail(err)
	}
	if err := keychain.Delete(p.Name); err != nil {
		return fail(err)
	}
	fmt.Printf("Signed out of %s on this machine. To end the grant itself, revoke StackDNA in the %s dashboard.\n", p.Name, p.Name)
	return 0
}

// tokenNote says where a run's token came from, so a run with an
// environment token left set is not mistaken for the person's sign-in.
func tokenNote(platform, how string) {
	if how != "" {
		fmt.Fprintf(os.Stderr, "%s: using %s\n", platform, how)
	}
}
