// Package access says who StackDNA is running as on a platform, and what
// that identity holds beyond what StackDNA needs. stackdna check puts it
// beside a trial capture, which shows what the identity can read, type by
// type.
//
// Everything here reads, behind the read-only guard. What it could not
// look at is reported as unchecked, never left out: "no warnings" from a
// check that could not see the identity's roles would read as "nothing to
// worry about" when nothing was looked at.
package access

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// Report is what was learned about one identity.
type Report struct {
	Platform string
	Who      string   // as the platform names the caller
	Kind     string   // root user, IAM user, role, service principal...
	Facts    []string // what was found: roles held, credential kind, expiry
	Warnings []string // what an administrator would want changed
	// Unchecked is what could not be looked at, and why. It is shown as
	// such: never as clear.
	Unchecked []string
}

func (r *Report) fact(s string)      { r.Facts = append(r.Facts, s) }
func (r *Report) warn(s string)      { r.Warnings = append(r.Warnings, s) }
func (r *Report) unchecked(s string) { r.Unchecked = append(r.Unchecked, s) }

// jwtClaims reads a token's claims without verifying it: it is the
// caller's own token, read to say who the caller is, never trusted for
// anything.
func jwtClaims(tok string) map[string]any {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return m
}

func claim(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}
