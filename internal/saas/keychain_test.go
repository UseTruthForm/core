package saas

import (
	"testing"

	"github.com/zalando/go-keyring"
)

// A sign-in stored before the tool was renamed sits under the old service
// name. It is not read, and it must not outlive a new sign-in or a logout:
// `logout` saying the sign-in is forgotten while a working refresh token
// stays in the keychain is the failure this pins.
func TestTheSignInStoredUnderTheOldNameIsRemoved(t *testing.T) {
	keyring.MockInit()
	old := func() bool { _, err := keyring.Get(legacyService, "cloudflare"); return err == nil }

	keyring.Set(legacyService, "cloudflare", "old")
	if _, err := (Keychain{}).Get("cloudflare"); err != ErrNotSignedIn {
		t.Errorf("the old sign-in was read: err %v", err)
	}
	if err := (Keychain{}).Delete("cloudflare"); err != nil || old() {
		t.Errorf("logout left the old sign-in: err %v, still there %v", err, old())
	}

	keyring.Set(legacyService, "cloudflare", "old")
	if err := (Keychain{}).Set("cloudflare", "new"); err != nil || old() {
		t.Errorf("login left the old sign-in: err %v, still there %v", err, old())
	}
	if s, _ := (Keychain{}).Get("cloudflare"); s != "new" {
		t.Errorf("stored %q", s)
	}
}
