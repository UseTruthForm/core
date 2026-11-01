package main

import "testing"

// A GCP restore took --values and never read it, so it reported what it
// applied as if the secrets had gone with it.
func TestValuesRefusedWhereNothingReadsThem(t *testing.T) {
	for _, tc := range []struct {
		platform, file string
		ok             bool
	}{
		{"gcp", "v.yaml", false},
		{"kubernetes", "v.yaml", false},
		{"gcp", "", true},
		{"kubernetes", "", true},
		{"aws", "v.yaml", true},
		{"azure", "v.yaml", true},
		{"github", "v.yaml", true},
		{"cloudflare", "v.yaml", true},
	} {
		if err := valuesAccepted(tc.platform, tc.file); (err == nil) != tc.ok {
			t.Errorf("%s %q: %v", tc.platform, tc.file, err)
		}
	}
}
