package main

import "testing"

// Claim: the dependency checker recognizes the selected pseudo-version and rejects the former 3baa201b selection and ambiguous non-commit versions.
func TestLegacySelectionRefused(t *testing.T) {
	for _, tc := range []struct {
		version string
		valid   bool
	}{
		{"v0.1.2-0.20261115014216-d01e38f1c966", true},
		{"v0.1.2-0.20261114150118-3baa201bafb6", false},
		{"v0.1.2", false}, {"v0.1.2-0.20261115014216-not-a-commit", false},
	} {
		_, err := revision(tc.version)
		if (err == nil) != tc.valid {
			t.Fatalf("%s: %v", tc.version, err)
		}
	}
}
