package sharedrelease

import "testing"

// The envelope module requires Go >=1.26.0. The release route keeps one exact
// compiler pin and rejects both the superseded compiler and unreviewed neighbors;
// this does not qualify native output or permit publication.
func TestEnvelopeCompilerPinNeighbors(t *testing.T) {
	tools, err := LoadTools("../..")
	if err != nil {
		t.Fatal(err)
	}
	if tools.Go != "go1.26.8" {
		t.Fatalf("envelope-compatible release compiler: %s", tools.Go)
	}
	for _, version := range []string{"go1.25.12", "go1.26.0", "go1.26.9", ""} {
		t.Run(version, func(t *testing.T) {
			other := tools
			other.Go = version
			if err := other.Validate(); err == nil || err.Error() != "linux-tool-policy" {
				t.Fatalf("unreviewed compiler %q accepted: %v", version, err)
			}
		})
	}
	if err := tools.Validate(); err != nil {
		t.Fatal(err)
	}
}
