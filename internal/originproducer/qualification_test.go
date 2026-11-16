package originproducer

import (
	"os"
	"strings"
	"testing"
)

// Claim: the qualification document retains explicit journal/clock and bracket-tip limitations, unlike text with those disclosures removed.
func TestQualificationLimits(t *testing.T) {
	raw, err := os.ReadFile("../../docs/origin-producer-qualification.md")
	if err != nil {
		t.Fatal(err)
	}
	for name, phrases := range map[string][]string{
		"journal": {"owner acceptance required", "no monotonic time floor across checks", "admission-gated at ingest", "writer's", "frozen", "future-tip skew"},
		"tip":     {"best block read before and after the grant check", "backend does not attest the tip it used", "A to B to A residual", "Backend-attested tip"},
	} {
		t.Run(name, func(t *testing.T) {
			complete := func(text string) bool {
				for _, phrase := range phrases {
					if !strings.Contains(text, phrase) {
						return false
					}
				}
				return true
			}
			if !complete(string(raw)) {
				t.Fatal("qualification disclosure is incomplete")
			}
			if complete(strings.ReplaceAll(string(raw), phrases[1], "")) {
				t.Fatal("missing-disclosure negative was not detected")
			}
		})
	}
}
