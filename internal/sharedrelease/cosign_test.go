package sharedrelease

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Uses the immutable published v0.1.1 checksum/signature/certificate triple on
// the required hosted control job. This is real keyless checksum verification,
// not a production combined manifest or a new signing/release operation.
// Other test jobs explicitly skip because they have no pinned cosign fixture.
func TestProductionCosignRealIdentityControls(t *testing.T) {
	dir := os.Getenv("A2A_DISTRIBUTION_COSIGN_FIXTURE")
	if dir == "" {
		t.Skip("real keyless fixture is exercised by distribution-controls")
	}
	for n, want := range map[string]string{
		"checksums.txt":     "520fd141b3e56672680347aaefc10623c95ba73685e0d45c822f1a65ff92bd23",
		"checksums.txt.sig": "c58db40dbaa413551a3ad9cc440f2ea1441396a160c13093803669e49347ef5e",
		"checksums.txt.pem": "4f629f14dc96163da74f0b5d708d38e944a264e8df199db3b81f01951c89407e",
	} {
		b, e := os.ReadFile(filepath.Join(dir, n))
		if e != nil || Hash(b) != want {
			t.Fatal("immutable fixture digest", n, e)
		}
	}
	b := Binding{"v0.1.1", "3c3c3d1c8c6fd8386fa4a740dbdb6f99a92bb8d1", "ccb3786d57d59cf1b7980808c80013b4c10fc7c5"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	p := filepath.Join(dir, "checksums.txt")
	args := CosignArgs(p, p+".sig", p+".pem", b, ".github/workflows/darwin-release.yml")
	cmd := exec.CommandContext(ctx, "cosign", args...)
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("authentic positive refused: %v: %s", e, out)
	}
	for name, tc := range map[string]struct{ flag, value, reason string }{
		"workflow": {"--certificate-identity", Identity(Workflow, b.Tag), "none of the expected identities matched"},
		"source":   {"--certificate-github-workflow-sha", strings.Repeat("a", 40), "expected GitHub Workflow SHA not found"},
		"tag":      {"--certificate-github-workflow-ref", "refs/tags/v0.1.2", "expected GitHub Workflow Ref not found"},
		"issuer":   {"--certificate-oidc-issuer", "https://example.com/issuer", "none of the expected identities matched"},
	} {
		t.Run(name, func(t *testing.T) {
			plant := append([]string{}, args...)
			for i, x := range plant {
				if x == tc.flag {
					plant[i+1] = tc.value
				}
			}
			cmd := exec.CommandContext(ctx, "cosign", plant...)
			out, e := cmd.CombinedOutput()
			if e == nil || !strings.Contains(strings.ToLower(string(out)), strings.ToLower(tc.reason)) {
				t.Fatalf("wanted named %s rejection, got %v: %s", tc.reason, e, out)
			}
		})
	}
}
