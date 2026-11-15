package sharedrelease

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/a2a-swarm/internal/cask"
)

// The closed final set binds canonical cask bytes to the authenticated platform manifest; altered or extra upload members refuse.
func TestFinalCandidateDerivation(t *testing.T) {
	for _, kind := range []string{"valid", "changed-cask", "missing", "extra", "signature-refused"} {
		t.Run(kind, func(t *testing.T) {
			dir, raw := platformFixture(t)
			put(t, dir, "release-assets.json", raw)
			put(t, dir, "release-assets.json.sig", []byte("fixture"))
			put(t, dir, "release-assets.json.pem", []byte("fixture"))
			m, e := ParseManifest(raw, binding())
			if e != nil {
				t.Fatal(e)
			}
			ruby, e := cask.Render(m.Cask())
			if e != nil {
				t.Fatal(e)
			}
			if kind == "changed-cask" {
				ruby = append(ruby, []byte("# changed\n")...)
			}
			put(t, dir, "a2a.rb", ruby)
			if kind == "missing" {
				if e = os.Remove(filepath.Join(dir, "a2a.rb")); e != nil {
					t.Fatal(e)
				}
			}
			if kind == "extra" {
				put(t, dir, "extra", []byte("extra"))
			}
			verify := BlobVerifier(acceptBlob)
			if kind == "signature-refused" {
				verify = func(context.Context, string, string, string, Binding, string) error { return os.ErrPermission }
			}
			e = VerifyCandidate(context.Background(), binding(), dir, verify)
			if kind == "valid" {
				if e != nil {
					t.Fatal(e)
				}
				if len(FinalMembers(binding().Version())) != 26 {
					t.Fatal("wrong upload set")
				}
			} else if e == nil {
				t.Fatal("unsafe candidate accepted")
			}
			if kind == "changed-cask" && (e == nil || e.Error() != "candidate-cask-derivation-mismatch") {
				t.Fatal("wrong refusal", e)
			}
		})
	}
}
