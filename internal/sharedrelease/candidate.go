package sharedrelease

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"

	"github.com/relux-works/a2a-swarm/internal/cask"
	"github.com/relux-works/a2a-swarm/internal/darwinrelease"
)

// FinalMembers is the closed upload set: 22 platform files, the aggregate's
// signature triple and the derived cask. The cask never signs itself.
func FinalMembers(version string) []string {
	names := append(Members(version), "release-assets.json", "release-assets.json.sig", "release-assets.json.pem", "a2a.rb")
	sort.Strings(names)
	return names
}

// VerifyCandidate authenticates captured platform input and deterministic cask
// derivation. It does not replace the native input, cross-build, artifact or
// main-lease gates required by a future combined production controller.
func VerifyCandidate(ctx context.Context, b Binding, dir string, verify BlobVerifier) error {
	if e := b.Validate(); e != nil {
		return e
	}
	if e := exactDirectory(dir, FinalMembers(b.Version())); e != nil {
		return e
	}
	captured, e := os.MkdirTemp("", "a2a-candidate-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(captured)
	for _, n := range FinalMembers(b.Version()) {
		if n == "a2a.rb" {
			continue
		}
		raw, e := readRegular(dir, n)
		if e != nil {
			return e
		}
		if e = os.WriteFile(filepath.Join(captured, n), raw, 0600); e != nil {
			return e
		}
	}
	raw, e := readRegular(captured, "release-assets.json")
	if e != nil {
		return e
	}
	m, e := VerifyProduction(ctx, raw, filepath.Join(captured, "release-assets.json.sig"), filepath.Join(captured, "release-assets.json.pem"), captured, b, verify)
	if e != nil {
		return e
	}
	canonical, e := cask.Render(m.Cask())
	if e != nil {
		return e
	}
	ruby, e := readRegular(dir, "a2a.rb")
	if e != nil {
		return e
	}
	if !bytes.Equal(ruby, canonical) {
		return errors.New("candidate-cask-derivation-mismatch")
	}
	return nil
}

// ReconcileCandidate is deliberately read-only. A public observation never
// causes an interrupted publication to be retried or a draft to be deleted.
func ReconcileCandidate(ctx context.Context, b Binding, id int64, dir string) (string, error) {
	return darwinrelease.ReconcilePreparedAssets(ctx, id, b.Tag, b.Commit, dir, FinalMembers(b.Version()), func(ctx context.Context, captured string) error { return VerifyCandidate(ctx, b, captured, nil) })
}
