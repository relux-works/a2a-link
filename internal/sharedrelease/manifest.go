package sharedrelease

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/relux-works/a2a-swarm/internal/cask"
	"github.com/relux-works/a2a-swarm/internal/darwinrelease"
)

// BlobVerifier is the cryptographic boundary. Production callers use Cosign;
// injection is for isolated gate tests, never a CLI flag or trust override.
type BlobVerifier func(context.Context, string, string, string, Binding, string) error

// Capture the complete platform input once. Signature verification, evidence
// parsing and digest enumeration then use the same private immutable copy,
// rather than reopening caller-controlled paths between those operations.
func capturePlatforms(dir string, b Binding, allowManifest bool) (string, error) {
	names := Members(b.Version())
	allowed := append([]string{}, names...)
	if allowManifest {
		for _, n := range []string{"release-assets.json", "release-assets.json.sig", "release-assets.json.pem"} {
			if _, e := os.Lstat(filepath.Join(dir, n)); e == nil {
				allowed = append(allowed, n)
			}
		}
	}
	if e := exactDirectory(dir, allowed); e != nil {
		return "", e
	}
	tmp, e := os.MkdirTemp("", "a2a-platform-input-")
	if e != nil {
		return "", e
	}
	for _, n := range names {
		x, e := readRegular(dir, n)
		if e != nil {
			os.RemoveAll(tmp)
			return "", e
		}
		if e = os.WriteFile(filepath.Join(tmp, n), x, 0600); e != nil {
			os.RemoveAll(tmp)
			return "", e
		}
	}
	return tmp, nil
}

func Identity(workflow, tag string) string {
	return "https://github.com/" + Repository + "/" + workflow + "@refs/tags/" + tag
}

// CosignArgs pins identity, issuer AND the workflow's source/ref/repository/
// event claims. A caller-selected certificate or fixture key cannot broaden it.
func CosignArgs(blob, signature, certificate string, b Binding, workflow string) []string {
	return []string{"verify-blob", "--signature", signature, "--certificate", certificate,
		"--certificate-identity", Identity(workflow, b.Tag), "--certificate-oidc-issuer", Issuer,
		"--certificate-github-workflow-sha", b.Commit, "--certificate-github-workflow-ref", "refs/tags/" + b.Tag,
		"--certificate-github-workflow-repository", Repository, "--certificate-github-workflow-trigger", "push", blob}
}

func Cosign(ctx context.Context, blob, signature, certificate string, b Binding, workflow string) error {
	if e := b.Validate(); e != nil {
		return e
	}
	if workflow != Workflow && workflow != ".github/workflows/darwin-release.yml" {
		return errors.New("signature-workflow-refused")
	}
	c := exec.CommandContext(ctx, "cosign", CosignArgs(blob, signature, certificate, b, workflow)...)
	if e := c.Run(); e != nil {
		return errors.New("signature-authenticity-refused")
	}
	return nil
}

func verifyChecksums(ctx context.Context, dir, name string, names []string, b Binding, workflow string, verify BlobVerifier) error {
	raw, e := readRegular(dir, name)
	if e != nil {
		return e
	}
	if e = verify(ctx, filepath.Join(dir, name), filepath.Join(dir, name+".sig"), filepath.Join(dir, name+".pem"), b, workflow); e != nil {
		return fmt.Errorf("%s: %w", name, e)
	}
	want := map[string]bool{}
	for _, n := range names {
		if n != name && n != name+".sig" && n != name+".pem" {
			want[n] = true
		}
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		sum, n, ok := strings.Cut(line, "  ")
		if !ok || !digestForm.MatchString(sum) || !want[n] || seen[n] {
			return fmt.Errorf("checksum-member-contract: %s", name)
		}
		seen[n] = true
		x, e := readRegular(dir, n)
		if e != nil {
			return e
		}
		if Hash(x) != sum {
			return fmt.Errorf("checksum-asset-bytes-mismatch: %s", n)
		}
	}
	if len(seen) != len(want) {
		return fmt.Errorf("checksum-members-missing: %s", name)
	}
	return nil
}

func evidenceBinding(dir string, b Binding) error {
	raw, e := readRegular(dir, "linux-release-evidence.json")
	if e != nil {
		return e
	}
	if e = VerifyLinuxEvidence(raw, b, dir); e != nil {
		return e
	}
	raw, e = readRegular(dir, "release-evidence.json")
	if e != nil {
		return e
	}
	var ev darwinrelease.Evidence
	if json.Unmarshal(raw, &ev) != nil {
		return errors.New("darwin-evidence-malformed")
	}
	a := ev.Admission
	if a.Tag != b.Tag || a.Commit != b.Commit || a.TagObject != b.TagObject || a.Version != b.Version() {
		return errors.New("darwin-evidence-source-tag-binding")
	}
	if len(ev.Identities) != 2 || ev.Notary.Status != "Accepted" || !digestForm.MatchString(ev.NotaryZIP) {
		return errors.New("darwin-evidence-qualification")
	}
	for i, n := range darwinrelease.Binaries {
		id := ev.Identities[i]
		if id.Name != n || !digestForm.MatchString(id.SHA256) || !digestForm.MatchString(id.CompiledDR) || id.DR == "" {
			return errors.New("darwin-evidence-requirements")
		}
	}
	return nil
}

func verifyPlatforms(ctx context.Context, dir string, b Binding, verify BlobVerifier) error {
	if e := verifyChecksums(ctx, dir, "checksums.txt", DarwinMembers(b.Version()), b, ".github/workflows/darwin-release.yml", verify); e != nil {
		return e
	}
	if e := verifyChecksums(ctx, dir, "linux-checksums.txt", LinuxMembers(b.Version()), b, Workflow, verify); e != nil {
		return e
	}
	return evidenceBinding(dir, b)
}

// CreateManifest accepts only complete, authenticated platform bundles for the
// independently supplied binding. It never infers a new member from a glob.
func CreateManifest(ctx context.Context, b Binding, dir string, verify BlobVerifier) ([]byte, error) {
	if e := b.Validate(); e != nil {
		return nil, e
	}
	if verify == nil {
		verify = Cosign
	}
	captured, e := capturePlatforms(dir, b, false)
	if e != nil {
		return nil, e
	}
	defer os.RemoveAll(captured)
	if e := verifyPlatforms(ctx, captured, b, verify); e != nil {
		return nil, e
	}
	m := Manifest{Schema: Schema, Binding: b, Version: b.Version(), Architectures: []string{"darwin/arm64", "linux/amd64", "linux/arm64"}, Assets: []cask.Asset{}}
	for _, n := range Members(b.Version()) {
		x, e := readRegular(captured, n)
		if e != nil {
			return nil, e
		}
		m.Assets = append(m.Assets, cask.Asset{Name: n, URL: cask.ReleaseBase + b.Tag + "/" + n, SHA256: Hash(x)})
	}
	raw, e := json.MarshalIndent(m, "", "  ")
	if e != nil {
		return nil, e
	}
	raw = append(raw, '\n')
	m, e = ParseManifest(raw, b)
	if e != nil {
		return nil, e
	}
	if e = BindFiles(m, dir); e != nil {
		return nil, e
	}
	return raw, nil
}

// VerifyProduction verifies captured manifest bytes first, then the closed
// schema, all asset bytes, platform checksum identities and evidence bindings.
// The temporary copy is private; callers use the returned parsed manifest only.
func VerifyProduction(ctx context.Context, raw []byte, signature, certificate, dir string, b Binding, verify BlobVerifier) (Manifest, error) {
	var zero Manifest
	if e := b.Validate(); e != nil {
		return zero, e
	}
	if verify == nil {
		verify = Cosign
	}
	tmp, e := os.MkdirTemp("", "a2a-platform-manifest-")
	if e != nil {
		return zero, e
	}
	defer os.RemoveAll(tmp)
	p := filepath.Join(tmp, "release-assets.json")
	if e = os.WriteFile(p, raw, 0600); e != nil {
		return zero, e
	}
	if e = verify(ctx, p, signature, certificate, b, Workflow); e != nil {
		return zero, fmt.Errorf("manifest-authenticity: %w", e)
	}
	m, e := ParseManifest(raw, b)
	if e != nil {
		return zero, e
	}
	captured, e := capturePlatforms(dir, b, true)
	if e != nil {
		return zero, e
	}
	defer os.RemoveAll(captured)
	if e = BindFiles(m, captured); e != nil {
		return zero, e
	}
	if e = verifyPlatforms(ctx, captured, b, verify); e != nil {
		return zero, e
	}
	return m, nil
}

// SealManifest signs only a verified platform aggregate. The three-file
// output is exposed by one directory rename after signing and readback succeed.
// There is no fixture, unsigned-success, release or upload mode.
func SealManifest(ctx context.Context, b Binding, dir, out string) error {
	if _, e := os.Lstat(out); !os.IsNotExist(e) {
		return errors.New("manifest-output-exists")
	}
	raw, e := CreateManifest(ctx, b, dir, nil)
	if e != nil {
		return e
	}
	tmp, e := os.MkdirTemp(filepath.Dir(out), ".a2a-manifest-*")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmp)
	p := filepath.Join(tmp, "release-assets.json")
	if e = os.WriteFile(p, raw, 0600); e != nil {
		return e
	}
	c := exec.CommandContext(ctx, "cosign", "sign-blob", "--yes", "--output-signature", p+".sig", "--output-certificate", p+".pem", p)
	if e = c.Run(); e != nil {
		return errors.New("manifest-keyless-sign-refused")
	}
	if e = Cosign(ctx, p, p+".sig", p+".pem", b, Workflow); e != nil {
		return e
	}
	// Re-read platform bytes after the external signer returns.
	m, e := ParseManifest(raw, b)
	if e != nil {
		return e
	}
	if e = BindFiles(m, dir); e != nil {
		return e
	}
	return os.Rename(tmp, out)
}

// VerifyDarwinProducerInput lets the Linux producer consume and authenticate
// the private six-file Darwin input before building. Native verification is
// repeated later on the approved macOS assembly runner.
func VerifyDarwinProducerInput(ctx context.Context, b Binding, dir string) error {
	if e := b.Validate(); e != nil {
		return e
	}
	if e := exactDirectory(dir, DarwinMembers(b.Version())); e != nil {
		return e
	}
	if e := verifyChecksums(ctx, dir, "checksums.txt", DarwinMembers(b.Version()), b, ".github/workflows/darwin-release.yml", Cosign); e != nil {
		return e
	}
	raw, e := readRegular(dir, "release-evidence.json")
	if e != nil {
		return e
	}
	var ev darwinrelease.Evidence
	if json.Unmarshal(raw, &ev) != nil || ev.Admission.Tag != b.Tag || ev.Admission.Commit != b.Commit || ev.Admission.TagObject != b.TagObject || ev.Admission.Version != b.Version() {
		return errors.New("darwin-producer-source-binding")
	}
	return nil
}
