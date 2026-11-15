package sharedrelease

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/a2a-swarm/internal/cask"
	"github.com/relux-works/a2a-swarm/internal/darwinrelease"
)

func binding() Binding { return Binding{"v0.1.2", strings.Repeat("a", 40), strings.Repeat("b", 40)} }
func encode(t *testing.T, x any) []byte {
	t.Helper()
	b, e := json.Marshal(x)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func put(t *testing.T, dir, n string, b []byte) {
	t.Helper()
	if e := os.WriteFile(filepath.Join(dir, n), b, 0600); e != nil {
		t.Fatal(e)
	}
}
func acceptBlob(context.Context, string, string, string, Binding, string) error { return nil }

// The synthetic fixture proves schema, digest and association gates only. Its
// injected verifier is NOT cryptographic or production signing evidence.
func platformFixture(t *testing.T) (string, []byte) {
	t.Helper()
	dir := t.TempDir()
	b := binding()
	tools, e := LoadTools(filepath.Join("..", ".."))
	if e != nil {
		t.Fatal(e)
	}
	ev := LinuxEvidence{Schema: LinuxSchema, Binding: b, Trust: "production", SourceArchiveSHA256: strings.Repeat("c", 64), SourceDateEpoch: 1700000000, GoVersion: tools.Go, Flags: append([]string{}, BuildFlags...), Tools: tools, Assets: []LinuxAsset{}, Limits: []string{"synthetic gate fixture"}}
	for i, n := range LinuxArtifacts(b.Version()) {
		x := []byte("artifact " + n)
		put(t, dir, n, x)
		sbom := sbomFixture(n, Hash(x))
		put(t, dir, n+".sbom.json", sbom)
		arch := "amd64"
		if i%2 == 1 {
			arch = "arm64"
		}
		pa := arch
		if i >= 4 {
			pa = "x86_64"
			if arch == "arm64" {
				pa = "aarch64"
			}
		}
		ev.Assets = append(ev.Assets, LinuxAsset{n, Hash(x), "linux/" + arch, pa, strings.Repeat("d", 64), Hash(sbom)})
	}
	put(t, dir, "linux-release-evidence.json", encode(t, ev))
	for _, n := range DarwinMembers(b.Version()) {
		put(t, dir, n, []byte("darwin "+n))
	}
	dev := darwinrelease.Evidence{Admission: darwinrelease.Admission{Tag: b.Tag, Commit: b.Commit, TagObject: b.TagObject, Version: b.Version()}, Notary: darwinrelease.NotaryResult{ID: "00000000-0000-0000-0000-000000000001", Status: "Accepted"}, NotaryZIP: strings.Repeat("1", 64)}
	for _, n := range darwinrelease.Binaries {
		dev.Identities = append(dev.Identities, darwinrelease.Identity{Name: n, SHA256: strings.Repeat("e", 64), DR: "fixture full requirement", CompiledDR: strings.Repeat("f", 64)})
	}
	put(t, dir, "release-evidence.json", encode(t, dev))
	// Checksum subjects are the exact platform-specific sets, not all files.
	writePlatformChecksums(t, dir, "checksums.txt", DarwinMembers(b.Version()))
	writePlatformChecksums(t, dir, "linux-checksums.txt", LinuxMembers(b.Version()))
	raw, e := CreateManifest(context.Background(), b, dir, acceptBlob)
	if e != nil {
		t.Fatal(e)
	}
	return dir, raw
}
func writePlatformChecksums(t *testing.T, dir, name string, names []string) {
	t.Helper()
	var sums strings.Builder
	for _, n := range names {
		if n == name || n == name+".sig" || n == name+".pem" {
			continue
		}
		b, e := readRegular(dir, n)
		if e != nil {
			t.Fatal(e)
		}
		sums.WriteString(Hash(b) + "  " + n + "\n")
	}
	put(t, dir, name, []byte(sums.String()))
	put(t, dir, name+".sig", []byte("signature fixture"))
	put(t, dir, name+".pem", []byte("certificate fixture"))
}
func sbomFixture(n, sum string) []byte {
	return []byte(`{"descriptor":{"name":"syft","version":"1.38.0"},"source":{"type":"file","metadata":{"path":"` + n + `","digests":[{"algorithm":"sha256","value":"` + sum + `"}]}},"artifacts":[{"name":"github.com/relux-works/a2a-swarm","type":"go-module"}]}`)
}

// Every production platform member is mandatory; exactly the reviewed three
// architectures and original repository URLs are accepted. Known-bad plants
// each violate one independent requirement while the positive control passes.
func TestProductionManifestClosedContract(t *testing.T) {
	dir, raw := platformFixture(t)
	m, e := ParseManifest(raw, binding())
	if e != nil {
		t.Fatal(e)
	}
	if len(m.Assets) != 22 {
		t.Fatalf("closed member count %d", len(m.Assets))
	}
	if e = BindFiles(m, dir); e != nil {
		t.Fatal(e)
	}
	if _, e = cask.ParseManifest(encode(t, m.Cask())); e != nil {
		t.Fatal("cask projection", e)
	}
	for n, tc := range map[string]struct {
		edit func(*Manifest)
		raw  func([]byte) []byte
		want string
	}{
		"missing package":           {edit: func(m *Manifest) { m.Assets = m.Assets[1:] }, want: "manifest-member-missing"},
		"derived cask":              {edit: func(m *Manifest) { m.Assets = append(m.Assets, cask.Asset{Name: "a2a.rb"}) }, want: "manifest-member-unknown"},
		"self":                      {edit: func(m *Manifest) { m.Assets = append(m.Assets, cask.Asset{Name: "release-assets.json"}) }, want: "manifest-member-unknown"},
		"self signature":            {edit: func(m *Manifest) { m.Assets = append(m.Assets, cask.Asset{Name: "release-assets.json.sig"}) }, want: "manifest-member-unknown"},
		"duplicate":                 {edit: func(m *Manifest) { m.Assets = append(m.Assets, m.Assets[0]) }, want: "manifest-member-duplicate"},
		"wrong architecture":        {edit: func(m *Manifest) { m.Architectures[0] = "darwin/amd64" }, want: "manifest-architecture-set"},
		"missing architecture":      {edit: func(m *Manifest) { m.Architectures = m.Architectures[1:] }, want: "manifest-architecture-set"},
		"commit mismatch":           {edit: func(m *Manifest) { m.Binding.Commit = strings.Repeat("c", 40) }, want: "manifest-source-tag-binding-mismatch"},
		"annotated object mismatch": {edit: func(m *Manifest) { m.Binding.TagObject = strings.Repeat("c", 40) }, want: "manifest-source-tag-binding-mismatch"},
		"tag mismatch":              {edit: func(m *Manifest) { m.Binding.Tag = "v0.1.3" }, want: "manifest-source-tag-binding-mismatch"},
		"version mismatch":          {edit: func(m *Manifest) { m.Version = "0.1.3" }, want: "manifest-tag-version-mismatch"},
		"fixture schema":            {edit: func(m *Manifest) { m.Schema = cask.Schema }, want: "manifest-production-schema-required"},
		"foreign URL":               {edit: func(m *Manifest) { m.Assets[0].URL = "https://example.com/asset" }, want: "manifest-url"},
		"digest form":               {edit: func(m *Manifest) { m.Assets[0].SHA256 = "abcd" }, want: "manifest-digest"},
		"case alias":                {raw: func(b []byte) []byte { return []byte(strings.Replace(string(b), `"sha256"`, `"SHA256"`, 1)) }, want: "json-unknown-key"},
		"duplicate nested key": {raw: func(b []byte) []byte {
			return []byte(strings.Replace(string(b), `"sha256":`, `"sha256":"`+strings.Repeat("0", 64)+`","sha256":`, 1))
		}, want: "json-duplicate-key"},
		"duplicate top key": {raw: func(b []byte) []byte { return append([]byte(`{"version":"0.1.2",`), b[1:]...) }, want: "json-duplicate-key"},
		"missing key":       {raw: func(b []byte) []byte { return []byte(strings.Replace(string(b), `"schema":"`+Schema+`",`, "", 1)) }, want: "json-missing-key"},
		"trailing data":     {raw: func(b []byte) []byte { return append(b, []byte(` {}`)...) }, want: "json-trailing-data"},
	} {
		t.Run(n, func(t *testing.T) {
			var x Manifest
			if e := json.Unmarshal(raw, &x); e != nil {
				t.Fatal(e)
			}
			if tc.edit != nil {
				tc.edit(&x)
			}
			b := encode(t, x)
			if tc.raw != nil {
				b = tc.raw(b)
			}
			_, e := ParseManifest(b, binding())
			if e == nil || !strings.Contains(e.Error(), tc.want) {
				t.Fatalf("want %s, got %v", tc.want, e)
			}
		})
	}
	for _, tag := range []string{"v0.1.2-rc.1", "v01.1.2", "0.1.2", "v0.1.2+meta"} {
		b := binding()
		b.Tag = tag
		if e := b.Validate(); e == nil || e.Error() != "release-version-not-stable" {
			t.Fatal(tag, e)
		}
	}
}

// Authenticity precedes parsing; every row's actual bytes and both signed
// checksum sets are then bound. Rejected input never yields manifest bytes.
func TestProductionPlatformGates(t *testing.T) {
	dir, raw := platformFixture(t)
	calls := 0
	verify := func(_ context.Context, p, sig, cert string, b Binding, w string) error {
		calls++
		if b != binding() {
			t.Fatal("verifier binding")
		}
		if _, e := os.Stat(p); e != nil {
			t.Fatal(e)
		}
		return nil
	}
	if _, e := VerifyProduction(context.Background(), raw, "sig", "cert", dir, binding(), verify); e != nil || calls != 3 {
		t.Fatalf("valid gates %d: %v", calls, e)
	}
	for n, tc := range map[string]struct {
		edit func(*testing.T, string)
		want string
	}{
		"changed Darwin bytes": {func(t *testing.T, d string) { put(t, d, "a2a_0.1.2_darwin_arm64.tar.gz", []byte("altered")) }, "checksum-asset-bytes-mismatch"},
		"missing Linux member": {func(t *testing.T, d string) { os.Remove(filepath.Join(d, LinuxArtifacts("0.1.2")[0])) }, "bundle-member-missing"},
		"extra file":           {func(t *testing.T, d string) { put(t, d, "private.key", []byte("synthetic forbidden member")) }, "bundle-member-unknown"},
		"symlink": {func(t *testing.T, d string) {
			p := filepath.Join(d, "evidence.tar.gz")
			os.Remove(p)
			if e := os.Symlink("release-evidence.json", p); e != nil {
				t.Fatal(e)
			}
		}, "asset-type-or-missing"},
		"duplicate checksum": {func(t *testing.T, d string) {
			b, _ := os.ReadFile(filepath.Join(d, "linux-checksums.txt"))
			put(t, d, "linux-checksums.txt", append(b, b...))
		}, "checksum-member-contract"},
		"missing checksum member": {func(t *testing.T, d string) {
			b, _ := os.ReadFile(filepath.Join(d, "linux-checksums.txt"))
			parts := strings.SplitN(string(b), "\n", 2)
			put(t, d, "linux-checksums.txt", []byte(parts[1]))
		}, "checksum-members-missing"},
		"fixture trust": {func(t *testing.T, d string) {
			b, _ := os.ReadFile(filepath.Join(d, "linux-release-evidence.json"))
			put(t, d, "linux-release-evidence.json", []byte(strings.Replace(string(b), `"trust":"production"`, `"trust":"qualification"`, 1)))
			writePlatformChecksums(t, d, "linux-checksums.txt", LinuxMembers("0.1.2"))
		}, "production-fixture-trust-refused"},
		"Darwin commit mismatch": {func(t *testing.T, d string) {
			b, _ := os.ReadFile(filepath.Join(d, "release-evidence.json"))
			put(t, d, "release-evidence.json", []byte(strings.Replace(string(b), binding().Commit, strings.Repeat("c", 40), 1)))
			writePlatformChecksums(t, d, "checksums.txt", DarwinMembers("0.1.2"))
		}, "darwin-evidence-source-tag-binding"},
	} {
		t.Run(n, func(t *testing.T) {
			d, _ := platformFixture(t)
			tc.edit(t, d)
			b, e := CreateManifest(context.Background(), binding(), d, acceptBlob)
			if e == nil || !strings.Contains(e.Error(), tc.want) || b != nil {
				t.Fatalf("want %s and no manifest, got %v", tc.want, e)
			}
		})
	}
	for _, w := range []string{Workflow, ".github/workflows/darwin-release.yml"} {
		_, e := CreateManifest(context.Background(), binding(), dir, func(_ context.Context, _, _, _ string, _ Binding, workflow string) error {
			if workflow == w {
				return errors.New("wrong-identity-plant")
			}
			return nil
		})
		if e == nil || !strings.Contains(e.Error(), "wrong-identity-plant") {
			t.Fatal("wrong platform identity admitted", w, e)
		}
	}
	_, e := VerifyProduction(context.Background(), []byte(`not JSON`), "s", "c", dir, binding(), func(context.Context, string, string, string, Binding, string) error {
		return errors.New("unsigned-plant")
	})
	if e == nil || e.Error() != "manifest-authenticity: unsigned-plant" {
		t.Fatal("authenticity must precede parse", e)
	}
}

// Claim pins are exact arguments in the real cosign route; a same-repository
// fixture signer, different workflow/ref, or different source SHA is insufficient.
func TestProductionCosignClaims(t *testing.T) {
	b := binding()
	args := CosignArgs("blob", "sig", "cert", b, Workflow)
	want := []string{"verify-blob", "--signature", "sig", "--certificate", "cert", "--certificate-identity", Identity(Workflow, b.Tag), "--certificate-oidc-issuer", Issuer, "--certificate-github-workflow-sha", b.Commit, "--certificate-github-workflow-ref", "refs/tags/" + b.Tag, "--certificate-github-workflow-repository", Repository, "--certificate-github-workflow-trigger", "push", "blob"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("claims differ: %v", args)
	}
	if e := Cosign(context.Background(), "blob", "sig", "cert", b, ".github/workflows/fixture.yml"); e == nil || e.Error() != "signature-workflow-refused" {
		t.Fatal(e)
	}
}
