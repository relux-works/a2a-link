package cask

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testCommit = "3c3c3d1c8c6fd8386fa4a740dbdb6f99a92bb8d1"

func digest(c byte) string { return strings.Repeat(string(c), 64) }

func asset(name, sha string) Asset {
	return Asset{Name: name, URL: ReleaseBase + "v0.1.1/" + name, SHA256: sha}
}

func validManifest() Manifest {
	d, la, lr := Archives("0.1.1")
	return Manifest{Schema: Schema, Tag: "v0.1.1", Commit: testCommit, Version: "0.1.1", Assets: []Asset{
		asset(d, digest('a')), asset(la, digest('b')), asset(lr, digest('c')),
		asset("a2a_0.1.1_amd64.deb", digest('d')), asset("linux-checksums.txt", digest('e')),
	}}
}

func raw(t *testing.T, m any) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Proves the exact rendered bytes for a known manifest: `version` first, the
// Darwin stanza carrying only the notarised archive digest, the companion and
// the arm64 requirement, and both Linux arches. The golden is hand-written
// from Homebrew's stanza order, not produced by the renderer.
func TestRenderGolden(t *testing.T) {
	m, err := ParseManifest(raw(t, validManifest()))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Render(m)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "a2a.rb.golden"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("rendered cask differs from the golden:\n%s", got)
	}
}

// Proves that `version` precedes every url using #{version} (the defect of
// GoReleaser's custom_block route) and that Intel macOS is refused by an
// arm64-only requirement inside the macOS block, which alone has the companion.
func TestRenderVersionFirstAndArm64OnlyMacOS(t *testing.T) {
	m, err := ParseManifest(raw(t, validManifest()))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Render(m)
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	v, u := strings.Index(s, `version "0.1.1"`), strings.Index(s, "#{version}")
	if v < 0 || u < 0 || v > u {
		t.Fatalf("version stanza must precede every #{version} url: version at %d, first url at %d", v, u)
	}
	mac := s[strings.Index(s, "on_macos do"):strings.Index(s, "on_linux do")]
	if !strings.Contains(mac, "depends_on arch: :arm64") || !strings.Contains(mac, `binary "a2a-keychain-status"`) {
		t.Fatalf("macOS block must require arm64 and carry the companion:\n%s", mac)
	}
	if strings.Count(s, "a2a-keychain-status") != 1 {
		t.Fatal("the companion must appear only in the macOS block")
	}
}

// Proves that Render refuses a manifest that did not come through ParseManifest.
func TestRenderRefusesUnvalidatedManifest(t *testing.T) {
	if out, err := Render(Manifest{Version: "0.1.1"}); err == nil || err.Error() != "manifest-not-validated" || out != nil {
		t.Fatalf("got %v %q, want manifest-not-validated and no output", err, out)
	}
}

// Negatives for the closed schema, each a single deviation from the valid
// manifest accepted above, each refused with its named reason.
func TestParseManifestRefusals(t *testing.T) {
	d, la, _ := Archives("0.1.1")
	for name, tc := range map[string]struct {
		edit func(*Manifest)
		raw  func([]byte) []byte
		want string
	}{
		"wrong schema":          {edit: func(m *Manifest) { m.Schema = "a2a-release-assets/2" }, want: "manifest-schema"},
		"prerelease":            {edit: func(m *Manifest) { m.Version, m.Tag = "0.1.1-rc.1", "v0.1.1-rc.1" }, want: "version-not-stable"},
		"tag version mismatch":  {edit: func(m *Manifest) { m.Tag = "v0.1.2" }, want: "manifest-tag-version-mismatch"},
		"short commit":          {edit: func(m *Manifest) { m.Commit = "3c3c3d1c" }, want: "manifest-commit-malformed"},
		"missing darwin":        {edit: func(m *Manifest) { m.Assets = m.Assets[1:] }, want: "asset-missing: " + d},
		"unknown member":        {edit: func(m *Manifest) { m.Assets = append(m.Assets, asset("a2a.rb", digest('f'))) }, want: `manifest-member-unknown: "a2a.rb"`},
		"duplicate member":      {edit: func(m *Manifest) { m.Assets = append(m.Assets, m.Assets[1]) }, want: "manifest-member-duplicate: " + la},
		"foreign url":           {edit: func(m *Manifest) { m.Assets[0].URL = "https://example.com/" + d }, want: "manifest-url: " + d},
		"url for another tag":   {edit: func(m *Manifest) { m.Assets[0].URL = ReleaseBase + "v0.1.0/" + d }, want: "manifest-url: " + d},
		"uppercase digest":      {edit: func(m *Manifest) { m.Assets[1].SHA256 = strings.ToUpper(digest('b')) }, want: "digest-malformed: " + la},
		"unknown top-level key": {raw: func(b []byte) []byte { return append([]byte(`{"extra":1,`), b[1:]...) }, want: "manifest-malformed"},
		"unknown asset key":     {raw: func(b []byte) []byte { return []byte(strings.Replace(string(b), `"sha256"`, `"size":1,"sha256"`, 1)) }, want: "manifest-malformed"},
		"trailing data":         {raw: func(b []byte) []byte { return append(b, []byte(" {}")...) }, want: "manifest-malformed: trailing data"},
	} {
		t.Run(name, func(t *testing.T) {
			m := validManifest()
			if tc.edit != nil {
				tc.edit(&m)
			}
			b := raw(t, m)
			if tc.raw != nil {
				b = tc.raw(b)
			}
			if _, err := ParseManifest(b); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want refusal %q", err, tc.want)
			}
		})
	}
}

// Proves checksum parsing: sha256sum lines are read; a malformed line and a
// conflicting duplicate are refused; an identical duplicate is accepted.
func TestParseChecksums(t *testing.T) {
	m := map[string]string{}
	if err := ParseChecksums(strings.NewReader(digest('a')+"  x.tar.gz\n"+digest('b')+" *y.tar.gz\n\n"), m); err != nil {
		t.Fatal(err)
	}
	if m["x.tar.gz"] != digest('a') || m["y.tar.gz"] != digest('b') {
		t.Fatalf("parsed %v", m)
	}
	if err := ParseChecksums(strings.NewReader(digest('a')+"  x.tar.gz\n"), m); err != nil {
		t.Fatalf("identical duplicate refused: %v", err)
	}
	if err := ParseChecksums(strings.NewReader(digest('c')+"  x.tar.gz\n"), m); err == nil || !strings.Contains(err.Error(), "checksum-conflict: x.tar.gz") {
		t.Fatalf("conflicting duplicate: got %v", err)
	}
	for _, bad := range []string{"nothex  x\n", digest('a') + "  ../x\n", digest('a') + "\n"} {
		if err := ParseChecksums(strings.NewReader(bad), map[string]string{}); err == nil {
			t.Fatalf("malformed line accepted: %q", bad)
		}
	}
}

// boundFixture writes the three archives and returns a manifest and checksum
// map that carry their real digests, so a binding passes until one is changed.
func boundFixture(t *testing.T) (Manifest, map[string]string, string) {
	t.Helper()
	dir := t.TempDir()
	m := validManifest()
	sums := map[string]string{}
	d, la, lr := Archives("0.1.1")
	for i, name := range []string{d, la, lr} {
		body := []byte("archive " + name)
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(body)
		m.Assets[i].SHA256 = hex.EncodeToString(sum[:])
		sums[name] = m.Assets[i].SHA256
	}
	return m, sums, dir
}

// Proves the binding gate. Positive: the manifest digests equal the checksum
// files and the bytes. Negatives, each a single WELL-FORMED deviation, each
// refused by name: a checksum file disagreeing with the manifest, an archive
// missing from the checksums, archive bytes that differ, and an absent archive.
func TestBind(t *testing.T) {
	_, la, lr := Archives("0.1.1")
	m, sums, dir := boundFixture(t)
	if err := Bind(m, sums, dir); err != nil {
		t.Fatalf("a matching binding was refused: %v", err)
	}
	t.Run("checksum disagrees", func(t *testing.T) {
		m, sums, dir := boundFixture(t)
		sums[la] = digest('9')
		if err := Bind(m, sums, dir); err == nil || err.Error() != "checksum-binding-mismatch: "+la {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("checksum missing", func(t *testing.T) {
		m, sums, dir := boundFixture(t)
		delete(sums, lr)
		if err := Bind(m, sums, dir); err == nil || err.Error() != "checksum-missing: "+lr {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("manifest and checksums agree but bytes differ", func(t *testing.T) {
		m, sums, dir := boundFixture(t)
		m.Assets[1].SHA256, sums[la] = digest('9'), digest('9')
		if err := Bind(m, sums, dir); err == nil || err.Error() != "asset-bytes-mismatch: "+la {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("archive absent", func(t *testing.T) {
		m, sums, dir := boundFixture(t)
		if err := os.Remove(filepath.Join(dir, lr)); err != nil {
			t.Fatal(err)
		}
		if err := Bind(m, sums, dir); err == nil || err.Error() != "asset-unreadable: "+lr {
			t.Fatalf("got %v", err)
		}
	})
}
