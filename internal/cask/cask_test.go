package cask

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func digest(c byte) string { return strings.Repeat(string(c), 64) }

func validDigests() map[string]string {
	d, la, lr := Archives("0.1.1")
	return map[string]string{d: digest('a'), la: digest('b'), lr: digest('c')}
}

// Proves the exact rendered bytes for a known input: `version` first, the
// Darwin stanza carrying only the notarised archive digest, the companion and
// the arm64 requirement, and both Linux arches. The golden is hand-written
// from Homebrew's stanza order, not produced by the renderer.
func TestRenderGolden(t *testing.T) {
	got, err := Render("0.1.1", validDigests())
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

// Proves that `version` precedes every url using #{version} (the defect that
// made GoReleaser's custom_block route render an empty version) and that
// Intel macOS is refused by an arm64-only requirement inside the macOS block.
func TestRenderVersionFirstAndArm64OnlyMacOS(t *testing.T) {
	got, err := Render("0.1.1", validDigests())
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

// Negatives, each beside the valid render above: a missing archive, a
// malformed digest, and a prerelease or malformed version are each refused by
// name, and nothing is rendered.
func TestRenderRefusals(t *testing.T) {
	d, la, lr := Archives("0.1.1")
	for name, tc := range map[string]struct {
		version string
		edit    func(map[string]string)
		want    string
	}{
		"missing darwin":      {"0.1.1", func(m map[string]string) { delete(m, d) }, "asset-missing: " + d},
		"missing linux amd64": {"0.1.1", func(m map[string]string) { delete(m, la) }, "asset-missing: " + la},
		"missing linux arm64": {"0.1.1", func(m map[string]string) { delete(m, lr) }, "asset-missing: " + lr},
		"uppercase digest":    {"0.1.1", func(m map[string]string) { m[d] = strings.ToUpper(digest('a')) }, "digest-malformed: " + d},
		"short digest":        {"0.1.1", func(m map[string]string) { m[la] = "abc" }, "digest-malformed: " + la},
		"prerelease":          {"0.1.1-rc.1", func(map[string]string) {}, "version-not-stable"},
		"leading v":           {"v0.1.1", func(map[string]string) {}, "version-not-stable"},
	} {
		t.Run(name, func(t *testing.T) {
			m := validDigests()
			tc.edit(m)
			out, err := Render(tc.version, m)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want refusal %q", err, tc.want)
			}
			if out != nil {
				t.Fatal("a refused render produced output")
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

// Proves VerifyFiles: the archives' real digests are accepted, and an archive
// whose bytes differ from its stated digest, or that is absent, is refused by name.
func TestVerifyFiles(t *testing.T) {
	dir := t.TempDir()
	d, la, lr := Archives("0.1.1")
	m := map[string]string{}
	for _, name := range []string{d, la, lr} {
		body := []byte("archive " + name)
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(body)
		m[name] = hex.EncodeToString(sum[:])
	}
	if err := VerifyFiles(dir, "0.1.1", m); err != nil {
		t.Fatalf("matching archives refused: %v", err)
	}
	wrong := map[string]string{d: m[d], la: digest('b'), lr: m[lr]}
	if err := VerifyFiles(dir, "0.1.1", wrong); err == nil || err.Error() != "digest-mismatch: "+la {
		t.Fatalf("wrong digest: got %v", err)
	}
	if err := os.Remove(filepath.Join(dir, lr)); err != nil {
		t.Fatal(err)
	}
	if err := VerifyFiles(dir, "0.1.1", m); err == nil || err.Error() != "asset-unreadable: "+lr {
		t.Fatalf("absent archive: got %v", err)
	}
}
