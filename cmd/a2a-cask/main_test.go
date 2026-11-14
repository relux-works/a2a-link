package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/a2a-swarm/internal/cask"
)

// fixture writes three archives, a manifest carrying their real digests, a
// signature placeholder and one checksum file, and returns the run arguments.
func fixture(t *testing.T) (dir string, args []string) {
	t.Helper()
	dir = t.TempDir()
	m := cask.Manifest{Schema: cask.Schema, Tag: "v0.1.1", Commit: strings.Repeat("3", 40), Version: "0.1.1"}
	var sums strings.Builder
	d, la, lr := cask.Archives("0.1.1")
	for _, name := range []string{d, la, lr} {
		body := []byte("archive " + name)
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(body)
		h := hex.EncodeToString(sum[:])
		m.Assets = append(m.Assets, cask.Asset{Name: name, URL: cask.ReleaseBase + "v0.1.1/" + name, SHA256: h})
		sums.WriteString(h + "  " + name + "\n")
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{"release-assets.json": raw, "release-assets.json.sig": []byte("sig"), "checksums.txt": []byte(sums.String())} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, []string{"-manifest", filepath.Join(dir, "release-assets.json"), "-signature", filepath.Join(dir, "release-assets.json.sig"),
		"-fixture-key", filepath.Join(dir, "fixture.pub"), "-checksums", filepath.Join(dir, "checksums.txt"),
		"-assets-dir", dir, "-out", filepath.Join(dir, "a2a.rb")}
}

func accept(string, string) error { return nil }

func noOutput(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(dir, "a2a.rb")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused run left a cask")
	}
	left, _ := filepath.Glob(filepath.Join(dir, ".a2a-cask-*"))
	if len(left) != 0 {
		t.Fatalf("a refused run left temporary files: %v", left)
	}
}

// Positive control: an authentic, valid and bound manifest renders exactly
// cask.Render's output to -out.
func TestRunWritesCask(t *testing.T) {
	dir, args := fixture(t)
	if err := run(args, io.Discard, accept); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "release-assets.json"))
	m, err := cask.ParseManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := cask.Render(m)
	got, err := os.ReadFile(filepath.Join(dir, "a2a.rb"))
	if err != nil || string(got) != string(want) {
		t.Fatalf("written cask differs: %v", err)
	}
}

// Proves the gate order and the no-output rule. Authenticity runs before the
// manifest is trusted: a refused signature stops the run even for a valid
// manifest. Verification and parsing use the same captured bytes, so a change
// to the caller's file during verification cannot reach the cask. A
// well-formed but wrong digest is refused at the binding gate. No refusal
// leaves a cask or a temporary file.
func TestRunRefusals(t *testing.T) {
	t.Run("signature refused", func(t *testing.T) {
		dir, args := fixture(t)
		err := run(args, io.Discard, func(string, string) error { return errors.New("manifest-authenticity: refused") })
		if err == nil || !strings.HasPrefix(err.Error(), "manifest-authenticity") {
			t.Fatalf("got %v", err)
		}
		noOutput(t, dir)
	})
	t.Run("verify and parse the same captured bytes", func(t *testing.T) {
		dir, args := fixture(t)
		path := filepath.Join(dir, "release-assets.json")
		original, _ := os.ReadFile(path)
		var verified []byte
		err := run(args, io.Discard, func(p, _ string) error {
			if p == path {
				return errors.New("verifier was given the caller's path, not a private copy")
			}
			verified, _ = os.ReadFile(p)
			// A change to the caller's file after capture must not reach parsing.
			return os.WriteFile(path, []byte(`{"schema":"other"}`), 0o600)
		})
		if err != nil {
			t.Fatal(err)
		}
		if string(verified) != string(original) {
			t.Fatal("the verifier did not see the captured bytes")
		}
		m, err := cask.ParseManifest(original)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := cask.Render(m)
		got, _ := os.ReadFile(filepath.Join(dir, "a2a.rb"))
		if string(got) != string(want) {
			t.Fatal("the cask was not rendered from the captured, verified bytes")
		}
	})
	t.Run("wrong well-formed digest in checksums", func(t *testing.T) {
		dir, args := fixture(t)
		_, la, _ := cask.Archives("0.1.1")
		sums, _ := os.ReadFile(filepath.Join(dir, "checksums.txt"))
		lines := strings.Split(strings.TrimSpace(string(sums)), "\n")
		for i, l := range lines {
			if strings.HasSuffix(l, la) {
				lines[i] = strings.Repeat("0", 64) + "  " + la
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "checksums.txt"), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := run(args, io.Discard, accept)
		if err == nil || err.Error() != "checksum-binding-mismatch: "+la {
			t.Fatalf("got %v", err)
		}
		noOutput(t, dir)
	})
	t.Run("manifest key case alias", func(t *testing.T) {
		dir, args := fixture(t)
		path := filepath.Join(dir, "release-assets.json")
		raw, _ := os.ReadFile(path)
		if err := os.WriteFile(path, []byte(strings.Replace(string(raw), `"sha256"`, `"SHA256"`, 1)), 0o600); err != nil {
			t.Fatal(err)
		}
		err := run(args, io.Discard, accept)
		if err == nil || !strings.HasPrefix(err.Error(), "manifest-malformed") {
			t.Fatalf("got %v", err)
		}
		noOutput(t, dir)
	})
	t.Run("checksum name with a path", func(t *testing.T) {
		dir, args := fixture(t)
		f, err := os.OpenFile(filepath.Join(dir, "checksums.txt"), os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.WriteString(strings.Repeat("a", 64) + "  a/../a2a_0.1.1_linux_amd64.tar.gz\n")
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		err = run(args, io.Discard, accept)
		if err == nil || !strings.HasPrefix(err.Error(), "checksum-line-malformed") {
			t.Fatalf("got %v", err)
		}
		noOutput(t, dir)
	})
	t.Run("archive bytes changed", func(t *testing.T) {
		dir, args := fixture(t)
		d, _, _ := cask.Archives("0.1.1")
		if err := os.WriteFile(filepath.Join(dir, d), []byte("other bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := run(args, io.Discard, accept)
		if err == nil || err.Error() != "asset-bytes-mismatch: "+d {
			t.Fatalf("got %v", err)
		}
		noOutput(t, dir)
	})
}

// Proves that exactly one authenticity mode is required: none, both, or an
// incomplete keyless set is a usage refusal before anything is read.
func TestRunRequiresOneTrustMode(t *testing.T) {
	_, args := fixture(t)
	base := args[:4]
	rest := args[6:]
	for name, extra := range map[string][]string{
		"none":            nil,
		"both":            {"-fixture-key", "k", "-certificate", "c", "-certificate-identity", "i", "-certificate-oidc-issuer", "o"},
		"keyless partial": {"-certificate-identity", "i"},
	} {
		t.Run(name, func(t *testing.T) {
			a := append(append(append([]string{}, base...), extra...), rest...)
			if err := run(a, io.Discard, accept); err == nil || !strings.HasPrefix(err.Error(), "usage:") {
				t.Fatalf("got %v", err)
			}
		})
	}
}
