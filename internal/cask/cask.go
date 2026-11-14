// Package cask derives the a2a Homebrew cask from the signed platform
// manifest (release-assets.json).
//
// The package holds the pure parts of the derivation; the gated entry point
// is cmd/a2a-cask, which verifies the manifest's signature first.
//   - ParseManifest validates a closed schema: exact keys, spelled exactly and
//     each once at both levels, the exact member
//     names for the tag, fixed repository URLs, the required architectures,
//     the digest form, a stable version and its agreement with the tag.
//   - Bind requires every archive the cask references to match both the
//     qualified platform checksum files and the actual asset bytes.
//   - Render is the template, fed only by a parsed manifest. `version` comes
//     first and the stanzas follow Homebrew's canonical order.
//
// Nothing is inferred. Every refusal carries a named reason.
package cask

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
)

// Schema is the only accepted manifest schema identifier.
const Schema = "a2a-release-assets/1"

// ReleaseBase is the fixed release download prefix every asset URL must use.
const ReleaseBase = "https://github.com/relux-works/a2a-swarm/releases/download/"

var (
	stableVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	sha256Hex     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitHex     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	// A checksum entry names a release file by its basename only: no
	// separator, no "." or "..", no leading dot.
	checksumLine = regexp.MustCompile(`^([0-9a-f]{64}) [ *]([A-Za-z0-9][A-Za-z0-9._+-]*)$`)
)

// Asset is one distributed platform file.
type Asset struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

// Manifest is the signed platform aggregate. It lists platform assets only:
// never itself, its own signature files or the derived cask.
type Manifest struct {
	Schema  string  `json:"schema"`
	Tag     string  `json:"tag"`
	Commit  string  `json:"commit"`
	Version string  `json:"version"`
	Assets  []Asset `json:"assets"`
}

// Archives returns the three archive names the cask needs for version.
func Archives(version string) (darwinArm64, linuxAmd64, linuxArm64 string) {
	return "a2a_" + version + "_darwin_arm64.tar.gz", "a2a_" + version + "_linux_amd64.tar.gz", "a2a_" + version + "_linux_arm64.tar.gz"
}

// members is the closed set of platform asset names for version. The three
// archives are required; the others are optional members of the release.
func members(version string) (required []string, allowed map[string]bool) {
	d, la, lr := Archives(version)
	required = []string{d, la, lr}
	allowed = map[string]bool{}
	for _, n := range []string{
		d, "checksums.txt", "checksums.txt.sig", "checksums.txt.pem", "evidence.tar.gz", "release-evidence.json",
		la, lr, la + ".sbom.json", lr + ".sbom.json",
		"a2a_" + version + "_amd64.deb", "a2a_" + version + "_arm64.deb",
		"a2a-" + version + "-1.x86_64.rpm", "a2a-" + version + "-1.aarch64.rpm",
		"linux-checksums.txt", "linux-checksums.txt.sig", "linux-checksums.txt.pem", "linux-release-evidence.json",
	} {
		allowed[n] = true
	}
	return required, allowed
}

var (
	topKeys   = map[string]bool{"schema": true, "tag": true, "commit": true, "version": true, "assets": true}
	assetKeys = map[string]bool{"name": true, "url": true, "sha256": true}
)

func expectDelim(dec *json.Decoder, want json.Delim) error {
	t, err := dec.Token()
	if d, ok := t.(json.Delim); err != nil || !ok || d != want {
		return fmt.Errorf("manifest-malformed: want %q", want)
	}
	return nil
}

func objectKey(dec *json.Decoder) (string, error) {
	t, err := dec.Token()
	k, ok := t.(string)
	if err != nil || !ok {
		return "", errors.New("manifest-malformed: key")
	}
	return k, nil
}

// exactKeys walks the raw JSON and requires exactly the schema's keys, spelled
// exactly, each once, at both levels. encoding/json matches field names case-
// insensitively and lets a duplicate key overwrite, so the typed decode alone
// would accept "SCHEMA" or a second "sha256".
func exactKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := expectDelim(dec, '{'); err != nil {
		return err
	}
	seen := map[string]bool{}
	for dec.More() {
		k, err := objectKey(dec)
		if err != nil {
			return err
		}
		if !topKeys[k] || seen[k] {
			return fmt.Errorf("manifest-malformed: key %q", k)
		}
		seen[k] = true
		if k != "assets" {
			var v json.RawMessage
			if err := dec.Decode(&v); err != nil {
				return errors.New("manifest-malformed: value")
			}
			continue
		}
		if err := expectDelim(dec, '['); err != nil {
			return err
		}
		for dec.More() {
			if err := expectDelim(dec, '{'); err != nil {
				return err
			}
			aseen := map[string]bool{}
			for dec.More() {
				ak, err := objectKey(dec)
				if err != nil {
					return err
				}
				if !assetKeys[ak] || aseen[ak] {
					return fmt.Errorf("manifest-malformed: asset key %q", ak)
				}
				aseen[ak] = true
				var v json.RawMessage
				if err := dec.Decode(&v); err != nil {
					return errors.New("manifest-malformed: value")
				}
			}
			if err := expectDelim(dec, '}'); err != nil {
				return err
			}
			if len(aseen) != len(assetKeys) {
				return errors.New("manifest-malformed: asset keys missing")
			}
		}
		if err := expectDelim(dec, ']'); err != nil {
			return err
		}
	}
	if err := expectDelim(dec, '}'); err != nil {
		return err
	}
	if len(seen) != len(topKeys) {
		return errors.New("manifest-malformed: keys missing")
	}
	return nil
}

// ParseManifest decodes and validates raw manifest bytes. Call it only after
// the bytes have passed the authenticity gate.
func ParseManifest(raw []byte) (Manifest, error) {
	if err := exactKeys(raw); err != nil {
		return Manifest{}, err
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("manifest-malformed: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return Manifest{}, errors.New("manifest-malformed: trailing data")
	}
	switch {
	case m.Schema != Schema:
		return Manifest{}, fmt.Errorf("manifest-schema: %q", m.Schema)
	case !stableVersion.MatchString(m.Version):
		return Manifest{}, fmt.Errorf("version-not-stable: %q", m.Version)
	case m.Tag != "v"+m.Version:
		return Manifest{}, fmt.Errorf("manifest-tag-version-mismatch: %q %q", m.Tag, m.Version)
	case !commitHex.MatchString(m.Commit):
		return Manifest{}, errors.New("manifest-commit-malformed")
	}
	required, allowed := members(m.Version)
	seen := map[string]bool{}
	for _, a := range m.Assets {
		switch {
		case !allowed[a.Name]:
			return Manifest{}, fmt.Errorf("manifest-member-unknown: %q", a.Name)
		case seen[a.Name]:
			return Manifest{}, fmt.Errorf("manifest-member-duplicate: %s", a.Name)
		case a.URL != ReleaseBase+m.Tag+"/"+a.Name:
			return Manifest{}, fmt.Errorf("manifest-url: %s", a.Name)
		case !sha256Hex.MatchString(a.SHA256):
			return Manifest{}, fmt.Errorf("digest-malformed: %s", a.Name)
		}
		seen[a.Name] = true
	}
	for _, n := range required {
		if !seen[n] {
			return Manifest{}, fmt.Errorf("asset-missing: %s", n)
		}
	}
	return m, nil
}

func (m Manifest) digest(name string) string {
	for _, a := range m.Assets {
		if a.Name == name {
			return a.SHA256
		}
	}
	return ""
}

// ParseChecksums reads sha256sum-format lines ("<digest>  <name>") into dst.
// A malformed line, or a name already in dst with a different digest, is refused.
func ParseChecksums(r io.Reader, dst map[string]string) error {
	s := bufio.NewScanner(r)
	for n := 1; s.Scan(); n++ {
		line := s.Text()
		if line == "" {
			continue
		}
		mm := checksumLine.FindStringSubmatch(line)
		if mm == nil {
			return fmt.Errorf("checksum-line-malformed: line %d", n)
		}
		if old, ok := dst[mm[2]]; ok && old != mm[1] {
			return fmt.Errorf("checksum-conflict: %s", mm[2])
		}
		dst[mm[2]] = mm[1]
	}
	return s.Err()
}

// Bind requires each archive the cask references to carry the manifest's
// digest in the qualified checksum files AND in its actual bytes under dir.
func Bind(m Manifest, checksums map[string]string, dir string) error {
	d, la, lr := Archives(m.Version)
	for _, name := range []string{d, la, lr} {
		want := m.digest(name)
		got, ok := checksums[name]
		if !ok {
			return fmt.Errorf("checksum-missing: %s", name)
		}
		if got != want {
			return fmt.Errorf("checksum-binding-mismatch: %s", name)
		}
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			return fmt.Errorf("asset-unreadable: %s", name)
		}
		h := sha256.New()
		_, err = io.Copy(h, f)
		f.Close()
		if err != nil {
			return fmt.Errorf("asset-unreadable: %s", name)
		}
		if hex.EncodeToString(h.Sum(nil)) != want {
			return fmt.Errorf("asset-bytes-mismatch: %s", name)
		}
	}
	return nil
}

type fields struct {
	Version, Darwin, LinuxAmd64, LinuxArm64 string
}

// Render returns the cask for a manifest that ParseManifest accepted.
func Render(m Manifest) ([]byte, error) {
	d, la, lr := Archives(m.Version)
	f := fields{Version: m.Version, Darwin: m.digest(d), LinuxAmd64: m.digest(la), LinuxArm64: m.digest(lr)}
	for _, v := range []string{f.Darwin, f.LinuxAmd64, f.LinuxArm64} {
		if !sha256Hex.MatchString(v) {
			return nil, errors.New("manifest-not-validated")
		}
	}
	var b bytes.Buffer
	if err := caskTemplate.Execute(&b, f); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

var caskTemplate = template.Must(template.New("cask").Parse(strings.TrimLeft(`
# Rendered by a2a-cask from the signed release manifest. Do not edit by hand.
cask "a2a" do
  version "{{.Version}}"

  on_macos do
    sha256 "{{.Darwin}}"

    url "https://github.com/relux-works/a2a-swarm/releases/download/v#{version}/a2a_#{version}_darwin_arm64.tar.gz"

    depends_on arch: :arm64

    binary "a2a-keychain-status"
  end
  on_linux do
    on_arm do
      sha256 "{{.LinuxArm64}}"
      url "https://github.com/relux-works/a2a-swarm/releases/download/v#{version}/a2a_#{version}_linux_arm64.tar.gz"
    end
    on_intel do
      sha256 "{{.LinuxAmd64}}"
      url "https://github.com/relux-works/a2a-swarm/releases/download/v#{version}/a2a_#{version}_linux_amd64.tar.gz"
    end
  end

  name "a2a"
  desc "Agent-to-agent messaging CLI"
  homepage "https://github.com/relux-works/a2a-swarm"

  livecheck do
    skip "Rendered on release."
  end

  binary "a2a"

  zap :not_required
end
`, "\n")))
