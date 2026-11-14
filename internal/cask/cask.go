// Package cask renders the a2a Homebrew cask from release checksums.
//
// It is a renderer, not a publisher. Its only inputs are the version and the
// sha256 digests of the three release archives (the notarised Darwin arm64
// archive and the two Linux archives), taken from the release checksum files.
// The stanzas are written in Homebrew's canonical order, with `version` first so
// that #{version} in every url resolves. Nothing is inferred: a missing archive,
// a malformed digest, a conflicting duplicate or a non-stable version is refused.
package cask

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
)

var (
	stableVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	sha256Hex     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	checksumLine  = regexp.MustCompile(`^([0-9a-f]{64}) [ *]([^/\s][^\s]*)$`)
)

// Archives returns the exact archive names the cask needs for version.
func Archives(version string) (darwinArm64, linuxAmd64, linuxArm64 string) {
	return "a2a_" + version + "_darwin_arm64.tar.gz", "a2a_" + version + "_linux_amd64.tar.gz", "a2a_" + version + "_linux_arm64.tar.gz"
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
		m := checksumLine.FindStringSubmatch(line)
		if m == nil {
			return fmt.Errorf("checksum-line-malformed: line %d", n)
		}
		if old, ok := dst[m[2]]; ok && old != m[1] {
			return fmt.Errorf("checksum-conflict: %s", m[2])
		}
		dst[m[2]] = m[1]
	}
	return s.Err()
}

type fields struct {
	Version, Darwin, LinuxAmd64, LinuxArm64 string
}

// Render returns the cask for version from digests (archive name -> sha256).
func Render(version string, digests map[string]string) ([]byte, error) {
	if !stableVersion.MatchString(version) {
		return nil, fmt.Errorf("version-not-stable: %q", version)
	}
	d, la, lr := Archives(version)
	f := fields{Version: version}
	for _, a := range []struct {
		name string
		dst  *string
	}{{d, &f.Darwin}, {la, &f.LinuxAmd64}, {lr, &f.LinuxArm64}} {
		v, ok := digests[a.name]
		if !ok {
			return nil, fmt.Errorf("asset-missing: %s", a.name)
		}
		if !sha256Hex.MatchString(v) {
			return nil, fmt.Errorf("digest-malformed: %s", a.name)
		}
		*a.dst = v
	}
	var b bytes.Buffer
	if err := caskTemplate.Execute(&b, f); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// VerifyFiles recomputes the sha256 of each archive the cask references from
// dir and refuses any that is absent or differs from digests.
func VerifyFiles(dir, version string, digests map[string]string) error {
	d, la, lr := Archives(version)
	for _, name := range []string{d, la, lr} {
		want, ok := digests[name]
		if !ok {
			return fmt.Errorf("asset-missing: %s", name)
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
		if got := hex.EncodeToString(h.Sum(nil)); got != want {
			return fmt.Errorf("digest-mismatch: %s", name)
		}
	}
	return nil
}

// ErrUsage marks a command-line misuse.
var ErrUsage = errors.New("usage")

var caskTemplate = template.Must(template.New("cask").Parse(strings.TrimLeft(`
# Rendered by a2a-cask from the release checksums. Do not edit by hand.
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
