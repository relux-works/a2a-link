package sharedrelease

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"debug/buildinfo"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const LinuxSchema = "a2a-linux-release/1"

var BuildFlags = []string{"-mod=readonly", "-trimpath", "-buildvcs=false", "-buildmode=exe", "-compiler=gc", "-pgo=off", "-p=1", "-ldflags=-linkmode=internal -libgcc=none"}

type Tool struct {
	Version          string `json:"version"`
	Commit           string `json:"commit"`
	URL              string `json:"url"`
	SHA256           string `json:"sha256"`
	ExecutableSHA256 string `json:"executable_sha256"`
	ChecksumsSHA256  string `json:"checksums_sha256"`
}
type Tools struct {
	Schema     string `json:"schema"`
	Go         string `json:"go"`
	Cosign     string `json:"cosign"`
	GoReleaser Tool   `json:"goreleaser"`
	Syft       Tool   `json:"syft"`
}

func LoadTools(root string) (Tools, error) {
	var t Tools
	b, e := os.ReadFile(filepath.Join(root, "release/linux-tools.json"))
	if e != nil {
		return t, e
	}
	if e = DecodeExact(b, &t); e != nil {
		return t, e
	}
	if e := t.Validate(); e != nil {
		return t, e
	}
	return t, nil
}

func (t Tools) Validate() error {
	if t.Schema != "a2a-linux-tools/1" || t.Go != "go1.25.12" || t.Cosign != "v2.6.1" || t.GoReleaser.Version != "v2.20.2" || t.Syft.Version != "v1.38.0" ||
		t.GoReleaser.Commit != "1bf59683fabedd7b446d089ec31b1e343b472ce6" || t.Syft.Commit != "a033ae525f6c7ef937c6f49513e3403f07a1d6c0" {
		return errors.New("linux-tool-policy")
	}
	for _, x := range []Tool{t.GoReleaser, t.Syft} {
		if !object.MatchString(x.Commit) || !digestForm.MatchString(x.SHA256) || !digestForm.MatchString(x.ExecutableSHA256) || !digestForm.MatchString(x.ChecksumsSHA256) {
			return errors.New("linux-tool-policy")
		}
	}
	return nil
}

// VerifyTools authenticates executable bytes before invoking either tool. The
// archive and checksum-list pins are checked before extraction by hosted CI.
func VerifyTools(t Tools) error {
	if runtime.Version() != t.Go {
		return errors.New("linux-go-toolchain-mismatch")
	}
	for n, x := range map[string]Tool{"goreleaser": t.GoReleaser, "syft": t.Syft} {
		p, e := exec.LookPath(n)
		if e != nil {
			return fmt.Errorf("linux-tool-missing: %s", n)
		}
		got, e := fileHash(p)
		if e != nil || got != x.ExecutableSHA256 {
			return fmt.Errorf("linux-tool-executable-mismatch: %s", n)
		}
	}
	return nil
}

type LinuxAsset struct {
	Name                string `json:"name"`
	SHA256              string `json:"sha256"`
	Architecture        string `json:"architecture"`
	PackageArchitecture string `json:"package_architecture"`
	BinarySHA256        string `json:"binary_sha256"`
	SBOMSHA256          string `json:"sbom_sha256"`
}
type LinuxEvidence struct {
	Schema              string       `json:"schema"`
	Binding             Binding      `json:"binding"`
	Trust               string       `json:"trust"`
	SourceArchiveSHA256 string       `json:"source_archive_sha256"`
	SourceDateEpoch     int64        `json:"source_date_epoch"`
	GoVersion           string       `json:"go_version"`
	Flags               []string     `json:"flags"`
	Tools               Tools        `json:"tools"`
	Assets              []LinuxAsset `json:"assets"`
	Limits              []string     `json:"limits"`
}

// ArchiveBinary verifies metadata and contents of the entire declared archive,
// not just its executable. No host stat metadata enters the accepted contract.
func ArchiveBinary(raw []byte, epoch int64, docs map[string][]byte) ([]byte, error) {
	g, e := gzip.NewReader(bytes.NewReader(raw))
	if e != nil {
		return nil, errors.New("linux-archive-gzip")
	}
	defer g.Close()
	if !g.ModTime.IsZero() || g.Name != "" || g.Comment != "" {
		return nil, errors.New("linux-archive-gzip-metadata")
	}
	plain, e := io.ReadAll(io.LimitReader(g, 256<<20+1))
	if e != nil || len(plain) > 256<<20 {
		return nil, errors.New("linux-archive-gzip")
	}
	stream := bytes.NewReader(plain)
	r := tar.NewReader(stream)
	seen := map[string]bool{}
	var bin []byte
	for {
		h, e := r.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, errors.New("linux-archive-tar")
		}
		mode := int64(0644)
		if h.Name == "a2a" {
			mode = 0755
		} else if _, ok := docs[h.Name]; !ok {
			return nil, fmt.Errorf("linux-archive-member: %s", h.Name)
		}
		if seen[h.Name] || h.Typeflag != tar.TypeReg || h.Mode != mode || h.Uid != 0 || h.Gid != 0 || h.Uname != "root" || h.Gname != "root" || !h.ModTime.Equal(time.Unix(epoch, 0)) || !h.AccessTime.IsZero() || !h.ChangeTime.IsZero() || h.Linkname != "" || len(h.PAXRecords) != 0 {
			return nil, fmt.Errorf("linux-archive-metadata: %s", h.Name)
		}
		if h.Size <= 0 || h.Size > 128<<20 {
			return nil, errors.New("linux-archive-size")
		}
		b, e := io.ReadAll(r)
		if e != nil {
			return nil, e
		}
		seen[h.Name] = true
		if h.Name == "a2a" {
			bin = b
		} else if !bytes.Equal(b, docs[h.Name]) {
			return nil, fmt.Errorf("linux-archive-document-bytes: %s", h.Name)
		}
	}
	if len(seen) != len(docs)+1 || bin == nil {
		return nil, errors.New("linux-archive-members")
	}
	// Only zero padding may follow the first tar terminator. A hidden second
	// archive is not part of the closed member set.
	if len(bytes.Trim(plain[len(plain)-stream.Len():], "\x00")) != 0 {
		return nil, errors.New("linux-archive-trailing-data")
	}
	return bin, nil
}

func VerifyELF(raw []byte, arch string) error {
	f, e := elf.NewFile(bytes.NewReader(raw))
	if e != nil {
		return errors.New("linux-binary-not-elf")
	}
	defer f.Close()
	want := elf.EM_X86_64
	if arch == "arm64" {
		want = elf.EM_AARCH64
	} else if arch != "amd64" {
		return errors.New("linux-binary-architecture")
	}
	if f.Machine != want || f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Type != elf.ET_EXEC {
		return errors.New("linux-binary-architecture")
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP || p.Type == elf.PT_DYNAMIC {
			return errors.New("linux-binary-not-static")
		}
	}
	info, e := buildinfo.Read(bytes.NewReader(raw))
	if e != nil || info.GoVersion != "go1.25.12" || info.Path != "github.com/relux-works/a2a-swarm/cmd/a2a" {
		return errors.New("linux-binary-go-identity")
	}
	settings := map[string]string{}
	for _, s := range info.Settings {
		settings[s.Key] = s.Value
	}
	for k, v := range map[string]string{"GOOS": "linux", "GOARCH": arch, "CGO_ENABLED": "0", "-trimpath": "true", "-buildmode": "exe", "-compiler": "gc"} {
		if settings[k] != v {
			return errors.New("linux-binary-build-settings")
		}
	}
	// buildvcs=false must not claim an embedded source revision. The workflow's
	// source archive hash and signed evidence provide that association instead.
	for k := range settings {
		if strings.HasPrefix(k, "vcs") {
			return errors.New("linux-binary-vcs-settings")
		}
	}
	return nil
}

func verifySBOM(raw []byte, name, sha, version, arch string) error {
	var s struct {
		Descriptor struct{ Name, Version string } `json:"descriptor"`
		Source     struct {
			Type     string
			Metadata struct {
				Path    string
				Digests []struct{ Algorithm, Value string }
			}
		} `json:"source"`
		Artifacts []struct {
			Name, Type, Version string
			Metadata            struct{ Architecture, Version, Release string }
		} `json:"artifacts"`
	}
	if json.Unmarshal(raw, &s) != nil || s.Descriptor.Name != "syft" || s.Descriptor.Version != "1.38.0" || s.Source.Type != "file" || filepath.Base(s.Source.Metadata.Path) != name {
		return errors.New("linux-sbom-identity")
	}
	matched := 0
	for _, d := range s.Source.Metadata.Digests {
		if d.Algorithm == "sha256" {
			if d.Value != sha {
				return errors.New("linux-sbom-subject-mismatch")
			}
			matched++
		}
	}
	if matched != 1 {
		return errors.New("linux-sbom-subject-mismatch")
	}
	if strings.HasSuffix(name, ".tar.gz") {
		for _, a := range s.Artifacts {
			if a.Type == "go-module" && a.Name == "github.com/relux-works/a2a-swarm" {
				return nil
			}
		}
		return errors.New("linux-sbom-cli-module-missing")
	}
	// Syft's deb/rpm archive catalogers describe the package, not the Go
	// modules nested inside its payload. The archive SBOM supplies that module
	// inventory; independently verified payload byte equality links the two.
	kind, packageArch, packageVersion := "deb", arch, version
	if strings.HasSuffix(name, ".rpm") {
		kind, packageVersion = "rpm", version+"-1"
		packageArch = "x86_64"
		if arch == "arm64" {
			packageArch = "aarch64"
		}
	}
	matchedPackage := 0
	for _, a := range s.Artifacts {
		if a.Name != "a2a" || a.Type != kind {
			continue
		}
		if a.Version != packageVersion || a.Metadata.Architecture != packageArch || a.Metadata.Version != version || kind == "rpm" && a.Metadata.Release != "1" {
			return errors.New("linux-sbom-package-binding")
		}
		matchedPackage++
	}
	if matchedPackage != 1 {
		return errors.New("linux-sbom-package-binding")
	}
	return nil
}

// PrepareLinux copies only the reviewed public members into a fresh private
// output directory. Failure removes staging and leaves the output absent.
// Callers must authenticate source and tools before running the builder.
func PrepareLinux(root, dist, out, sourceArchive string, binding Binding, epoch int64, trust string, tools Tools) (err error) {
	if e := binding.Validate(); e != nil {
		return e
	}
	if trust != "qualification" && trust != "production" {
		return errors.New("linux-trust-mode")
	}
	if epoch <= 0 {
		return errors.New("linux-source-epoch")
	}
	if _, e := os.Lstat(out); !os.IsNotExist(e) {
		return errors.New("linux-output-exists")
	}
	staging, e := os.MkdirTemp(filepath.Dir(out), ".a2a-linux-*")
	if e != nil {
		return e
	}
	defer os.RemoveAll(staging)
	sourceHash, e := fileHash(sourceArchive)
	if e != nil {
		return errors.New("linux-source-archive")
	}
	evidence := LinuxEvidence{Schema: LinuxSchema, Binding: binding, Trust: trust, SourceArchiveSHA256: sourceHash, SourceDateEpoch: epoch, GoVersion: tools.Go, Flags: append([]string{}, BuildFlags...), Tools: tools, Assets: []LinuxAsset{}, Limits: []string{"Module inputs use -mod=readonly after resolution, instead of managed vendor staging.", "No native arm64 installation, public download, macOS cross-build equality or combined publication is established by Linux preparation."}}
	docs := map[string][]byte{}
	for n, p := range map[string]string{"LICENSE": "LICENSE", "NOTICE": "NOTICE", "INSTALL.md": "release/INSTALL-linux.md"} {
		b, e := os.ReadFile(filepath.Join(root, p))
		if e != nil {
			return e
		}
		docs[n] = b
	}
	binaries := map[string][]byte{}
	for i, n := range LinuxArtifacts(binding.Version()) {
		arch := "amd64"
		if i%2 == 1 {
			arch = "arm64"
		}
		b, e := readRegular(dist, n)
		if e != nil {
			return e
		}
		sha := Hash(b)
		sbom, e := readRegular(dist, n+".sbom.json")
		if e != nil {
			return e
		}
		if e = verifySBOM(sbom, n, sha, binding.Version(), arch); e != nil {
			return fmt.Errorf("%s: %w", n, e)
		}
		packageArch := arch
		switch {
		case strings.HasSuffix(n, ".tar.gz"):
			binaryBytes, e := ArchiveBinary(b, epoch, docs)
			if e != nil {
				return e
			}
			if e = VerifyELF(binaryBytes, arch); e != nil {
				return e
			}
			binaries[arch] = binaryBytes
		case strings.HasSuffix(n, ".deb"):
			if e = verifyDeb(b, binaries[arch], binding.Version(), arch); e != nil {
				return e
			}
		case strings.HasSuffix(n, ".rpm"):
			packageArch = "x86_64"
			if arch == "arm64" {
				packageArch = "aarch64"
			}
			if e = verifyRPM(b, binaries[arch], binding.Version(), packageArch); e != nil {
				return e
			}
		}
		evidence.Assets = append(evidence.Assets, LinuxAsset{n, sha, "linux/" + arch, packageArch, Hash(binaries[arch]), Hash(sbom)})
		for name, data := range map[string][]byte{n: b, n + ".sbom.json": sbom} {
			if e = os.WriteFile(filepath.Join(staging, name), data, 0600); e != nil {
				return e
			}
		}
	}
	b, e := json.MarshalIndent(evidence, "", "  ")
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(staging, "linux-release-evidence.json"), append(b, '\n'), 0600); e != nil {
		return e
	}
	if e = WriteChecksums(staging, "linux-checksums.txt"); e != nil {
		return e
	}
	return os.Rename(staging, out)
}

func WriteChecksums(dir, name string) error {
	es, e := os.ReadDir(dir)
	if e != nil {
		return e
	}
	sort.Slice(es, func(i, j int) bool { return es[i].Name() < es[j].Name() })
	var sums strings.Builder
	for _, entry := range es {
		n := entry.Name()
		if n == name || n == name+".sig" || n == name+".pem" {
			continue
		}
		b, e := readRegular(dir, n)
		if e != nil {
			return e
		}
		fmt.Fprintf(&sums, "%s  %s\n", Hash(b), n)
	}
	return os.WriteFile(filepath.Join(dir, name), []byte(sums.String()), 0600)
}

func VerifyLinuxEvidence(raw []byte, b Binding, dir string) error {
	var ev LinuxEvidence
	if e := DecodeExact(raw, &ev); e != nil {
		return fmt.Errorf("linux-evidence-malformed: %w", e)
	}
	if ev.Schema != LinuxSchema || ev.Binding != b {
		return errors.New("linux-evidence-source-tag-binding")
	}
	if ev.Trust != "production" {
		return errors.New("production-fixture-trust-refused")
	}
	if ev.GoVersion != "go1.25.12" || ev.SourceDateEpoch <= 0 || !digestForm.MatchString(ev.SourceArchiveSHA256) || strings.Join(ev.Flags, "\n") != strings.Join(BuildFlags, "\n") {
		return errors.New("linux-evidence-build-contract")
	}
	if ev.Tools.Validate() != nil || ev.Tools.Go != ev.GoVersion {
		return errors.New("linux-evidence-tools")
	}
	if len(ev.Assets) != 6 {
		return errors.New("linux-evidence-members")
	}
	binaryDigests := map[string]string{}
	for i, n := range LinuxArtifacts(b.Version()) {
		a := ev.Assets[i]
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
		if a.Name != n || a.Architecture != "linux/"+arch || a.PackageArchitecture != pa || !digestForm.MatchString(a.BinarySHA256) {
			return errors.New("linux-evidence-architecture")
		}
		if i < 2 {
			binaryDigests[arch] = a.BinarySHA256
		} else if a.BinarySHA256 != binaryDigests[arch] {
			return errors.New("linux-evidence-binary-binding")
		}
		x, e := readRegular(dir, n)
		if e != nil {
			return e
		}
		s, e := readRegular(dir, n+".sbom.json")
		if e != nil {
			return e
		}
		if a.SHA256 != Hash(x) || a.SBOMSHA256 != Hash(s) {
			return errors.New("linux-evidence-digest-binding")
		}
		if e = verifySBOM(s, n, a.SHA256, b.Version(), arch); e != nil {
			return e
		}
	}
	return nil
}
