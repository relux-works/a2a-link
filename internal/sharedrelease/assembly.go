package sharedrelease

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/relux-works/a2a-swarm/internal/darwinrelease"
)

type BundleInput struct {
	ZIP      string            `json:"zip"`
	Artifact ArtifactReference `json:"artifact"`
}
type AssemblyInputs struct {
	Darwin BundleInput `json:"darwin"`
	Linux  BundleInput `json:"linux"`
}
type AssemblyEvidence struct {
	Binding      Binding           `json:"binding"`
	Darwin       ArtifactReference `json:"darwin"`
	Linux        ArtifactReference `json:"linux"`
	BinarySHA256 map[string]string `json:"independent_linux_binary_sha256"`
}

// AssembleInputs is private preparation only. Immutable producer association,
// original native Darwin verification and actual independent offline macOS
// builds precede the authenticated aggregate. No upload/publisher is called.
func AssembleInputs(ctx context.Context, root, out, sourceArchive string, b Binding, epoch int64, inputs AssemblyInputs) (AssemblyEvidence, error) {
	var zero AssemblyEvidence
	if e := b.Validate(); e != nil {
		return zero, e
	}
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" || runtime.Version() != qualifiedGoVersion {
		return zero, errors.New("assembly-native-toolchain-required")
	}
	if inputs.Darwin.Artifact.Platform != "darwin" || inputs.Linux.Artifact.Platform != "linux" || inputs.Darwin.Artifact.RunID != inputs.Linux.Artifact.RunID {
		return zero, errors.New("assembly-producer-run-binding")
	}
	if _, e := os.Lstat(out); !os.IsNotExist(e) {
		return zero, errors.New("assembly-output-exists")
	}
	temp, e := os.MkdirTemp(filepath.Dir(out), ".a2a-assembly-")
	if e != nil {
		return zero, e
	}
	defer os.RemoveAll(temp)
	darwinDir := filepath.Join(temp, "darwin")
	linuxDir := filepath.Join(temp, "linux")
	if e = CaptureBundle(ctx, inputs.Darwin.ZIP, darwinDir, b, inputs.Darwin.Artifact); e != nil {
		return zero, e
	}
	if e = CaptureBundle(ctx, inputs.Linux.ZIP, linuxDir, b, inputs.Linux.Artifact); e != nil {
		return zero, e
	}
	if e = darwinrelease.VerifyPreparedBundle(ctx, root, b.Tag, b.Commit, b.TagObject, darwinDir); e != nil {
		return zero, e
	}
	raw, e := readRegular(linuxDir, "linux-release-evidence.json")
	if e != nil {
		return zero, e
	}
	if e = VerifyLinuxEvidence(raw, b, linuxDir); e != nil {
		return zero, e
	}
	if e = VerifyCrossSource(linuxDir, sourceArchive, b); e != nil {
		return zero, e
	}
	evidence := AssemblyEvidence{b, inputs.Darwin.Artifact, inputs.Linux.Artifact, map[string]string{}}
	for _, arch := range []string{"amd64", "arm64"} {
		binary := filepath.Join(temp, "independent-"+arch)
		if e = BuildIndependentLinux(ctx, root, binary, arch); e != nil {
			return zero, e
		}
		if e = CompareLinuxBuild(root, linuxDir, binary, arch, b, epoch); e != nil {
			return zero, e
		}
		raw, e := os.ReadFile(binary)
		if e != nil {
			return zero, e
		}
		evidence.BinarySHA256[arch] = Hash(raw)
	}
	staging := filepath.Join(temp, "platform")
	if e = os.Mkdir(staging, 0700); e != nil {
		return zero, e
	}
	for _, platform := range []struct {
		dir   string
		names []string
	}{{darwinDir, DarwinMembers(b.Version())}, {linuxDir, LinuxMembers(b.Version())}} {
		for _, n := range platform.names {
			raw, e := readRegular(platform.dir, n)
			if e != nil {
				return zero, e
			}
			if e = os.WriteFile(filepath.Join(staging, n), raw, 0600); e != nil {
				return zero, e
			}
		}
	}
	// Creation authenticates both checksum signatures with the source/ref claims.
	// Signing the aggregate remains the separate admitted manifest boundary.
	if _, e = CreateManifest(ctx, b, staging, nil); e != nil {
		return zero, e
	}
	if e = os.Rename(staging, out); e != nil {
		return zero, e
	}
	return evidence, nil
}

// BuildIndependentLinux runs the approved compiler on macOS, offline and with
// explicit portable settings. A caller cannot substitute an extracted binary.
func BuildIndependentLinux(ctx context.Context, root, out, arch string) error {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" || runtime.Version() != qualifiedGoVersion {
		return errors.New("crossbuild-native-toolchain-required")
	}
	if arch != "amd64" && arch != "arm64" {
		return errors.New("crossbuild-architecture")
	}
	if _, e := os.Lstat(out); !os.IsNotExist(e) {
		return errors.New("crossbuild-output-exists")
	}
	args := append([]string{"build"}, BuildFlags...)
	args = append(args, "-o", out, "./cmd/a2a")
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = root
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "GO") || strings.HasPrefix(key, "CGO_") || strings.HasPrefix(key, "GIT_") || strings.HasPrefix(key, "ACTIONS_ID_TOKEN_") || key == "GITHUB_TOKEN" || key == "GH_TOKEN" {
			continue
		}
		blocked := false
		for _, field := range darwinrelease.SigningFields {
			blocked = blocked || key == field
		}
		if !blocked {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	// Only task-local cache paths are inherited; ambient build flags and settings
	// cannot alter the independent compiler contract or enable dependency access.
	for _, key := range []string{"GOCACHE", "GOMODCACHE"} {
		if value := os.Getenv(key); value != "" {
			cmd.Env = append(cmd.Env, key+"="+value)
		}
	}
	cmd.Env = append(cmd.Env, "GOOS=linux", "GOARCH="+arch, "GOAMD64=v1", "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOWORK=off", "GOENV=off", "GOFLAGS=")
	version := exec.CommandContext(ctx, "go", "version")
	version.Env = cmd.Env
	version.Dir = root
	reported, e := version.Output()
	if e != nil || strings.TrimSpace(string(reported)) != "go version "+qualifiedGoVersion+" darwin/arm64" {
		return errors.New("crossbuild-compiler-toolchain")
	}
	if e := cmd.Run(); e != nil {
		os.Remove(out)
		return errors.New("crossbuild-compiler-refused")
	}
	return nil
}

// VerifyCrossSource binds the producer's full Git archive to the independently
// checked source archive; matching executable bytes alone cannot replace it.
func VerifyCrossSource(dir, archive string, b Binding) error {
	raw, e := readRegular(dir, "linux-release-evidence.json")
	if e != nil {
		return e
	}
	var ev LinuxEvidence
	if DecodeExact(raw, &ev) != nil || ev.Binding != b {
		return errors.New("crossbuild-evidence-binding")
	}
	source, e := os.ReadFile(archive)
	if e != nil || ev.SourceArchiveSHA256 != Hash(source) {
		return errors.New("crossbuild-source-archive")
	}
	return nil
}
