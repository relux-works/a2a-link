package darwinrelease

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// VerifyPreparedBundle independently verifies captured Darwin bytes on the
// approved native runner without signing material, rebuilding or executing the
// payload. The caller independently supplies all three source identities.
func VerifyPreparedBundle(ctx context.Context, root, tag, commit, tagObject, dir string) error {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		return errors.New("native-darwin-arm64-runner-required")
	}
	if !stableTag.MatchString(tag) || !objectID.MatchString(commit) || !objectID.MatchString(tagObject) {
		return errors.New("darwin-input-binding")
	}
	for _, n := range SigningFields {
		if os.Getenv(n) != "" {
			return errors.New("assembly-signing-material-refused")
		}
	}
	policy, e := LoadPolicy(root)
	if e != nil {
		return e
	}
	if runtime.Version() != policy.GoVersion {
		return errors.New("go-toolchain-mismatch")
	}
	temp, e := os.MkdirTemp("", "a2a-native-input-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(temp)
	names := []string{"a2a_" + strings.TrimPrefix(tag, "v") + "_darwin_arm64.tar.gz", "checksums.txt", "checksums.txt.sig", "checksums.txt.pem", "evidence.tar.gz", "release-evidence.json"}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != len(names) {
		return errors.New("darwin-input-members")
	}
	for _, n := range names {
		p := filepath.Join(dir, n)
		st, e := os.Lstat(p)
		if e != nil || !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > 128<<20 {
			return errors.New("darwin-input-member")
		}
		x, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		if e = os.WriteFile(filepath.Join(temp, n), x, 0600); e != nil {
			return e
		}
	}
	if e = verifyAssetChecksums(temp); e != nil {
		return e
	}
	identity := "https://github.com/relux-works/a2a-swarm/.github/workflows/darwin-release.yml@refs/tags/" + tag
	if _, e = execute(ctx, root, "cosign", "verify-blob", "--signature", filepath.Join(temp, "checksums.txt.sig"), "--certificate", filepath.Join(temp, "checksums.txt.pem"), "--certificate-identity", identity, "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", "--certificate-github-workflow-sha", commit, "--certificate-github-workflow-ref", "refs/tags/"+tag, "--certificate-github-workflow-repository", "relux-works/a2a-swarm", "--certificate-github-workflow-trigger", "push", filepath.Join(temp, "checksums.txt")); e != nil {
		return errors.New("darwin-input-signature")
	}
	raw, e := os.ReadFile(filepath.Join(temp, "release-evidence.json"))
	if e != nil {
		return e
	}
	var ev Evidence
	if json.Unmarshal(raw, &ev) != nil || ev.Admission.Tag != tag || ev.Admission.Commit != commit || ev.Admission.TagObject != tagObject || ev.Admission.Version != strings.TrimPrefix(tag, "v") || len(ev.Identities) != 2 {
		return errors.New("darwin-input-evidence-binding")
	}
	modes := map[string]int64{}
	for _, n := range payloadNames {
		modes[n] = 0644
	}
	for _, n := range Binaries {
		modes[n] = 0755
	}
	payload, e := extractBoundTar(filepath.Join(temp, names[0]), modes)
	if e != nil {
		return e
	}
	proofModes := map[string]int64{"notary.json": 0600, "release-evidence.json": 0600}
	for _, n := range Binaries {
		for _, suffix := range []string{".requirement.bin", ".requirement.txt", ".codesign.txt"} {
			proofModes[n+suffix] = 0600
		}
	}
	proof, e := extractBoundTar(filepath.Join(temp, "evidence.tar.gz"), proofModes)
	if e != nil {
		return e
	}
	if !bytes.Equal(proof["release-evidence.json"], raw) {
		return errors.New("darwin-input-evidence-copy")
	}
	native := filepath.Join(temp, "native")
	if e = os.Mkdir(native, 0700); e != nil {
		return e
	}
	hashes := map[string]string{}
	for i, n := range Binaries {
		path := filepath.Join(native, n)
		if e = os.WriteFile(path, payload[n], 0755); e != nil {
			return e
		}
		id, e := VerifyBinary(path, n, native)
		if e != nil {
			return e
		}
		if id != ev.Identities[i] || digest(proof[n+".requirement.bin"]) != id.CompiledDR || !bytes.Equal(proof[n+".requirement.txt"], []byte(id.DR+"\n")) {
			return errors.New("darwin-input-full-requirement")
		}
		displayCmd := exec.CommandContext(ctx, "/usr/bin/codesign", "--display", "--verbose=4", "--requirements", "-", path)
		displayCmd.Env = cleanEnvironment()
		display, e := displayCmd.CombinedOutput()
		if e != nil {
			return errors.New("darwin-input-codesign-display")
		}
		current, e := codeDirectoryHash(display)
		if e != nil {
			return e
		}
		recorded, e := codeDirectoryHash(proof[n+".codesign.txt"])
		if e != nil || current != recorded {
			return errors.New("darwin-input-ticket-binary")
		}
		hashes[n] = current
	}
	if _, e = validateNotaryLog(proof["notary.json"], ev.Notary, ev.NotaryZIP, hashes); e != nil {
		return e
	}
	return nil
}

// extractBoundTar accepts only closed flat regular entries at exact installer
// modes; no traversal, alias, duplicate, privileged bit or trailing stream.
func extractBoundTar(path string, modes map[string]int64) (map[string][]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	compressed := bufio.NewReader(f)
	gz, e := gzip.NewReader(compressed)
	if e != nil {
		return nil, e
	}
	defer gz.Close()
	gz.Multistream(false)
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
		mode, ok := modes[h.Name]
		if !ok || files[h.Name] != nil || h.Typeflag != tar.TypeReg || h.Mode != mode || h.Linkname != "" || h.Size <= 0 || h.Size > 128<<20 {
			return nil, errors.New("darwin-input-tar-entry")
		}
		x, e := io.ReadAll(io.LimitReader(tr, 128<<20+1))
		if e != nil || int64(len(x)) != h.Size {
			return nil, errors.New("darwin-input-tar-read")
		}
		files[h.Name] = x
	}
	if len(files) != len(modes) {
		return nil, errors.New("darwin-input-tar-members")
	}
	if e = finishArchiveStream(gz, compressed); e != nil {
		return nil, e
	}
	return files, nil
}
