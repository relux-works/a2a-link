package sharedrelease

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// CompareLinuxBuild binds an independently compiled executable to the complete
// Linux archive and producer evidence. Callers establish source/toolchain and
// run the independent build on macOS; this function never compiles or executes.
func CompareLinuxBuild(root, dir, independent, arch string, b Binding, epoch int64) error {
	if e := b.Validate(); e != nil {
		return e
	}
	if arch != "amd64" && arch != "arm64" {
		return errors.New("crossbuild-architecture")
	}
	raw, e := readRegular(dir, "linux-release-evidence.json")
	if e != nil {
		return e
	}
	var ev LinuxEvidence
	if DecodeExact(raw, &ev) != nil || ev.Binding != b || ev.SourceDateEpoch != epoch || ev.GoVersion != "go1.26.8" || ev.Schema != LinuxSchema || strings.Join(ev.Flags, "\n") != strings.Join(BuildFlags, "\n") || ev.Tools.Validate() != nil || (ev.Trust != "production" && ev.Trust != "qualification") {
		return errors.New("crossbuild-evidence-binding")
	}
	// Verification remains production-only elsewhere. Qualification comparison
	// emits no manifest/signature and cannot promote qualification evidence.
	docs := map[string][]byte{}
	for _, p := range []struct{ name, path string }{{"LICENSE", "LICENSE"}, {"NOTICE", "NOTICE"}, {"INSTALL.md", "release/INSTALL-linux.md"}} {
		docs[p.name], e = os.ReadFile(filepath.Join(root, p.path))
		if e != nil {
			return e
		}
	}
	archiveName := "a2a_" + b.Version() + "_linux_" + arch + ".tar.gz"
	raw, e = readRegular(dir, archiveName)
	if e != nil {
		return e
	}
	bin, e := ArchiveBinary(raw, epoch, docs)
	if e != nil {
		return e
	}
	if e = VerifyELF(bin, arch); e != nil {
		return e
	}
	found := 0
	for _, a := range ev.Assets {
		if a.Name == archiveName {
			found++
			if a.SHA256 != Hash(raw) || a.BinarySHA256 != Hash(bin) || a.Architecture != "linux/"+arch {
				return errors.New("crossbuild-producer-digest")
			}
		}
	}
	if found != 1 {
		return errors.New("crossbuild-evidence-member")
	}
	other, e := readRegular(filepath.Dir(independent), filepath.Base(independent))
	if e != nil {
		return e
	}
	if !bytes.Equal(bin, other) {
		return errors.New("crossbuild-binary-mismatch")
	}
	return nil
}
