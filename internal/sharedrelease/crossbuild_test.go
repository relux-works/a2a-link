package sharedrelease

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Real approved archives match their extracted binary; a one-byte independent-build change refuses at the byte gate.
func TestIndependentLinuxByteControl(t *testing.T) {
	bundle := os.Getenv("A2A_CROSSBUILD_BUNDLE")
	if bundle == "" {
		t.Skip("real hosted Linux preparation bundle required")
	}
	root := os.Getenv("A2A_CROSSBUILD_ROOT")
	if root == "" {
		t.Fatal("source root required")
	}
	raw, e := os.ReadFile(filepath.Join(bundle, "linux-release-evidence.json"))
	if e != nil {
		t.Fatal(e)
	}
	var ev LinuxEvidence
	if e = json.Unmarshal(raw, &ev); e != nil {
		t.Fatal(e)
	}
	docs := map[string][]byte{}
	for n, p := range map[string]string{"LICENSE": "LICENSE", "NOTICE": "NOTICE", "INSTALL.md": "release/INSTALL-linux.md"} {
		docs[n], e = os.ReadFile(filepath.Join(root, p))
		if e != nil {
			t.Fatal(e)
		}
	}
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			raw, e := os.ReadFile(filepath.Join(bundle, "a2a_"+ev.Binding.Version()+"_linux_"+arch+".tar.gz"))
			if e != nil {
				t.Fatal(e)
			}
			bin, e := ArchiveBinary(raw, ev.SourceDateEpoch, docs)
			if e != nil {
				t.Fatal(e)
			}
			p := filepath.Join(t.TempDir(), "a2a")
			if e = os.WriteFile(p, bin, 0600); e != nil {
				t.Fatal(e)
			}
			if e = CompareLinuxBuild(root, bundle, p, arch, ev.Binding, ev.SourceDateEpoch); e != nil {
				t.Fatal(e)
			}
			bin[len(bin)-1] ^= 1
			if e = os.WriteFile(p, bin, 0600); e != nil {
				t.Fatal(e)
			}
			if e = CompareLinuxBuild(root, bundle, p, arch, ev.Binding, ev.SourceDateEpoch); e == nil || e.Error() != "crossbuild-binary-mismatch" {
				t.Fatal("altered byte survived", e)
			}
		})
	}
}
