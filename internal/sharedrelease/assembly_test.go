package sharedrelease

import (
	"os"
	"path/filepath"
	"testing"
)

// Independent source binding refuses a different archive beside the accepted producer archive digest.
func TestCrossBuildSourceBinding(t *testing.T) {
	dir, raw := platformFixture(t)
	_ = raw
	source := []byte("source fixture")
	p := filepath.Join(t.TempDir(), "source.tar")
	put(t, filepath.Dir(p), filepath.Base(p), source)
	evidenceRaw, e := os.ReadFile(filepath.Join(dir, "linux-release-evidence.json"))
	if e != nil {
		t.Fatal(e)
	}
	var ev LinuxEvidence
	if e = DecodeExact(evidenceRaw, &ev); e != nil {
		t.Fatal(e)
	}
	ev.SourceArchiveSHA256 = Hash(source)
	put(t, dir, "linux-release-evidence.json", encode(t, ev))
	if e = VerifyCrossSource(dir, p, binding()); e != nil {
		t.Fatal(e)
	}
	put(t, filepath.Dir(p), filepath.Base(p), []byte("different source"))
	if e = VerifyCrossSource(dir, p, binding()); e == nil || e.Error() != "crossbuild-source-archive" {
		t.Fatal("different source accepted", e)
	}
}
