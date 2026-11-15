package sharedrelease

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func archiveFixture(t *testing.T, edit func(*tar.Header)) ([]byte, map[string][]byte) {
	t.Helper()
	docs := map[string][]byte{"LICENSE": []byte("license"), "NOTICE": []byte("notice"), "INSTALL.md": []byte("install")}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, n := range []string{"LICENSE", "NOTICE", "INSTALL.md", "a2a"} {
		b := docs[n]
		mode := int64(0644)
		if n == "a2a" {
			b = []byte("static binary fixture")
			mode = 0755
		}
		h := &tar.Header{Name: n, Mode: mode, Size: int64(len(b)), Typeflag: tar.TypeReg, ModTime: time.Unix(1700000000, 0), Uname: "root", Gname: "root"}
		if edit != nil {
			edit(h)
		}
		if e := tw.WriteHeader(h); e != nil {
			t.Fatal(e)
		}
		if h.Typeflag == tar.TypeReg {
			if _, e := tw.Write(b); e != nil {
				t.Fatal(e)
			}
		}
	}
	if e := tw.Close(); e != nil {
		t.Fatal(e)
	}
	if e := gz.Close(); e != nil {
		t.Fatal(e)
	}
	return buf.Bytes(), docs
}

// Exact member metadata is part of the archive contract. In particular, the
// observed LICENSE/NOTICE timestamp drift is rejected while unchanged binary
// bytes alone would pass a binary-only comparison. Real two-build archive byte
// equality is exercised separately by linux-production-packages.
func TestLinuxArchiveMetadataPlants(t *testing.T) {
	b, docs := archiveFixture(t, nil)
	bin, e := ArchiveBinary(b, 1700000000, docs)
	if e != nil || string(bin) != "static binary fixture" {
		t.Fatal(e)
	}
	for n, edit := range map[string]func(*tar.Header){
		"LICENSE mtime": func(h *tar.Header) {
			if h.Name == "LICENSE" {
				h.ModTime = h.ModTime.Add(time.Hour)
			}
		},
		"NOTICE mtime": func(h *tar.Header) {
			if h.Name == "NOTICE" {
				h.ModTime = h.ModTime.Add(time.Hour)
			}
		},
		"binary mode": func(h *tar.Header) {
			if h.Name == "a2a" {
				h.Mode = 0644
			}
		},
		"owner id":   func(h *tar.Header) { h.Uid = 501 },
		"group name": func(h *tar.Header) { h.Gname = "staff" },
		"symlink": func(h *tar.Header) {
			if h.Name == "NOTICE" {
				h.Typeflag = tar.TypeSymlink
				h.Linkname = "LICENSE"
				h.Size = 0
			}
		},
	} {
		t.Run(n, func(t *testing.T) {
			x, docs := archiveFixture(t, edit)
			_, e := ArchiveBinary(x, 1700000000, docs)
			if e == nil || !strings.Contains(e.Error(), "linux-archive-metadata") {
				t.Fatal("metadata plant survived", e)
			}
		})
	}
	changed := map[string][]byte{}
	for k, v := range docs {
		changed[k] = v
	}
	changed["NOTICE"] = []byte("changed")
	if _, e := ArchiveBinary(b, 1700000000, changed); e == nil || e.Error() != "linux-archive-document-bytes: NOTICE" {
		t.Fatal(e)
	}
	corrupt := append([]byte{}, b...)
	corrupt[len(corrupt)-8] ^= 1
	if _, e := ArchiveBinary(corrupt, 1700000000, docs); e == nil || e.Error() != "linux-archive-gzip" {
		t.Fatal("CRC plant survived", e)
	}
}

// SBOMs must identify the pinned scanner, actual artifact digest and CLI module;
// a nonempty but unrelated SBOM cannot satisfy the subject binding gate.
func TestLinuxSBOMBinding(t *testing.T) {
	n := "a2a_0.1.2_linux_arm64.tar.gz"
	sha := strings.Repeat("a", 64)
	good := sbomFixture(n, sha)
	if e := verifySBOM(good, n, sha); e != nil {
		t.Fatal(e)
	}
	for name, tc := range map[string]struct{ from, to, want string }{
		"digest":  {sha, strings.Repeat("b", 64), "linux-sbom-subject-mismatch"},
		"scanner": {"1.38.0", "1.37.0", "linux-sbom-identity"},
		"subject": {n, "other.tar.gz", "linux-sbom-identity"},
		"module":  {Repository, "other/project", "linux-sbom-cli-module-missing"},
	} {
		t.Run(name, func(t *testing.T) {
			bad := []byte(strings.Replace(string(good), tc.from, tc.to, 1))
			if e := verifySBOM(bad, n, sha); e == nil || e.Error() != tc.want {
				t.Fatalf("wanted %s, got %v", tc.want, e)
			}
		})
	}
}

func tgz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	g := gzip.NewWriter(&b)
	w := tar.NewWriter(g)
	names := []string{}
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		x := files[n]
		mode := int64(0644)
		if n == "./usr/bin/a2a" {
			mode = 0755
		}
		if e := w.WriteHeader(&tar.Header{Name: n, Typeflag: tar.TypeReg, Mode: mode, Size: int64(len(x))}); e != nil {
			t.Fatal(e)
		}
		if _, e := w.Write(x); e != nil {
			t.Fatal(e)
		}
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	if e := g.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func debFixture(t *testing.T, arch string, bin []byte, script bool) []byte {
	t.Helper()
	control := map[string][]byte{"control": []byte("Package: a2a\nVersion: 0.1.2\nArchitecture: " + arch + "\n")}
	if script {
		control["postinst"] = []byte("forbidden fixture script")
	}
	var out bytes.Buffer
	out.WriteString("!<arch>\n")
	for _, f := range []struct {
		n string
		b []byte
	}{{"debian-binary", []byte("2.0\n")}, {"control.tar.gz", tgz(t, control)}, {"data.tar.gz", tgz(t, map[string][]byte{"./usr/bin/a2a": bin})}} {
		fmt.Fprintf(&out, "%-16s%-12d%-6d%-6d%-8o%-10d`\n", f.n+"/", 0, 0, 0, 0644, len(f.b))
		out.Write(f.b)
		if len(f.b)%2 != 0 {
			out.WriteByte('\n')
		}
	}
	return out.Bytes()
}
func rpmFixture(t *testing.T, arch string, bin []byte, script bool) []byte {
	t.Helper()
	header := func(tags map[uint32]string) []byte {
		keys := []int{}
		for k := range tags {
			keys = append(keys, int(k))
		}
		sort.Ints(keys)
		var idx, data bytes.Buffer
		for _, i := range keys {
			for _, n := range []uint32{uint32(i), 6, uint32(data.Len()), 1} {
				if e := binary.Write(&idx, binary.BigEndian, n); e != nil {
					t.Fatal(e)
				}
			}
			data.WriteString(tags[uint32(i)])
			data.WriteByte(0)
		}
		b := []byte{0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0}
		b = binary.BigEndian.AppendUint32(b, uint32(len(keys)))
		b = binary.BigEndian.AppendUint32(b, uint32(data.Len()))
		b = append(b, idx.Bytes()...)
		return append(b, data.Bytes()...)
	}
	lead := make([]byte, 96)
	copy(lead, []byte{0xed, 0xab, 0xee, 0xdb})
	sig := header(map[uint32]string{})
	lead = append(lead, sig...)
	for len(lead)%8 != 0 {
		lead = append(lead, 0)
	}
	tags := map[uint32]string{1000: "a2a", 1001: "0.1.2", 1002: "1", 1022: arch, 1124: "cpio", 1125: "gzip"}
	if script {
		tags[1024] = "forbidden fixture script"
	}
	lead = append(lead, header(tags)...)
	var cpio bytes.Buffer
	entry := func(n string, x []byte, mode int) {
		fmt.Fprintf(&cpio, "070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x", 1, mode, 0, 0, 1, 0, len(x), 0, 0, 0, 0, len(n)+1, 0)
		cpio.WriteString(n)
		cpio.WriteByte(0)
		for cpio.Len()%4 != 0 {
			cpio.WriteByte(0)
		}
		cpio.Write(x)
		for cpio.Len()%4 != 0 {
			cpio.WriteByte(0)
		}
	}
	entry("./usr/bin/a2a", bin, 0100755)
	entry("TRAILER!!!", nil, 0)
	var compressed bytes.Buffer
	g := gzip.NewWriter(&compressed)
	if _, e := g.Write(cpio.Bytes()); e != nil {
		t.Fatal(e)
	}
	if e := g.Close(); e != nil {
		t.Fatal(e)
	}
	return append(lead, compressed.Bytes()...)
}

// Parser fixtures establish intended metadata/payload rejection, not package
// installation. Hosted CI separately verifies the real GoReleaser packages and
// runs install/uninstall in disposable offline containers.
func TestLinuxPackageContract(t *testing.T) {
	bin := []byte("reference binary")
	for _, format := range []string{"deb", "rpm"} {
		t.Run(format, func(t *testing.T) {
			arch := "arm64"
			makePkg := func(arch string, bin []byte, script bool) []byte { return debFixture(t, arch, bin, script) }
			check := verifyDeb
			if format == "rpm" {
				arch = "aarch64"
				makePkg = func(arch string, bin []byte, script bool) []byte { return rpmFixture(t, arch, bin, script) }
				check = verifyRPM
			}
			if e := check(makePkg(arch, bin, false), bin, "0.1.2", arch); e != nil {
				t.Fatal("valid package", e)
			}
			for n, tc := range map[string]struct {
				data []byte
				want string
			}{
				"architecture": {makePkg("x86_64", bin, false), "package-architecture-or-version"},
				"payload":      {makePkg(arch, []byte("altered binary"), false), "package-payload-mismatch"},
				"script":       {makePkg(arch, bin, true), map[string]string{"deb": "deb-maintainer-or-config-file", "rpm": "rpm-script-or-trigger"}[format]},
			} {
				t.Run(n, func(t *testing.T) {
					if e := check(tc.data, bin, "0.1.2", arch); e == nil || !strings.Contains(e.Error(), tc.want) {
						t.Fatalf("want %s, got %v", tc.want, e)
					}
				})
			}
		})
	}
}

// Missing producer outputs cannot expose a partial bundle. An existing output
// directory belongs to its caller and is preserved, never cleaned on refusal.
func TestLinuxBundleFailureIsAtomic(t *testing.T) {
	root := t.TempDir()
	if e := os.Mkdir(filepath.Join(root, "release"), 0700); e != nil {
		t.Fatal(e)
	}
	for _, n := range []string{"LICENSE", "NOTICE", "release/INSTALL-linux.md"} {
		put(t, filepath.Dir(filepath.Join(root, n)), filepath.Base(n), []byte("document"))
	}
	archive := filepath.Join(root, "source.tar")
	put(t, root, "source.tar", []byte("source archive"))
	dist := t.TempDir()
	out := filepath.Join(root, "bundle")
	e := PrepareLinux(root, dist, out, archive, binding(), 1700000000, "qualification", Tools{Go: "go1.25.12"})
	if e == nil || !strings.Contains(e.Error(), "asset-type-or-missing") {
		t.Fatal(e)
	}
	if _, e := os.Stat(out); !os.IsNotExist(e) {
		t.Fatal("partial bundle exposed")
	}
	left, _ := filepath.Glob(filepath.Join(root, ".a2a-linux-*"))
	if len(left) != 0 {
		t.Fatal("staging leaked", left)
	}
	if e := os.Mkdir(out, 0700); e != nil {
		t.Fatal(e)
	}
	put(t, out, "owned", []byte("preserve"))
	e = PrepareLinux(root, dist, out, archive, binding(), 1700000000, "qualification", Tools{})
	if e == nil || e.Error() != "linux-output-exists" {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(filepath.Join(out, "owned"))
	if string(b) != "preserve" {
		t.Fatal("existing output changed")
	}
}
