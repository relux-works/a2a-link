package sharedrelease

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/md5"  // RPM's existing header+payload integrity field, not an authentication primitive.
	"crypto/sha1" // RPM's existing header integrity field, not an authentication primitive.
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
)

type reviewerRPMField struct {
	kind, count uint32
	offset      int
}

// This fixture decoder is independent of the product decoder under test.
func reviewerRPMHeader(t *testing.T, b []byte, off int) (map[uint32]reviewerRPMField, int) {
	t.Helper()
	if off < 0 || off+16 > len(b) {
		t.Fatal("fixture RPM header")
	}
	n := int(binary.BigEndian.Uint32(b[off+8 : off+12]))
	size := int(binary.BigEndian.Uint32(b[off+12 : off+16]))
	store := off + 16 + 16*n
	if n > 8192 || size < 0 || store+size > len(b) {
		t.Fatal("fixture RPM bounds")
	}
	fields := map[uint32]reviewerRPMField{}
	for i := 0; i < n; i++ {
		p := off + 16 + 16*i
		tag := binary.BigEndian.Uint32(b[p : p+4])
		offset := int(binary.BigEndian.Uint32(b[p+8 : p+12]))
		if offset > size {
			t.Fatal("fixture RPM field")
		}
		fields[tag] = reviewerRPMField{binary.BigEndian.Uint32(b[p+4 : p+8]), binary.BigEndian.Uint32(b[p+12 : p+16]), store + offset}
	}
	return fields, store + size
}

func reviewerRPMIntegrity(t *testing.T, b []byte, write bool) {
	t.Helper()
	sig, end := reviewerRPMHeader(t, b, 96)
	start := (end + 7) / 8 * 8
	_, headerEnd := reviewerRPMHeader(t, b, start)
	s1 := sha1.Sum(b[start:headerEnd])
	s256 := sha256.Sum256(b[start:headerEnd])
	m := md5.Sum(b[start:])
	for _, d := range []struct {
		tag, kind uint32
		digest    []byte
	}{{269, 6, []byte(hex.EncodeToString(s1[:]))}, {273, 6, []byte(hex.EncodeToString(s256[:]))}, {1004, 7, m[:]}} {
		f, ok := sig[d.tag]
		if !ok || f.kind != d.kind || f.offset+len(d.digest) > len(b) {
			t.Fatal("missing real RPM integrity field", d.tag)
		}
		wantCount := len(d.digest)
		if d.kind == 6 {
			wantCount++
		}
		if int(f.count) != wantCount {
			t.Fatal("fixture digest cardinality")
		}
		if write {
			copy(b[f.offset:], d.digest)
		} else if !bytes.Equal(b[f.offset:f.offset+len(d.digest)], d.digest) {
			t.Fatal("fixture integrity mismatch", d.tag)
		}
	}
}

// Regenerate the reviewer's two header-only plants against the current real package, retaining its CPIO bytes and valid integrity fields.
func reviewerRPMModePlant(t *testing.T, original []byte, mode uint16) []byte {
	t.Helper()
	reviewerRPMIntegrity(t, original, false)
	b := append([]byte{}, original...)
	_, end := reviewerRPMHeader(t, b, 96)
	tags, headerEnd := reviewerRPMHeader(t, b, (end+7)/8*8)
	f := tags[1030]
	if f.kind != 3 || f.count != 1 || binary.BigEndian.Uint16(b[f.offset:f.offset+2]) != 0100755 {
		t.Fatal("real RPM fixture lacks its sole approved FILEMODES row")
	}
	binary.BigEndian.PutUint16(b[f.offset:f.offset+2], mode)
	reviewerRPMIntegrity(t, b, true)
	reviewerRPMIntegrity(t, b, false)
	if !bytes.Equal(b[headerEnd:], original[headerEnd:]) {
		t.Fatal("header-only plant changed CPIO payload")
	}
	return b
}

func reviewerDebPlant(t *testing.T, original []byte, plant string) []byte {
	t.Helper()
	if !bytes.HasPrefix(original, []byte("!<arch>\n")) {
		t.Fatal("real deb fixture")
	}
	var out bytes.Buffer
	out.WriteString("!<arch>\n")
	for b := original[8:]; len(b) > 0; {
		if len(b) < 60 {
			t.Fatal("fixture ar header")
		}
		name := strings.TrimSuffix(strings.TrimSpace(string(b[:16])), "/")
		size, e := strconv.Atoi(strings.TrimSpace(string(b[48:58])))
		if e != nil || size < 0 || size+60 > len(b) {
			t.Fatal("fixture ar size")
		}
		contents := b[60 : 60+size]
		if name == "control.tar.gz" && plant != "deb-setuid.deb" || name == "data.tar.gz" && plant == "deb-setuid.deb" {
			g, e := gzip.NewReader(bytes.NewReader(contents))
			if e != nil {
				t.Fatal(e)
			}
			r := tar.NewReader(g)
			var expanded bytes.Buffer
			gw := gzip.NewWriter(&expanded)
			tw := tar.NewWriter(gw)
			changed := false
			for {
				h, e := r.Next()
				if e == io.EOF {
					break
				}
				if e != nil {
					t.Fatal(e)
				}
				data, e := io.ReadAll(r)
				if e != nil {
					t.Fatal(e)
				}
				n := strings.TrimPrefix(h.Name, "./")
				if n == "control" && plant == "wrong-architecture.deb" {
					if !bytes.Contains(data, []byte("Architecture: amd64\n")) {
						t.Fatal("control architecture witness")
					}
					data = bytes.ReplaceAll(data, []byte("Architecture: amd64\n"), []byte("Architecture: arm64\n"))
					h.Size = int64(len(data))
					changed = true
				}
				if n == "usr/bin/a2a" && plant == "deb-setuid.deb" {
					if h.Mode != 0755 {
						t.Fatal("control executable mode")
					}
					h.Mode = 04755
					changed = true
				}
				if e = tw.WriteHeader(h); e != nil {
					t.Fatal(e)
				}
				if _, e = tw.Write(data); e != nil {
					t.Fatal(e)
				}
			}
			if plant == "extra-postinst.deb" {
				data := []byte("#!/bin/sh\nexit 0\n")
				if e = tw.WriteHeader(&tar.Header{Name: "postinst", Typeflag: tar.TypeReg, Mode: 0755, Size: int64(len(data))}); e != nil {
					t.Fatal(e)
				}
				if _, e = tw.Write(data); e != nil {
					t.Fatal(e)
				}
				changed = true
			}
			if !changed {
				t.Fatal("deb plant not applied", plant)
			}
			if e = tw.Close(); e != nil {
				t.Fatal(e)
			}
			if e = gw.Close(); e != nil {
				t.Fatal(e)
			}
			if e = g.Close(); e != nil {
				t.Fatal(e)
			}
			contents = expanded.Bytes()
		}
		fmt.Fprintf(&out, "%-16s%-12d%-6d%-6d%-8o%-10d`\n", name+"/", 0, 0, 0, 0100644, len(contents))
		out.Write(contents)
		if len(contents)%2 != 0 {
			out.WriteByte('\n')
		}
		b = b[60+size+size%2:]
	}
	return out.Bytes()
}

func reviewerPlant(t *testing.T, name string, original []byte) []byte {
	t.Helper()
	switch name {
	case "rpm-header-setuid.rpm":
		return reviewerRPMModePlant(t, original, 0104755)
	case "rpm-header-nonexecutable.rpm":
		return reviewerRPMModePlant(t, original, 0100644)
	case "wrong-architecture.deb", "extra-postinst.deb", "deb-setuid.deb":
		return reviewerDebPlant(t, original, name)
	default:
		t.Fatal("unknown reviewer plant", name)
		return nil
	}
}

func reviewerModeRegression(t *testing.T, plant, target string) {
	t.Helper()
	if e := reviewerPrepare(t, "", ""); e != nil {
		t.Fatal("valid real-package positive", e)
	}
	if e := reviewerPrepare(t, plant, target); e == nil || e.Error() != "package-executable-mode-or-owner" {
		t.Fatal("expected mode/owner refusal before output, got", e)
	}
}

// A header-only setuid change to a valid real RPM must refuse before PrepareLinux exposes success evidence.
func TestRPMHeaderOnlySetuidRealPackage(t *testing.T) {
	reviewerModeRegression(t, "rpm-header-setuid.rpm", "a2a-0.1.2-1.x86_64.rpm")
}

// A header-only non-executable change to a valid real RPM must refuse despite its unchanged executable CPIO mode.
func TestRPMHeaderOnlyNonExecutableRealPackage(t *testing.T) {
	reviewerModeRegression(t, "rpm-header-nonexecutable.rpm", "a2a-0.1.2-1.x86_64.rpm")
}

// A setuid data.tar executable in a valid real deb must refuse before PrepareLinux exposes an output bundle.
func TestDebSetuidTarModeRealPackage(t *testing.T) {
	reviewerModeRegression(t, "deb-setuid.deb", "a2a_0.1.2_amd64.deb")
}
