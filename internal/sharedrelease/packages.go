package sharedrelease

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Package inspection is independent of the builder's artifact metadata and
// needs no package manager on the assemble runner. The accepted formats are
// deliberately narrow: gzip deb/tar and gzip RPM/newc, one regular executable,
// no links, configuration, services or maintainer scripts.
func gunzip(b []byte) ([]byte, error) {
	g, e := gzip.NewReader(bytes.NewReader(b))
	if e != nil {
		return nil, errors.New("package-gzip")
	}
	defer g.Close()
	x, e := io.ReadAll(io.LimitReader(g, 256<<20+1))
	if e != nil || len(x) > 256<<20 {
		return nil, errors.New("package-gzip")
	}
	return x, nil
}

func tarFiles(b []byte) (map[string][]byte, error) {
	r := tar.NewReader(bytes.NewReader(b))
	files := map[string][]byte{}
	for {
		h, e := r.Next()
		if e == io.EOF {
			return files, nil
		}
		if e != nil {
			return nil, errors.New("package-tar")
		}
		n := strings.TrimPrefix(h.Name, "./")
		n = strings.TrimPrefix(n, "/")
		if h.Typeflag == tar.TypeDir && (n == "" || n == "usr/" || n == "usr/bin/" || n == "usr" || n == "usr/bin") {
			continue
		}
		if h.Typeflag != tar.TypeReg || files[n] != nil || h.Size < 0 || h.Size > 128<<20 {
			return nil, errors.New("package-entry-type")
		}
		if n == "usr/bin/a2a" && (h.Mode != 0755 || h.Uid != 0 || h.Gid != 0) {
			return nil, errors.New("package-executable-mode-or-owner")
		}
		x, e := io.ReadAll(r)
		if e != nil {
			return nil, e
		}
		files[n] = x
	}
}

func verifyDeb(b, binaryBytes []byte, version, arch string) error {
	if !bytes.HasPrefix(b, []byte("!<arch>\n")) {
		return errors.New("deb-ar")
	}
	b = b[8:]
	members := map[string][]byte{}
	for len(b) > 0 {
		if len(b) < 60 || string(b[58:60]) != "`\n" {
			return errors.New("deb-ar")
		}
		n := strings.TrimSuffix(strings.TrimSpace(string(b[:16])), "/")
		size, e := strconv.Atoi(strings.TrimSpace(string(b[48:58])))
		if e != nil || size < 0 || size > len(b)-60 || members[n] != nil {
			return errors.New("deb-ar")
		}
		members[n] = b[60 : 60+size]
		next := 60 + size + size%2
		if next > len(b) {
			return errors.New("deb-ar")
		}
		b = b[next:]
	}
	if len(members) != 3 || string(members["debian-binary"]) != "2.0\n" || members["control.tar.gz"] == nil || members["data.tar.gz"] == nil {
		return errors.New("deb-members")
	}
	x, e := gunzip(members["control.tar.gz"])
	if e != nil {
		return e
	}
	controls, e := tarFiles(x)
	if e != nil {
		return e
	}
	for n := range controls {
		if n != "control" && n != "md5sums" {
			return fmt.Errorf("deb-maintainer-or-config-file: %s", n)
		}
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(controls["control"]), "\n") {
		if line == "" || strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			return errors.New("deb-control")
		}
		if _, exists := fields[k]; exists {
			return errors.New("deb-control")
		}
		fields[k] = strings.TrimSpace(v)
	}
	if fields["Package"] != "a2a" || fields["Version"] != version || fields["Architecture"] != arch {
		return errors.New("package-architecture-or-version")
	}
	x, e = gunzip(members["data.tar.gz"])
	if e != nil {
		return e
	}
	files, e := tarFiles(x)
	if e != nil {
		return e
	}
	if len(files) != 1 || !bytes.Equal(files["usr/bin/a2a"], binaryBytes) {
		return errors.New("package-payload-mismatch")
	}
	return nil
}

// rpmHeader bounds all offsets before reading strings; duplicate tags are
// rejected. Only string tags requested by this verifier are interpreted.
func rpmHeader(b []byte) (map[uint32]string, int, error) {
	if len(b) < 16 || !bytes.Equal(b[:4], []byte{0x8e, 0xad, 0xe8, 1}) {
		return nil, 0, errors.New("rpm-header")
	}
	n := uint64(binary.BigEndian.Uint32(b[8:12]))
	size := uint64(binary.BigEndian.Uint32(b[12:16]))
	end := uint64(16) + n*16 + size
	if n > 8192 || end > uint64(len(b)) {
		return nil, 0, errors.New("rpm-header")
	}
	store := b[16+n*16 : end]
	tags := map[uint32]string{}
	for i := uint64(0); i < n; i++ {
		x := b[16+i*16 : 32+i*16]
		tag := binary.BigEndian.Uint32(x[:4])
		typ := binary.BigEndian.Uint32(x[4:8])
		offset := uint64(binary.BigEndian.Uint32(x[8:12]))
		count := uint64(binary.BigEndian.Uint32(x[12:16]))
		if _, ok := tags[tag]; ok || offset > size {
			return nil, 0, errors.New("rpm-header")
		}
		tags[tag] = ""
		if typ == 6 {
			if count != 1 || offset >= size {
				return nil, 0, errors.New("rpm-header")
			}
			tail := store[offset:]
			j := bytes.IndexByte(tail, 0)
			if j < 0 {
				return nil, 0, errors.New("rpm-header")
			}
			tags[tag] = string(tail[:j])
		}
	}
	return tags, int(end), nil
}

func verifyRPM(b, binaryBytes []byte, version, arch string) error {
	if len(b) < 96 || !bytes.Equal(b[:4], []byte{0xed, 0xab, 0xee, 0xdb}) {
		return errors.New("rpm-lead")
	}
	_, sigEnd, e := rpmHeader(b[96:])
	if e != nil {
		return e
	}
	start := 96 + (sigEnd+7)/8*8
	if start > len(b) {
		return errors.New("rpm-header")
	}
	tags, end, e := rpmHeader(b[start:])
	if e != nil {
		return e
	}
	if tags[1000] != "a2a" || tags[1001] != version || tags[1002] != "1" || tags[1022] != arch {
		return errors.New("package-architecture-or-version")
	}
	// All script bodies, interpreters and transaction/file triggers are forbidden,
	// even when an empty value would appear harmless.
	for _, tag := range []uint32{1023, 1024, 1025, 1026, 1065, 1079, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1151, 1152, 1153, 1154, 1155, 1156, 1157, 1158, 5025, 5026, 5027, 5028, 5029, 5030, 5031, 5032, 5033, 5034, 5035, 5036, 5037, 5038, 5039, 5040} {
		if _, ok := tags[tag]; ok {
			return errors.New("rpm-script-or-trigger")
		}
	}
	if tags[1124] != "cpio" || tags[1125] != "gzip" {
		return errors.New("rpm-payload-format")
	}
	x, e := gunzip(b[start+end:])
	if e != nil {
		return e
	}
	files := map[string][]byte{}
	for {
		if len(x) < 110 || string(x[:6]) != "070701" {
			return errors.New("rpm-cpio")
		}
		field := func(i int) (uint64, error) { return strconv.ParseUint(string(x[6+i*8:14+i*8]), 16, 32) }
		mode, e := field(1)
		if e != nil {
			return errors.New("rpm-cpio")
		}
		uid, ue := field(2)
		gid, ge := field(3)
		links, le := field(4)
		if ue != nil || ge != nil || le != nil || uid != 0 || gid != 0 {
			return errors.New("package-owner-or-links")
		}
		size, e := field(6)
		if e != nil {
			return errors.New("rpm-cpio")
		}
		ns, e := field(11)
		if e != nil || ns < 1 || ns > 4096 || 110+ns > uint64(len(x)) {
			return errors.New("rpm-cpio")
		}
		if x[110+ns-1] != 0 {
			return errors.New("rpm-cpio")
		}
		name := strings.TrimPrefix(string(x[110:110+ns-1]), "./")
		name = strings.TrimPrefix(name, "/")
		pos := (110 + ns + 3) / 4 * 4
		if pos+size > uint64(len(x)) {
			return errors.New("rpm-cpio")
		}
		if name == "TRAILER!!!" {
			if size != 0 || len(bytes.Trim(x[pos:], "\x00")) != 0 {
				return errors.New("rpm-cpio-trailing")
			}
			break
		}
		if mode&0170000 == 0040000 && (name == "usr" || name == "usr/bin") { /* allowed directory */
		} else {
			if mode&0170000 != 0100000 || files[name] != nil {
				return errors.New("package-entry-type")
			}
			if mode != 0100755 {
				return errors.New("package-executable-mode-or-owner")
			}
			if links != 1 {
				return errors.New("package-owner-or-links")
			}
			files[name] = x[pos : pos+size]
		}
		next := pos + (size+3)/4*4
		if next > uint64(len(x)) {
			return errors.New("rpm-cpio")
		}
		x = x[next:]
	}
	if len(files) != 1 || !bytes.Equal(files["usr/bin/a2a"], binaryBytes) {
		return errors.New("package-payload-mismatch")
	}
	return nil
}
