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
			if !approvedTarOwner(h) || h.Mode != 0755 {
				return nil, errors.New("package-executable-mode-or-owner")
			}
			continue
		}
		if h.Typeflag != tar.TypeReg || files[n] != nil || h.Size < 0 || h.Size > 128<<20 {
			return nil, errors.New("package-entry-type")
		}
		if n == "usr/bin/a2a" && (h.Mode != 0755 || !approvedTarOwner(h)) {
			return nil, errors.New("package-executable-mode-or-owner")
		}
		x, e := io.ReadAll(r)
		if e != nil {
			return nil, e
		}
		files[n] = x
	}
}

func approvedTarOwner(h *tar.Header) bool {
	return h.Uid == 0 && h.Gid == 0 && (h.Uname == "" || h.Uname == "root") && (h.Gname == "" || h.Gname == "root")
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

type rpmValue struct {
	kind, count uint32
	data        []byte
	scalar      string
}

// rpmHeader retains typed array metadata as well as scalars; duplicate tags
// and out-of-store reads are refused before installation metadata is consumed.
func rpmHeader(b []byte) (map[uint32]rpmValue, int, error) {
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
	tags := map[uint32]rpmValue{}
	for i := uint64(0); i < n; i++ {
		x := b[16+i*16 : 32+i*16]
		tag := binary.BigEndian.Uint32(x[:4])
		typ := binary.BigEndian.Uint32(x[4:8])
		offset := uint64(binary.BigEndian.Uint32(x[8:12]))
		count := uint64(binary.BigEndian.Uint32(x[12:16]))
		if _, ok := tags[tag]; ok || offset > size {
			return nil, 0, errors.New("rpm-header")
		}
		value := rpmValue{kind: typ, count: uint32(count), data: store[offset:]}
		if typ == 6 {
			if count != 1 || offset >= size {
				return nil, 0, errors.New("rpm-header")
			}
			tail := store[offset:]
			j := bytes.IndexByte(tail, 0)
			if j < 0 {
				return nil, 0, errors.New("rpm-header")
			}
			value.scalar = string(tail[:j])
		}
		if typ == 4 && count == 1 {
			if offset+4 > size {
				return nil, 0, errors.New("rpm-header")
			}
			value.scalar = strconv.FormatUint(uint64(binary.BigEndian.Uint32(store[offset:offset+4])), 10)
		}
		tags[tag] = value
	}
	return tags, int(end), nil
}

func rpmSingleString(v rpmValue) (string, bool) {
	if v.kind != 8 || v.count != 1 {
		return "", false
	}
	i := bytes.IndexByte(v.data, 0)
	if i < 0 {
		return "", false
	}
	return string(v.data[:i]), true
}

// RPM installs FILEMODES/FILEUSERNAME/FILEGROUPNAME, not CPIO permissions.
// Bind the single authoritative file row to the approved executable path.
func rpmInstallFile(tags map[uint32]rpmValue) (uint64, error) {
	mode := tags[1030]
	if mode.kind != 3 || mode.count != 1 || len(mode.data) < 2 || binary.BigEndian.Uint16(mode.data[:2]) != 0100755 {
		return 0, errors.New("package-executable-mode-or-owner")
	}
	for _, tag := range []uint32{1039, 1040} {
		if name, ok := rpmSingleString(tags[tag]); !ok || name != "root" {
			return 0, errors.New("package-executable-mode-or-owner")
		}
	}
	for _, tag := range []uint32{1031, 1032} {
		if v, ok := tags[tag]; ok && (v.kind != 4 || v.count != 1 || len(v.data) < 4 || binary.BigEndian.Uint32(v.data[:4]) != 0) {
			return 0, errors.New("package-executable-mode-or-owner")
		}
	}
	base, bok := rpmSingleString(tags[1117])
	dir, dok := rpmSingleString(tags[1118])
	index := tags[1116]
	if !bok || !dok || base != "a2a" || dir != "/usr/bin/" || index.kind != 4 || index.count != 1 || len(index.data) < 4 || binary.BigEndian.Uint32(index.data[:4]) != 0 {
		return 0, errors.New("package-header-file-binding")
	}
	// Alternative legacy/relocation tables cannot disagree with the accepted row.
	for _, tag := range []uint32{1027, 1119, 1120, 1121} {
		if _, ok := tags[tag]; ok {
			return 0, errors.New("package-header-file-binding")
		}
	}
	return uint64(binary.BigEndian.Uint16(mode.data[:2])), nil
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
	if tags[1000].scalar != "a2a" || tags[1001].scalar != version || tags[1002].scalar != "1" || tags[1022].scalar != arch {
		return errors.New("package-architecture-or-version")
	}
	if epoch, exists := tags[1003]; exists && epoch.scalar != "0" {
		return errors.New("package-architecture-or-version")
	}
	// All script bodies, interpreters and transaction/file triggers are forbidden,
	// even when an empty value would appear harmless.
	// RPMTAG_* from rpm-software-management/rpm include/rpm/rpmtag.h:
	// script bodies/interpreters/flags and ordinary/file/transaction triggers.
	// BUILDARCHS (1089), for example, is metadata rather than a script.
	for _, tag := range []uint32{
		1023, 1024, 1025, 1026, 1065, 1066, 1067, 1068, 1069, 1079, 1085, 1086, 1087, 1088, 1091, 1092,
		1100, 1101, 1102, 1151, 1152, 1153, 1154, 1171, 1174, 1175, 5005, 5006,
		5020, 5021, 5022, 5023, 5024, 5025, 5026, 5027,
		5063, 5064, 5065, 5066, 5067, 5068, 5069, 5070, 5071, 5072, 5073, 5074, 5075, 5076, 5077, 5078, 5079, 5080, 5081, 5082,
		5084, 5085, 5086, 5087, 5088, 5089, 5103, 5104, 5105, 5106, 5107, 5108,
	} {
		if _, ok := tags[tag]; ok {
			return errors.New("rpm-script-or-trigger")
		}
	}
	if tags[1124].scalar != "cpio" || tags[1125].scalar != "gzip" {
		return errors.New("rpm-payload-format")
	}
	installMode, e := rpmInstallFile(tags)
	if e != nil {
		return e
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
			if mode != 0040755 {
				return errors.New("package-executable-mode-or-owner")
			}
		} else {
			if mode&0170000 != 0100000 || files[name] != nil {
				return errors.New("package-entry-type")
			}
			if mode != installMode {
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
