package sharedrelease

import "testing"

// Header-only mode and ownership changes must refuse despite an unchanged 0755 CPIO executable.
func TestRPMHeaderInstallModeBinding(t *testing.T) {
	bin := []byte("reference binary")
	if e := verifyRPM(rpmFixture(t, "x86_64", bin, false), bin, "0.1.2", "x86_64"); e != nil {
		t.Fatal("valid header/payload positive", e)
	}
	for name, fields := range map[string]map[uint32]string{
		"header-only-setuid":        {1030: "0104755"},
		"header-only-nonexecutable": {1030: "0100644"},
		"header-only-setgid":        {1030: "0102755"},
		"header-only-sticky":        {1030: "0101755"},
		"header-user":               {1039: "other"},
		"header-group":              {1040: "other"},
	} {
		t.Run(name, func(t *testing.T) {
			if e := verifyRPM(rpmFixture(t, "x86_64", bin, false, fields), bin, "0.1.2", "x86_64"); e == nil || e.Error() != "package-executable-mode-or-owner" {
				t.Fatal("unsafe install header admitted", e)
			}
		})
	}
}

// FILEMODES and ownership rows must have the expected RPM types and single-file cardinality, including on truncated input.
func TestRPMHeaderFileMetadataShape(t *testing.T) {
	b := rpmFixture(t, "x86_64", []byte("binary"), false)
	_, end, e := rpmHeader(b[96:])
	if e != nil {
		t.Fatal(e)
	}
	tags, _, e := rpmHeader(b[96+(end+7)/8*8:])
	if e != nil {
		t.Fatal(e)
	}
	if _, e = rpmInstallFile(tags); e != nil {
		t.Fatal("valid typed metadata", e)
	}
	for name, value := range map[string]rpmValue{
		"missing": {}, "wrong-type": {kind: 4, count: 1, data: []byte{0, 0, 0x81, 0xed}}, "extra-mode": {kind: 3, count: 2, data: []byte{0x81, 0xed, 0x81, 0xed}}, "truncated": {kind: 3, count: 1, data: []byte{0x81}},
	} {
		t.Run(name, func(t *testing.T) {
			original := tags[1030]
			tags[1030] = value
			defer func() { tags[1030] = original }()
			if _, e := rpmInstallFile(tags); e == nil || e.Error() != "package-executable-mode-or-owner" {
				t.Fatal("invalid mode row admitted", e)
			}
		})
	}
}

// A safe mode cannot authorize a header that names a different installation path or file-table cardinality.
func TestRPMHeaderFileAssociation(t *testing.T) {
	bin := []byte("reference binary")
	for name, fields := range map[string]map[uint32]string{
		"different-basename": {1117: "other"}, "different-directory": {1118: "/etc/"}, "different-directory-index": {1116: "1"}, "legacy-table": {1027: "/etc/other"},
	} {
		t.Run(name, func(t *testing.T) {
			if e := verifyRPM(rpmFixture(t, "x86_64", bin, false, fields), bin, "0.1.2", "x86_64"); e == nil || e.Error() != "package-header-file-binding" {
				t.Fatal("unbound header path admitted", e)
			}
		})
	}
}
