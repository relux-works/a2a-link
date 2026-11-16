package cli

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// Public r4 encoding vectors (public-encoding-vectors-r0.json in the frozen r4
// pack): literal preimages and names produced independently of this package.
var vaultSyntheticVectors = []struct {
	host, project, profile, encodedHex, name string
}{
	{"host-fixture-01", "project-fixture-01", "profile-fixture-01", "737761726d612e73796e7468657469632d6964656e746974792f7631000000000f686f73742d666978747572652d30310000001270726f6a6563742d666978747572652d30310000001270726f66696c652d666978747572652d3031", "syn1:09155b1290b5e9bc09a1a929ad8d9fffcb21002e553fdf849acda156d6b74bb7"},
	{"host-fixture-01", "project-fixture-02", "profile-fixture-01", "737761726d612e73796e7468657469632d6964656e746974792f7631000000000f686f73742d666978747572652d30310000001270726f6a6563742d666978747572652d30320000001270726f66696c652d666978747572652d3031", "syn1:f86be17907524fc610dbfd970f2d0fe3098bf5ffa5de7fe2dd2b8f38c5e87623"},
	{"h", "p/x", "r", "737761726d612e73796e7468657469632d6964656e746974792f763100000000016800000003702f780000000172", "syn1:0e477d8a3b4be99c40436158a8c3f3b9103178eb00d78b4f45dcb010a4fa6dfe"},
	{"h/p", "x", "r", "737761726d612e73796e7468657469632d6964656e746974792f76310000000003682f7000000001780000000172", "syn1:c6ea87c0ec1fbe79dd55271a9ead7121dbb4466092b1fa9465f83aa3da0e9095"},
}

func vaultTestCode(t *testing.T, err error) vaultCode {
	t.Helper()
	var r *vaultFailure
	if !errors.As(err, &r) {
		t.Fatalf("not a vault vaultFailure: %T", err)
	}
	if r.Outcome != vaultNotSubmitted {
		t.Fatalf("local validation produced vaultOutcome %s", r.Outcome)
	}
	return r.Code
}

// Claim: the synthetic derivation reproduces all four agreed public vectors
// byte for byte (preimage and name), and the delimiter-shift pair (h,p/x,r)
// versus (h/p,x,r) yields distinct names.
func TestSyntheticNamePublicVectors(t *testing.T) {
	for _, v := range vaultSyntheticVectors {
		o := vaultSyntheticContext{v.host, v.project, v.profile}
		if got := hex.EncodeToString(vaultSyntheticPreimage(o)); got != v.encodedHex {
			t.Fatalf("preimage mismatch for %q", v.host)
		}
		name, err := vaultSyntheticName(o)
		if err != nil || name != v.name || len(name) != 69 {
			t.Fatalf("name mismatch for %q: %v", v.host, err)
		}
		if err := vaultValidateIdentity(vaultIdentity{Domain: "fixture-domain", Kind: vaultKindSynthetic, Name: v.name, Origin: &o}); err != nil {
			t.Fatalf("valid synthetic identity vaultRefused: %v", err)
		}
	}
	if vaultSyntheticVectors[2].name == vaultSyntheticVectors[3].name {
		t.Fatal("length prefix did not separate shifted delimiters")
	}
}

// Claim: IdentityV2 validation accepts the source-valid explicit and synthetic
// neighbours unchanged and refuses each one-variable change with the r4 code
// and precedence (shape, limits, representation, context, recomputation).
// Limit: explicit names are additionally restricted to the a2a selector
// grammar, so a common-envelope Unicode name is refused here by design.
func TestIdentityValidation(t *testing.T) {
	v := vaultSyntheticVectors[0]
	origin := vaultSyntheticContext{v.host, v.project, v.profile}
	syn := func(mut func(*vaultIdentity)) vaultIdentity {
		o := origin
		id := vaultIdentity{Domain: "fixture-domain", Kind: vaultKindSynthetic, Name: v.name, Origin: &o}
		if mut != nil {
			mut(&id)
		}
		return id
	}
	exp := func(name string) vaultIdentity {
		return vaultIdentity{Domain: "fixture-domain", Kind: vaultKindExplicit, Name: name}
	}
	for _, tc := range []struct {
		label string
		id    vaultIdentity
	}{
		{"explicit fixture_alpha", exp("fixture_alpha")},
		{"explicit 64-byte selector", exp("a" + strings.Repeat("b", 63))},
		{"explicit dotted", exp("fixture_agent.v2=x-y")},
		{"128-byte domain", vaultIdentity{Domain: "d" + strings.Repeat("e", 127), Kind: vaultKindExplicit, Name: "fixture_alpha"}},
		{"synthetic vector", syn(nil)},
		{"256-byte origin id", func() vaultIdentity {
			o := vaultSyntheticContext{strings.Repeat("h", 256), "P Ü", "r"}
			n, err := vaultSyntheticName(o)
			if err != nil {
				t.Fatal(err)
			}
			return vaultIdentity{Domain: "fixture-domain", Kind: vaultKindSynthetic, Name: n, Origin: &o}
		}()},
	} {
		if err := vaultValidateIdentity(tc.id); err != nil {
			t.Fatalf("%s vaultRefused: %v", tc.label, err)
		}
	}
	for _, tc := range []struct {
		label string
		id    vaultIdentity
		want  vaultCode
	}{
		{"vaultUnknown kind", vaultIdentity{Domain: "fixture-domain", Kind: "Explicit", Name: "fixture_alpha"}, vaultEFormat},
		{"explicit with origin", vaultIdentity{Domain: "fixture-domain", Kind: vaultKindExplicit, Name: "fixture_alpha", Origin: &origin}, vaultEFormat},
		{"explicit 513 bytes", exp(strings.Repeat("a", 513)), vaultELimit},
		{"explicit 513 bytes beats invalid domain", vaultIdentity{Domain: "", Kind: vaultKindExplicit, Name: strings.Repeat("A", 513)}, vaultELimit},
		{"explicit empty", exp(""), vaultEIdentity},
		{"explicit 65-byte selector", exp(strings.Repeat("a", 65)), vaultEIdentity},
		{"explicit uppercase", exp("Fixture_alpha"), vaultEIdentity},
		{"explicit control", exp("fixture\u0085alpha"), vaultEIdentity},
		{"explicit space", exp("fixture alpha"), vaultEIdentity},
		{"explicit full MXID", exp("@fixture_alpha:example.invalid"), vaultEIdentity},
		{"synthetic uppercase hex", syn(func(id *vaultIdentity) { id.Name = "syn1:" + strings.ToUpper(id.Name[5:]) }), vaultEIdentity},
		{"synthetic wrong prefix", syn(func(id *vaultIdentity) { id.Name = "syn2:" + id.Name[5:] }), vaultEIdentity},
		{"synthetic short", syn(func(id *vaultIdentity) { id.Name = id.Name[:68] }), vaultEIdentity},
		{"explicit name as synthetic", syn(func(id *vaultIdentity) { id.Name = "fixture_alpha" }), vaultEIdentity},
		{"synthetic name as explicit", exp(v.name), vaultEIdentity},
		{"empty domain", syn(func(id *vaultIdentity) { id.Domain = "" }), vaultEContext},
		{"uppercase domain", syn(func(id *vaultIdentity) { id.Domain = "Fixture-domain" }), vaultEContext},
		{"129-byte domain", syn(func(id *vaultIdentity) { id.Domain = "d" + strings.Repeat("e", 128) }), vaultEContext},
		{"hostname-like domain with colon", syn(func(id *vaultIdentity) { id.Domain = "example.invalid:443" }), vaultEContext},
		{"synthetic missing origin", syn(func(id *vaultIdentity) { id.Origin = nil }), vaultEContext},
		{"empty origin id", syn(func(id *vaultIdentity) { id.Origin.HostID = "" }), vaultEContext},
		{"control origin id", syn(func(id *vaultIdentity) { id.Origin.ProfileID = "p\tq" }), vaultEContext},
		{"invalid UTF-8 origin id", syn(func(id *vaultIdentity) { id.Origin.ProjectID = "\xff" }), vaultEContext},
		{"257-byte origin id", syn(func(id *vaultIdentity) { id.Origin.HostID = strings.Repeat("h", 257) }), vaultELimit},
		{"origin does not recompute name", syn(func(id *vaultIdentity) { id.Origin.ProjectID = "project-fixture-02" }), vaultEIdentityConflict},
	} {
		if got := vaultTestCode(t, vaultValidateIdentity(tc.id)); got != tc.want {
			t.Fatalf("%s: got %s want %s", tc.label, got, tc.want)
		}
	}
}
