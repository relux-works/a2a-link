package originproducer

import (
	"context"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
)

// Claim: the profile seam is closed. Only the pay profile exists; a mapping
// that names any other profile, including the future trust profile, refuses
// before a checker is built. The pay mapping opens beside it.
func TestOnlyPayProfileIsImplemented(t *testing.T) {
	if p, ok := profileByName("pay"); !ok || p == nil || p.name() != "pay" {
		t.Fatal("valid control: pay profile missing")
	}
	for _, name := range []string{"trust", "PAY", "pay ", "", "none"} {
		if p, ok := profileByName(name); ok || p != nil {
			t.Fatalf("profile %q is implemented", name)
		}
	}
	f := newFixture(t)
	control, _ := f.session()
	control.Close()
	f.mapping.Agents[0].TermsProfile = "trust"
	f.saveMapping()
	s, err := f.producer.Open(context.Background(), f.selection)
	f.notOpened(s, err, ReasonProfile, 1)
}

// Claim: the pay profile keeps the existing pay validator at full strength:
// canonical terms-v2 bytes under their own hash pass; a wrong hash,
// non-canonical bytes, a document of another contract kind, empty bytes and an
// empty set are refused.
func TestPayProfileValidator(t *testing.T) {
	raw := payTerms(t)
	hash := rental.Hash(raw)
	profile := payProfile{}
	if err := profile.admit(map[string][]byte{hash: raw}); err != nil {
		t.Fatal("valid control: canonical pay terms refused", err)
	}
	other := []byte(`{"actions":["instruct","review"],"version":1}`)
	cases := map[string]map[string][]byte{
		"empty-set":          {},
		"wrong-hash":         {strings.Repeat("0", 64): raw},
		"non-canonical":      {rental.Hash(append([]byte(" "), raw...)): append([]byte(" "), raw...)},
		"other-contract":     {rental.Hash(other): other},
		"empty-bytes":        {rental.Hash(nil): nil},
		"valid-plus-invalid": {hash: raw, rental.Hash(other): other},
	}
	for name, terms := range cases {
		t.Run(name, func(t *testing.T) {
			if err := profile.admit(terms); err == nil {
				t.Fatal("the pay validator accepted invalid terms")
			}
		})
	}
}
