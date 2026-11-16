package originproducer

import (
	"context"
	"strings"
	"testing"

	"github.com/relux-works/a2a-swarm/internal/cg1"
	"github.com/relux-works/a2a-swarm/runorigin"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
)

// Claim: only exact pay and trust names open; every unknown name refuses before checker construction.
func TestClosedTermsProfiles(t *testing.T) {
	for _, name := range []string{"pay", "trust"} {
		if p, ok := profileByName(name); !ok || p == nil || p.name() != name {
			t.Fatal("valid control: profile missing")
		}
	}
	for _, name := range []string{"TRUST", "PAY", "pay ", "", "none"} {
		if p, ok := profileByName(name); ok || p != nil {
			t.Fatalf("profile %q is implemented", name)
		}
	}
	f := newFixture(t)
	control, _ := f.session()
	control.Close()
	for _, tc := range []struct {
		name   string
		reason Reason
	}{
		{"unknown", ReasonProfile}, {"PAY", ReasonMappingInvalid},
		{"TRUST", ReasonMappingInvalid}, {"", ReasonMappingInvalid}, {"trust ", ReasonMappingInvalid},
	} {
		f.mapping.Agents[0].TermsProfile = tc.name
		f.saveMapping()
		s, err := f.producer.Open(context.Background(), f.selection)
		f.notOpened(s, err, tc.reason, 1)
	}
}

// Claim: a trust mapping passes its exact profile to the owned checker; a grant refusal yields no Result beside a valid checker control.
func TestTrustMappingAndRefusal(t *testing.T) {
	f := newFixture(t)
	f.mapping.Agents[0].TermsProfile = "trust"
	f.saveMapping()
	s, checker := f.session()
	defer s.Close()
	if checker.scope.Profile != "trust" {
		t.Fatal("protected trust mapping was not passed to the factory")
	}
	if result, err := s.Prepare(context.Background()); err != nil || result == (runorigin.Result{}) {
		t.Fatal("valid checker control", err)
	}
	checker.set(func(c *fakeChecker) { c.code = cg1.OriginGrantRefused })
	result, err := s.Validate(context.Background())
	if result != (runorigin.Result{}) || err == nil {
		t.Fatal("grant refusal produced a Result")
	}
	refusal, ok := err.(*Refusal)
	if !ok || refusal.Reason != ReasonGrantRefused {
		t.Fatal("wrong typed grant refusal")
	}
}

// Claim: the trust object seam rejects missing, oversized or incorrectly addressed bytes; contract validity remains CG1's mandatory subsequent check.
func TestTrustProfileObjects(t *testing.T) {
	profile := trustProfile{}
	raw := []byte(`{"profile":"swarma-trust-contract/1"}`)
	control := map[string][]byte{rental.Hash(raw): raw}
	for _, terms := range []map[string][]byte{nil, {}, {"wrong": raw}, {rental.Hash(nil): nil}, {"oversized": make([]byte, 16385)}} {
		if err := profile.admit(control); err != nil {
			t.Fatal("valid addressed object", err)
		}
		if err := profile.admit(terms); err != errTerms {
			t.Fatal("want terms code", err)
		}
	}
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
