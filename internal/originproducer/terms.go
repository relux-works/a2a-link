package originproducer

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/relux-works/swarma-chain-lab/experiments/grantcheck"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
)

var errTerms = errors.New("origin producer: terms")

// termsProfile is the one seam through which a contract profile is read. A
// profile receives the protected contract terms by their hash and says whether
// the protected objects can be supplied to that profile. Trust's document
// rules and grant bindings are judged by the subsequent CG1 check, never here.
type termsProfile interface {
	name() string
	admit(terms map[string][]byte) error
}

// payProfile is the existing pay contract profile. It repeats the validator of
// the protected cg1 policy exactly: canonical terms-v2 bytes under their own
// hash. It is not relaxed for any other contract kind.
type payProfile struct{}

func (payProfile) name() string { return "pay" }

func (payProfile) admit(terms map[string][]byte) error {
	if len(terms) == 0 {
		return errTerms
	}
	for hash, raw := range terms {
		if len(raw) == 0 || rental.Hash(raw) != hash {
			return errTerms
		}
		var pay rental.PayTermsV2
		if json.Unmarshal(raw, &pay) != nil {
			return errTerms
		}
		canonical, err := rental.EncodePayTermsV2(pay)
		if err != nil || !bytes.Equal(canonical, raw) {
			return errTerms
		}
	}
	return nil
}

// trustProfile deliberately does not duplicate CG1's internal trust parser.
// This seam checks only bounded hash-addressed objects; a Result still requires
// CG1 to judge the contract and every binding against the presented Grant v3.
type trustProfile struct{}

func (trustProfile) name() string { return grantcheck.ContractProfileTrust }

func (trustProfile) admit(terms map[string][]byte) error {
	if len(terms) == 0 || len(terms) > 64 {
		return errTerms
	}
	for hash, raw := range terms {
		if len(raw) == 0 || len(raw) > grantcheck.MaxPresentationBytes || rental.Hash(raw) != hash {
			return errTerms
		}
	}
	return nil
}

// profileByName is closed. A profile that is not implemented here refuses.
func profileByName(name string) (termsProfile, bool) {
	switch name {
	case grantcheck.ContractProfilePay:
		return payProfile{}, true
	case grantcheck.ContractProfileTrust:
		return trustProfile{}, true
	default:
		return nil, false
	}
}
