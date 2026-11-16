package originproducer

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
)

var errTerms = errors.New("origin producer: terms")

// termsProfile is the one seam through which a contract profile is read. A
// profile receives the protected contract terms by their hash and says whether
// every one of them is a well-formed contract of that profile.
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

// profileByName is closed. A profile that is not implemented here refuses.
func profileByName(name string) (termsProfile, bool) {
	if name == (payProfile{}).name() {
		return payProfile{}, true
	}
	return nil, false
}
