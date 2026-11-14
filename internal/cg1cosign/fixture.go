package cg1cosign

import (
	"encoding/hex"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// FixtureSign uses only deliberately public test scalars. It accepts no custody input.
// These identities cannot be used for enforcing mode or real grants.
func FixtureSign(envelope []byte, fixture string) (map[string]any, error) {
	var scalar [32]byte
	switch fixture {
	case "alice":
		scalar[31] = 1
	case "bob":
		scalar[31] = 2
	default:
		return nil, ErrInvalid
	}
	digest, e := Digest(envelope)
	if e != nil {
		return nil, e
	}
	key, pub := btcec.PrivKeyFromBytes(scalar[:])
	defer key.Zero()
	sig, e := schnorr.Sign(key, digest[:], schnorr.CustomNonce([32]byte{}))
	if e != nil {
		return nil, ErrInvalid
	}
	return map[string]any{"version": Version, "key": "bip340:" + hex.EncodeToString(schnorr.SerializePubKey(pub)), "sig": hex.EncodeToString(sig.Serialize())}, nil
}
