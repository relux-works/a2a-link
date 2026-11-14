// Package cg1cosign verifies the fork-only Track A signature on exact envelope bytes.
package cg1cosign

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/a2a-swarm/internal/matrix"
)

const ContentKey = "works.relux.cg1.cosignature"
const Version = "a2a-link-cg1-cosignature/1"
const Domain = "a2a-link cg1 cosignature/1"

var ErrInvalid = errors.New("cg1: invalid co-signature")

// Verifier is the only Track A seam; a future author-profile verifier can replace it.
type Verifier interface {
	Verify(envelope []byte, content any) (string, error)
}
type BIP340 struct{}

// Digest signs exact wire bytes, not their canonical form or the envelope content id.
func Digest(envelope []byte) ([32]byte, error) {
	if len(envelope) == 0 || len(envelope) > matrix.EnvelopeMaxBytes {
		return [32]byte{}, ErrInvalid
	}
	tag := sha256.Sum256([]byte(Domain))
	h := sha256.New()
	h.Write(tag[:])
	h.Write(tag[:])
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(envelope)))
	h.Write(size[:])
	h.Write(envelope)
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}
func decodeHex(s string, n int) ([]byte, error) {
	if len(s) != n*2 || strings.ToLower(s) != s {
		return nil, ErrInvalid
	}
	b, e := hex.DecodeString(s)
	if e != nil {
		return nil, ErrInvalid
	}
	return b, nil
}

func (BIP340) Verify(envelope []byte, content any) (string, error) {
	obj, ok := content.(map[string]any)
	if !ok || len(obj) != 3 || obj["version"] != Version {
		return "", ErrInvalid
	}
	key, ok := obj["key"].(string)
	if !ok || !strings.HasPrefix(key, "bip340:") {
		return "", ErrInvalid
	}
	key = strings.TrimPrefix(key, "bip340:")
	pub, e := decodeHex(key, 32)
	if e != nil {
		return "", ErrInvalid
	}
	pk, e := schnorr.ParsePubKey(pub)
	if e != nil {
		return "", ErrInvalid
	}
	text, ok := obj["sig"].(string)
	if !ok {
		return "", ErrInvalid
	}
	raw, e := decodeHex(text, 64)
	if e != nil {
		return "", ErrInvalid
	}
	sig, e := canonicalSignature(raw)
	if e != nil {
		return "", ErrInvalid
	}
	digest, e := Digest(envelope)
	if e != nil {
		return "", ErrInvalid
	}
	if !sig.Verify(digest[:], pk) {
		return "", ErrInvalid
	}
	return key, nil
}

// btcec normalizes s while parsing; the wire profile forbids that normalization.
func canonicalSignature(raw []byte) (*schnorr.Signature, error) {
	sig, err := schnorr.ParseSignature(raw)
	if err != nil || !bytes.Equal(sig.Serialize(), raw) {
		return nil, ErrInvalid
	}
	return sig, nil
}
