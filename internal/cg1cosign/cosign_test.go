package cg1cosign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"math/big"
	"strings"
	"testing"
)

// Proves the published digest construction independently of the signer and refuses byte/length/domain changes.
func TestCoSignatureExactBytes(t *testing.T) {
	raw := []byte("{\"fixture\":true}\n")
	tag := sha256.Sum256([]byte("a2a-link cg1 cosignature/1"))
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(raw)))
	pre := append(append(append(append([]byte{}, tag[:]...), tag[:]...), size[:]...), raw...)
	expected := sha256.Sum256(pre)
	got, e := Digest(raw)
	if e != nil || got != expected {
		t.Fatal("domain/length/exact-byte digest changed")
	}
	co, e := FixtureSign(raw, "alice")
	if e != nil {
		t.Fatal(e)
	}
	if key, e := (BIP340{}).Verify(raw, co); e != nil || key != "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" {
		t.Fatal("valid fixture co-signature", key, e)
	}
	for _, changed := range [][]byte{bytes.TrimSpace(raw), append(append([]byte{}, raw...), ' '), []byte("{ \"fixture\":true}\n")} {
		if _, e := (BIP340{}).Verify(changed, co); e != ErrInvalid {
			t.Fatal("co-signature accepted different exact bytes")
		}
	}
	for _, bad := range [][]byte{nil, make([]byte, 65537)} {
		if _, e := Digest(bad); e != ErrInvalid {
			t.Fatal("digest bounds bypass")
		}
	}
}

// Proves strict key/curve/signature encodings and signature math beside a valid control; no alternate algorithm spelling is inferred.
func TestCoSignatureCryptoRefusals(t *testing.T) {
	raw := []byte(`{"fixture":true}`)
	for _, name := range []string{"missing", "unknown-field", "wrong-version", "matrix-id", "ed25519-id", "compressed-even", "compressed-odd", "wrong-curve", "noncanonical-s", "ed25519-signature", "bad-signature", "uppercase-key", "uppercase-signature"} {
		t.Run(name, func(t *testing.T) {
			good, e := FixtureSign(raw, "bob")
			if e != nil {
				t.Fatal(e)
			}
			bad := map[string]any{}
			for k, v := range good {
				bad[k] = v
			}
			switch name {
			case "missing":
				bad = nil
			case "unknown-field":
				bad["extra"] = true
			case "wrong-version":
				bad["version"] = "swarm-envelope/2"
			case "matrix-id":
				bad["key"] = "@bob:fixture.invalid"
			case "ed25519-id":
				ed := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
				bad["key"] = "ed25519:" + base64.RawURLEncoding.EncodeToString(ed.Public().(ed25519.PublicKey))
			case "compressed-even":
				bad["key"] = "bip340:02" + strings.TrimPrefix(good["key"].(string), "bip340:")
			case "compressed-odd":
				bad["key"] = "bip340:03" + strings.TrimPrefix(good["key"].(string), "bip340:")
			case "wrong-curve":
				bad["key"] = "bip340:" + strings.Repeat("f", 64)
			case "noncanonical-s":
				bad["sig"] = good["sig"].(string)[:64] + "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
			case "ed25519-signature":
				digest, _ := Digest(raw)
				key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
				bad["sig"] = hex.EncodeToString(ed25519.Sign(key, digest[:]))
			case "bad-signature":
				bad["sig"] = strings.Repeat("0", 128)
			case "uppercase-key":
				bad["key"] = "bip340:" + strings.ToUpper(strings.TrimPrefix(good["key"].(string), "bip340:"))
			case "uppercase-signature":
				bad["sig"] = strings.ToUpper(good["sig"].(string))
			}
			if _, e := (BIP340{}).Verify(raw, bad); e != ErrInvalid {
				t.Fatal("invalid co-signature accepted")
			}
			if _, e := (BIP340{}).Verify(raw, good); e != nil {
				t.Fatal("valid co-signature refused", e)
			}
		})
	}
}

// Proves fixture signing refuses arbitrary identity/key input instead of accepting ambient custody.
func TestFixtureSignerClosed(t *testing.T) {
	for _, name := range []string{"", "real", "@alice:fixture.invalid", strings.Repeat("1", 64)} {
		if _, e := FixtureSign([]byte("{}"), name); e != ErrInvalid {
			t.Fatal("nonfixture identity accepted")
		}
	}
	if _, e := FixtureSign([]byte("{}"), "alice"); e != nil {
		t.Fatal(e)
	}
}

// Proves a mathematically constructed odd-y R is refused under this exact co-signature digest, beside a standard even-y BIP-340 control.
func TestCoSignatureOddY(t *testing.T) {
	raw := []byte("{\"odd_y_control\":true}")
	good, e := FixtureSign(raw, "alice")
	if e != nil {
		t.Fatal(e)
	}
	pubBytes, _ := hex.DecodeString(strings.TrimPrefix(good["key"].(string), "bip340:"))
	digest, _ := Digest(raw)
	// Deliberately omit BIP-340's even-y nonce normalization for a public fixture scalar.
	var nonce int64
	var rx []byte
	for n := int64(1); n < 100; n++ {
		var scalar [32]byte
		scalar[31] = byte(n)
		k, p := btcec.PrivKeyFromBytes(scalar[:])
		k.Zero()
		if p.SerializeCompressed()[0] == 3 {
			nonce = n
			rx = schnorr.SerializePubKey(p)
			break
		}
	}
	if nonce == 0 {
		t.Fatal("no odd-y nonce fixture")
	}
	tag := sha256.Sum256([]byte("BIP0340/challenge"))
	pre := append(append(append(append(append([]byte{}, tag[:]...), tag[:]...), rx...), pubBytes...), digest[:]...)
	h := sha256.Sum256(pre)
	s := new(big.Int).SetBytes(h[:])
	s.Add(s, big.NewInt(nonce))
	s.Mod(s, btcec.S256().Params().N)
	bad := map[string]any{"version": Version, "key": good["key"], "sig": hex.EncodeToString(append(append([]byte{}, rx...), s.FillBytes(make([]byte, 32))...))}
	sigBytes, _ := hex.DecodeString(bad["sig"].(string))
	if _, e := schnorr.ParseSignature(sigBytes); e != nil {
		t.Fatal("odd-y witness failed encoding setup", e)
	}
	if _, e := (BIP340{}).Verify(raw, bad); e != ErrInvalid {
		t.Fatal("odd-y R accepted")
	}
	if _, e := (BIP340{}).Verify(raw, good); e != nil {
		t.Fatal("even-y positive refused", e)
	}
}

// Proves wire scalar normalization itself is forbidden before signature math; s=n must not silently parse as s=0.
func TestCoSignatureCanonicalScalar(t *testing.T) {
	co, e := FixtureSign([]byte("{}"), "alice")
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := hex.DecodeString(co["sig"].(string))
	sig, e := canonicalSignature(raw)
	if e != nil || !bytes.Equal(sig.Serialize(), raw) {
		t.Fatal("canonical scalar control refused", e)
	}
	order, _ := hex.DecodeString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
	bad := append([]byte{}, raw...)
	copy(bad[32:], order)
	normalized, e := schnorr.ParseSignature(bad)
	if e != nil || bytes.Equal(normalized.Serialize(), bad) {
		t.Fatal("scalar-normalization witness setup failed")
	}
	if _, e := canonicalSignature(bad); e != ErrInvalid {
		t.Fatal("noncanonical scalar normalized")
	}
	if !bytes.Equal(bad[32:], order) {
		t.Fatal("scalar refusal changed input bytes")
	}
}
