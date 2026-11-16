package e2ee

import (
	"encoding/json"
	"strings"
	"testing"

	goolmcrypto "maunium.net/go/mautrix/crypto/goolm/crypto"
)

func testPointer(mxid, device string) Pointer {
	return Pointer{1, strings.Repeat("0", 64), Binding{strings.Repeat("a", 64), mxid, device, strings.Repeat("b", 32)}}
}

// newCrossSigning derives generated cross-signing material for mxid from a
// fresh random root. Every control uses generated keys, never fixtures.
func newCrossSigning(t testing.TB, mxid string) (*CrossSigning, Root) {
	t.Helper()
	inv := new(Inventory)
	r, err := NewRoot(testPointer(mxid, "DEV"), inv)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := DeriveCrossSigning(r, inv)
	if err != nil {
		t.Fatal(err)
	}
	return keys, r
}

// Derivation is deterministic per root (a resumed upload re-derives exactly the
// persisted public material) and yields three distinct keys whose subordinate
// signatures verify under the master and whose fingerprints are SHA256 of the
// public bytes; control: the SSK signature does not verify under the USK.
func TestCrossSigningDerivationAndSignatures(t *testing.T) {
	const mxid = "@agent:example.test"
	keys, root := newCrossSigning(t, mxid)
	again, err := DeriveCrossSigning(root, new(Inventory))
	if err != nil || again.Master() != keys.Master() || again.SelfSigning() != keys.SelfSigning() || again.UserSigning() != keys.UserSigning() {
		t.Fatal("re-derivation changed public material", err)
	}
	m, s, u := keys.Master(), keys.SelfSigning(), keys.UserSigning()
	if m.Public == s.Public || m.Public == u.Public || s.Public == u.Public || m.ID != "ed25519:"+m.Public {
		t.Fatal("keys are not distinct standard key IDs")
	}
	for _, key := range []PublicKey{m, s, u} {
		if fp, err := Fingerprint(key.Public); err != nil || fp != key.SHA256 || !hexSize(fp, 32) {
			t.Fatal("fingerprint", err)
		}
	}
	master, err := keys.MasterKey(mxid)
	if err != nil || master.UserID != mxid || master.Usage[0] != UsageMaster || master.Keys[m.ID] != m.Public || master.Signatures != nil {
		t.Fatal("master object", err)
	}
	ssk, err := keys.SelfSigningKey(mxid)
	if err != nil {
		t.Fatal(err)
	}
	signature := ssk.Signatures[mxid][m.ID]
	if ok, err := verifySigned(m.Public, ssk, signature); err != nil || !ok {
		t.Fatal("SSK signature under master", err)
	}
	if ok, err := verifySigned(u.Public, ssk, signature); err != nil || ok {
		t.Fatal("SSK signature verified under the wrong key", err)
	}
	usk, err := keys.UserSigningKey(mxid)
	if err != nil || usk.Usage[0] != UsageUserSigning {
		t.Fatal(err)
	}
	if ok, err := verifySigned(m.Public, usk, usk.Signatures[mxid][m.ID]); err != nil || !ok {
		t.Fatal("USK signature under master", err)
	}
	// The signature covers the object without its signatures member, so the
	// signed bytes carry no signature of their own.
	input, err := signingInput(ssk)
	if err != nil || strings.Contains(string(input), "signatures") {
		t.Fatal("signing input retained signatures", err)
	}
	if _, err := keys.MasterKey("agent"); err != ErrInvalid {
		t.Fatal("partial MXID admitted", err)
	}
}

// The account adapter signs exactly the canonical bytes signingInput produces:
// the device self-signature verifies with goolm's Ed25519 verification over
// those bytes, the adapter reproduces the same (deterministic) signature when
// called again, and verification of the same signature fails once one field
// (device_id) of the signed object changes, with the untouched object as the
// control beside it.
func TestAccountSignerMatchesGoolmVerification(t *testing.T) {
	const mxid = "@agent:example.test"
	_, w, _ := working(t)
	d, err := w.DeviceKeys(mxid, "DEVICE")
	if err != nil {
		t.Fatal(err)
	}
	public, err := publicBase64(d.Keys["ed25519:DEVICE"], 32)
	if err != nil {
		t.Fatal("device public key", err)
	}
	encoded := d.Signatures[mxid]["ed25519:DEVICE"]
	signature, err := publicBase64(encoded, 64)
	if err != nil {
		t.Fatal("signature is not unpadded standard base64 of 64 bytes", err)
	}
	canonical, err := signingInput(d)
	if err != nil {
		t.Fatal(err)
	}
	if !goolmcrypto.Ed25519PublicKey(public).Verify(canonical, signature) {
		t.Fatal("adapter signature does not verify over the canonical bytes")
	}
	again, err := accountSigner{w.account}.SignJSON(d)
	if err != nil || again != encoded {
		t.Fatal("adapter did not reproduce the deterministic signature", err)
	}
	tampered := d
	tampered.DeviceID = "OTHER"
	changed, err := signingInput(tampered)
	if err != nil || string(changed) == string(canonical) {
		t.Fatal("tampered object has the same canonical bytes", err)
	}
	if goolmcrypto.Ed25519PublicKey(public).Verify(changed, signature) {
		t.Fatal("signature verified over a changed field")
	}
	if !goolmcrypto.Ed25519PublicKey(public).Verify(canonical, signature) {
		t.Fatal("control: untouched object no longer verifies")
	}
	if _, err := (accountSigner{}).SignJSON(d); err != ErrInvalid {
		t.Fatal("nil account admitted", err)
	}
}

// A device-key object is self-signed by the account's Ed25519 key and
// cross-signed by the SSK; control: changing the device ID breaks both.
func TestDeviceKeysSelfAndCrossSignatures(t *testing.T) {
	const mxid = "@agent:example.test"
	_, w, _ := working(t)
	keys, _ := newCrossSigning(t, mxid)
	d, err := w.DeviceKeys(mxid, "DEVICE")
	if err != nil || d.Keys["ed25519:DEVICE"] == "" || d.Keys["curve25519:DEVICE"] == "" || len(d.Algorithms) != 2 {
		t.Fatal("device keys", err)
	}
	if err = VerifyDeviceSelfSignature(d); err != nil {
		t.Fatal("self signature", err)
	}
	signed, err := keys.SignDevice(d)
	if err != nil {
		t.Fatal(err)
	}
	ssk := keys.SelfSigning()
	if ok, err := verifySigned(ssk.Public, signed, signed.Signatures[mxid][ssk.ID]); err != nil || !ok {
		t.Fatal("SSK device signature", err)
	}
	if signed.Signatures[mxid]["ed25519:DEVICE"] != d.Signatures[mxid]["ed25519:DEVICE"] || d.Signatures[mxid][ssk.ID] != "" {
		t.Fatal("cross-signing mutated the original object")
	}
	tampered := signed
	tampered.DeviceID = "OTHER"
	if err = VerifyDeviceSelfSignature(tampered); err != ErrIntegrity {
		t.Fatal("tampered device admitted", err)
	}
	if ok, _ := verifySigned(ssk.Public, tampered, signed.Signatures[mxid][ssk.ID]); ok {
		t.Fatal("tampered device verified under SSK")
	}
	raw, _ := json.Marshal(signed)
	var round DeviceKeys
	if json.Unmarshal(raw, &round) != nil || VerifyDeviceSelfSignature(round) != nil {
		t.Fatal("wire round trip")
	}
	if _, err = w.DeviceKeys(mxid, ""); err != ErrInvalid {
		t.Fatal("empty device admitted", err)
	}
}
