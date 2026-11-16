package e2ee

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const (
	ownerMXID = "@owner:example.test"
	agentMXID = "@agent:example.test"
	agentDev  = "AGENTDEV"
)

// renderPin writes the section 3 artifact for one owner principal from
// generated owner material; edit may alter the decoded object before encoding.
func renderPin(t testing.TB, owner *CrossSigning, binding string, revision uint64, edit func(map[string]any)) []byte {
	t.Helper()
	m, u := owner.Master(), owner.UserSigning()
	usk := SignedKey{UserID: ownerMXID, Usage: []string{UsageUserSigning}, Keys: map[string]string{u.ID: u.Public}}
	signature, err := owner.SignAsMaster(usk)
	if err != nil {
		t.Fatal(err)
	}
	principal := map[string]any{
		"mxid": ownerMXID, "master_key_id": m.ID, "master_public_key": m.Public, "master_sha256": m.SHA256,
		"user_signing_key_id": u.ID, "user_signing_public_key": u.Public, "user_signing_sha256": u.SHA256,
		"user_signing_master_signature": signature, "approved_devices": []string{"OWNERDEVICE"},
	}
	file := map[string]any{"v": 1, "binding": binding, "identity": agentMXID, "device_id": agentDev, "revision": revision, "owner": ownerMXID, "principals": []any{principal}}
	if edit != nil {
		edit(file)
	}
	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func ownerPin(t testing.TB) (*CrossSigning, HostPin, string) {
	t.Helper()
	owner, _ := newCrossSigning(t, ownerMXID)
	binding := strings.Repeat("c", 64)
	pin, err := parseHostPin(renderPin(t, owner, binding, 1, nil), binding, agentMXID, agentDev)
	if err != nil {
		t.Fatal(err)
	}
	return owner, pin, binding
}

func principal(file map[string]any) map[string]any {
	return file["principals"].([]any)[0].(map[string]any)
}

// The strict pin decoder accepts the exact section 3 shape and refuses a
// duplicate member, an unknown member, oversize input, binding/identity/device
// mismatch, a zero revision, a principal list without the owner (a USK pinned
// under another MXID), and an unsigned USK, each with its typed code.
func TestParseHostPinShape(t *testing.T) {
	owner, pin, binding := ownerPin(t)
	if pin.Revision != 1 || pin.Owner != ownerMXID || pin.Record.UserSigningPublicKey != owner.UserSigning().Public || !hexSize(pin.Digest, 32) || len(pin.ApprovedDevices) != 1 {
		t.Fatal("valid pin fields")
	}
	valid := renderPin(t, owner, binding, 1, nil)
	// plant duplicates one existing member by string surgery and proves the
	// surgery happened: json.Marshal sorts members, so a pattern that does not
	// occur would otherwise leave the valid bytes untouched and pass vacuously.
	plant := func(member string) []byte {
		if strings.Count(string(valid), member) != 1 {
			t.Fatalf("fixture member %s not found exactly once", member)
		}
		planted := strings.Replace(string(valid), member, member+","+member, 1)
		if planted == string(valid) || !json.Valid([]byte(planted)) {
			t.Fatal("duplicate plant did not apply or produced invalid JSON")
		}
		return []byte(planted)
	}
	for _, tc := range []struct {
		name string
		raw  []byte
		want error
	}{
		{"duplicate-top-level-field", plant(`"revision":1`), ErrPinInvalid},
		{"duplicate-nested-field", plant(`"mxid":"` + ownerMXID + `"`), ErrPinInvalid},
		{"unknown-field", renderPin(t, owner, binding, 1, func(f map[string]any) { f["trusted"] = true }), ErrPinInvalid},
		{"unknown-principal-field", renderPin(t, owner, binding, 1, func(f map[string]any) { principal(f)["local_trust"] = true }), ErrPinInvalid},
		{"oversize", append(append([]byte(nil), valid...), []byte(strings.Repeat(" ", MaxPin))...), ErrCapacity},
		{"wrong-binding", renderPin(t, owner, strings.Repeat("d", 64), 1, nil), ErrPinInvalid},
		{"wrong-identity", renderPin(t, owner, binding, 1, func(f map[string]any) { f["identity"] = "@other:example.test" }), ErrPinInvalid},
		{"wrong-device", renderPin(t, owner, binding, 1, func(f map[string]any) { f["device_id"] = "OTHERDEV" }), ErrPinInvalid},
		{"zero-revision", renderPin(t, owner, binding, 0, nil), ErrPinInvalid},
		{"usk-of-another-mxid", renderPin(t, owner, binding, 1, func(f map[string]any) { principal(f)["mxid"] = "@other:example.test" }), ErrPinInvalid},
		{"unsigned-usk", renderPin(t, owner, binding, 1, func(f map[string]any) { principal(f)["user_signing_master_signature"] = "" }), ErrPinInvalid},
		{"missing-signature-member", renderPin(t, owner, binding, 1, func(f map[string]any) { delete(principal(f), "user_signing_master_signature") }), ErrPinInvalid},
		{"wrong-usk-fingerprint", renderPin(t, owner, binding, 1, func(f map[string]any) { principal(f)["user_signing_sha256"] = strings.Repeat("0", 64) }), ErrPinInvalid},
		{"duplicate-approved-device", renderPin(t, owner, binding, 1, func(f map[string]any) { principal(f)["approved_devices"] = []string{"A", "A"} }), ErrPinInvalid},
		{"not-json", []byte("{"), ErrPinInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseHostPin(tc.raw, binding, agentMXID, agentDev); err != tc.want {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	// Control: the same bytes with the expected device left unspecified parse.
	if _, err := parseHostPin(valid, binding, agentMXID, ""); err != nil {
		t.Fatal("device-agnostic control", err)
	}
}

// checkForgedOwnerSignatureRefused is the killer assertion shared by the
// wrong-owner-USK negative and its plant control: a signature not made by the
// pinned USK over the agent master must yield ErrOwnerSignature.
func checkForgedOwnerSignatureRefused(pin HostPin, ev IdentityEvidence, forged json.RawMessage) error {
	_, err := OwnerSignatureOnMaster(pin, agentMXID, ev, forged)
	if err != ErrOwnerSignature {
		return fmt.Errorf("forged owner signature not refused: %v", err)
	}
	return nil
}

// checkForgedChainRefused is the killer assertion for the pin-level gate: a USK
// object not signed by the pinned MSK must yield ErrOwnerSignature.
func checkForgedChainRefused(pin HostPin) error {
	if err := VerifyOwnerChain(pin); err != ErrOwnerSignature {
		return fmt.Errorf("forged owner chain not refused: %v", err)
	}
	return nil
}

func agentEvidence(t testing.TB, pin HostPin) (IdentityEvidence, *CrossSigning, SignedKey) {
	t.Helper()
	agent, _ := newCrossSigning(t, agentMXID)
	_, w, _ := working(t)
	device, err := w.DeviceKeys(agentMXID, agentDev)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := NewIdentityEvidence(agent, device, pin, 1)
	if err != nil {
		t.Fatal(err)
	}
	master, err := agent.MasterKey(agentMXID)
	if err != nil {
		t.Fatal(err)
	}
	return ev, agent, master
}

func signedMaster(t testing.TB, master SignedKey, signer string, keyID, signature string) json.RawMessage {
	t.Helper()
	master.Signatures = map[string]map[string]string{signer: {keyID: signature}}
	raw, err := json.Marshal(master)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The owner gates: the pinned MSK signature over the pinned USK verifies and a
// genuine owner USK signature over the agent's queried master is accepted;
// beside it, a wrong MSK signature on the USK, a USK object signed for another
// MXID, a wrong USK signature on the agent master, a signature under another
// user or key ID (no signature from the pinned USK: awaiting-owner), a master
// object that is not ours, and an unsigned master all refuse with their codes.
func TestOwnerChainAndMasterSignature(t *testing.T) {
	owner, pin, binding := ownerPin(t)
	if err := VerifyOwnerChain(pin); err != nil {
		t.Fatal("valid chain", err)
	}
	ev, _, master := agentEvidence(t, pin)
	genuine, err := owner.SignAsUser(master)
	if err != nil {
		t.Fatal(err)
	}
	queried := signedMaster(t, master, ownerMXID, pin.Record.UserSigningKeyID, genuine)
	if got, err := OwnerSignatureOnMaster(pin, agentMXID, ev, queried); err != nil || got != genuine {
		t.Fatal("genuine owner signature", err)
	}
	// Wrong owner MSK signature on the USK: signed by the owner's SSK instead.
	uskObject, _ := OwnerUserSigningKeyObject(pin)
	wrongChain := pin
	wrongChain.Record.UserSigningMasterSignature, _ = signWith(owner.selfSigning, owner.SelfSigning().Public, uskObject)
	if err := checkForgedChainRefused(wrongChain); err != nil {
		t.Fatal(err)
	}
	// USK object of another MXID: the signature was made over user_id=@other.
	otherUSK := uskObject
	otherUSK.UserID = "@other:example.test"
	otherChain := pin
	otherChain.Record.UserSigningMasterSignature, _ = owner.SignAsMaster(otherUSK)
	if err := checkForgedChainRefused(otherChain); err != nil {
		t.Fatal(err)
	}
	// Wrong owner USK signature on the agent master: another generated USK.
	impostor, _ := newCrossSigning(t, ownerMXID)
	forgedSig, _ := impostor.SignAsUser(master)
	forged := signedMaster(t, master, ownerMXID, pin.Record.UserSigningKeyID, forgedSig)
	if err := checkForgedOwnerSignatureRefused(pin, ev, forged); err != nil {
		t.Fatal(err)
	}
	// Signature under another user or under the impostor's own key ID is not
	// the pinned USK's signature: awaiting-owner, never accepted.
	for name, raw := range map[string]json.RawMessage{
		"other-user":   signedMaster(t, master, "@other:example.test", pin.Record.UserSigningKeyID, genuine),
		"other-key-id": signedMaster(t, master, ownerMXID, impostor.UserSigning().ID, forgedSig),
		"unsigned":     signedMaster(t, master, ownerMXID, "", ""),
	} {
		if _, err := OwnerSignatureOnMaster(pin, agentMXID, ev, raw); err != ErrAwaitingOwner {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// A master object that is not ours is a published conflict even when the
	// owner signed it.
	otherAgent, _ := newCrossSigning(t, agentMXID)
	otherMaster, _ := otherAgent.MasterKey(agentMXID)
	otherSig, _ := owner.SignAsUser(otherMaster)
	if _, err := OwnerSignatureOnMaster(pin, agentMXID, ev, signedMaster(t, otherMaster, ownerMXID, pin.Record.UserSigningKeyID, otherSig)); err != ErrPublishedConflict {
		t.Fatal("foreign master admitted", err)
	}
	if _, err := OwnerSignatureOnMaster(pin, agentMXID, ev, json.RawMessage(`{"user_id":"@agent:example.test"`)); err != ErrPublishedConflict {
		t.Fatal("malformed master admitted", err)
	}
	// Extended signed objects need an explicit schema change: the owner's
	// signature over a master object carrying an extra member is not evidence
	// for our persisted master.
	extended := map[string]any{"user_id": agentMXID, "usage": []string{UsageMaster}, "keys": master.Keys, "extra": "member"}
	extendedSig, _ := owner.SignAsUser(extended)
	extended["signatures"] = map[string]map[string]string{ownerMXID: {pin.Record.UserSigningKeyID: extendedSig}}
	extendedRaw, _ := json.Marshal(extended)
	if _, err := OwnerSignatureOnMaster(pin, agentMXID, ev, extendedRaw); err != ErrPublishedConflict {
		t.Fatal("extended master admitted", err)
	}
	_ = binding
}

// Plant control: with the Ed25519 verification bypassed, both killer assertions
// (forged owner chain, forged owner USK signature) must fail, proving the
// negatives detect a disabled signature gate rather than passing vacuously.
func TestOwnerSignatureGatePlantKilled(t *testing.T) {
	owner, pin, _ := ownerPin(t)
	ev, _, master := agentEvidence(t, pin)
	impostor, _ := newCrossSigning(t, ownerMXID)
	forgedSig, _ := impostor.SignAsUser(master)
	forged := signedMaster(t, master, ownerMXID, pin.Record.UserSigningKeyID, forgedSig)
	uskObject, _ := OwnerUserSigningKeyObject(pin)
	wrongChain := pin
	wrongChain.Record.UserSigningMasterSignature, _ = signWith(owner.selfSigning, owner.SelfSigning().Public, uskObject)
	if checkForgedOwnerSignatureRefused(pin, ev, forged) != nil || checkForgedChainRefused(wrongChain) != nil {
		t.Fatal("killer assertions must pass before the plant")
	}
	original := ed25519Verify
	ed25519Verify = func([]byte, []byte, []byte) bool { return true }
	defer func() { ed25519Verify = original }()
	if checkForgedOwnerSignatureRefused(pin, ev, forged) == nil {
		t.Fatal("plant survived: bypassed owner USK signature check was not detected")
	}
	if checkForgedChainRefused(wrongChain) == nil {
		t.Fatal("plant survived: bypassed owner MSK chain check was not detected")
	}
}

// Identity evidence: a derived record validates and matches its keys; a record
// claiming owner-verified without the signature it names (a local trust flag)
// refuses as ErrIntegrity, an unverified record carrying a signature refuses as
// ErrCodec, other keys or another device never match, and the stored signature
// re-verifies only under the pinned USK over our own master.
func TestIdentityEvidenceValidationAndStoredSignature(t *testing.T) {
	owner, pin, _ := ownerPin(t)
	ev, agent, master := agentEvidence(t, pin)
	if err := ev.validate(); err != nil || ev.State != StateLocalReady {
		t.Fatal("derived evidence", err)
	}
	_, w, _ := working(t)
	device, _ := w.DeviceKeys(agentMXID, agentDev)
	if err := ev.MatchesKeys(agent, device); err != ErrIntegrity {
		t.Fatal("another device matched", err)
	}
	flag := ev
	flag.State = StateOwnerVerified
	if err := flag.validate(); err != ErrIntegrity {
		t.Fatal("local trust flag admitted", err)
	}
	flag.OwnerUserSigningKeyID = pin.Record.UserSigningKeyID
	if err := flag.validate(); err != ErrIntegrity {
		t.Fatal("trust flag with key ID but no signature admitted", err)
	}
	genuine, _ := owner.SignAsUser(master)
	flag.OwnerSignature = genuine
	if err := flag.validate(); err != nil {
		t.Fatal("complete verified record", err)
	}
	if err := VerifyStoredOwnerSignature(pin, agentMXID, flag); err != nil {
		t.Fatal("stored signature re-verification", err)
	}
	impostor, _ := newCrossSigning(t, ownerMXID)
	forged := flag
	forged.OwnerSignature, _ = impostor.SignAsUser(master)
	if err := VerifyStoredOwnerSignature(pin, agentMXID, forged); err != ErrOwnerSignature {
		t.Fatal("forged stored signature admitted", err)
	}
	if err := VerifyStoredOwnerSignature(pin, agentMXID, ev); err != ErrAwaitingOwner {
		t.Fatal("unverified record claimed verified", err)
	}
	stray := ev
	stray.OwnerSignature = genuine
	if err := stray.validate(); err != ErrCodec {
		t.Fatal("stray signature on unverified record admitted", err)
	}
	for name, edit := range map[string]func(*IdentityEvidence){
		"state": func(e *IdentityEvidence) { e.State = "trusted" },
		"same-keys": func(e *IdentityEvidence) {
			e.SelfSigningKeyID, e.SelfSigningPublicKey = e.MasterKeyID, e.MasterPublicKey
		},
		"bad-key-id":   func(e *IdentityEvidence) { e.MasterKeyID = "curve25519:" + e.MasterPublicKey },
		"zero-pin":     func(e *IdentityEvidence) { e.PinRevision = 0 },
		"bad-digest":   func(e *IdentityEvidence) { e.PinDigest = "short" },
		"bad-owner":    func(e *IdentityEvidence) { e.Owner = "owner" },
		"bad-device":   func(e *IdentityEvidence) { e.DeviceCurve25519 = "" },
		"negative-obs": func(e *IdentityEvidence) { e.ObservedMS = -1 },
	} {
		bad := ev
		edit(&bad)
		if err := bad.validate(); err != ErrCodec {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// ComparePin admits only the exact accepted revision and bytes; the same
// revision with changed bytes, a decreasing revision and a higher revision all
// enter changed in U2a.
func TestComparePin(t *testing.T) {
	owner, pin, binding := ownerPin(t)
	ev, _, _ := agentEvidence(t, pin)
	if err := ev.ComparePin(pin); err != nil {
		t.Fatal("unchanged pin", err)
	}
	for name, raw := range map[string][]byte{
		"same-revision-changed-bytes": renderPin(t, owner, binding, 1, func(f map[string]any) { principal(f)["approved_devices"] = []string{"OTHERDEVICE"} }),
		"decreasing-revision":         renderPin(t, owner, binding, 1, nil),
		"higher-revision":             renderPin(t, owner, binding, 2, nil),
	} {
		fresh, err := parseHostPin(raw, binding, agentMXID, agentDev)
		if err != nil {
			t.Fatal(name, err)
		}
		if name == "decreasing-revision" {
			// Accepted revision 2 previously; the host rolled back to 1.
			ev.PinRevision = 2
		}
		if err := ev.ComparePin(fresh); err != ErrTrustChanged {
			t.Fatalf("%s: %v", name, err)
		}
		ev.PinRevision = pin.Revision
	}
}

// SameMasterKey/SameDeviceKeys accept exactly the persisted public material and
// refuse other keys, another user or device, and malformed objects.
func TestPublishedMaterialComparison(t *testing.T) {
	_, pin, _ := ownerPin(t)
	ev, agent, master := agentEvidence(t, pin)
	raw, _ := json.Marshal(master)
	if err := SameMasterKey(ev, agentMXID, raw); err != nil {
		t.Fatal("own master", err)
	}
	other, _ := newCrossSigning(t, agentMXID)
	otherMaster, _ := other.MasterKey(agentMXID)
	otherRaw, _ := json.Marshal(otherMaster)
	if err := SameMasterKey(ev, agentMXID, otherRaw); err != ErrPublishedConflict {
		t.Fatal("foreign master", err)
	}
	if err := SameMasterKey(ev, agentMXID, nil); err != ErrPublishedConflict {
		t.Fatal("empty master", err)
	}
	_ = agent
	device := DeviceKeys{UserID: agentMXID, DeviceID: agentDev, Keys: map[string]string{"ed25519:" + agentDev: ev.DeviceEd25519, "curve25519:" + agentDev: ev.DeviceCurve25519}}
	deviceRaw, _ := json.Marshal(device)
	if err := SameDeviceKeys(ev, agentMXID, agentDev, deviceRaw); err != nil {
		t.Fatal("own device", err)
	}
	device.Keys["ed25519:"+agentDev] = ev.MasterPublicKey
	deviceRaw, _ = json.Marshal(device)
	if err := SameDeviceKeys(ev, agentMXID, agentDev, deviceRaw); err != ErrPublishedConflict {
		t.Fatal("foreign device key", err)
	}
}
