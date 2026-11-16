//go:build darwin || linux

package e2ee

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

// Identity evidence round-trips through the sealed snapshot; a planted record
// whose state claims owner-verified without its signature (a local trust flag)
// refuses on save without replacing the previous bytes and refuses on load
// without repair; a record with the genuine signature saves and loads.
func TestIdentityEvidenceSealedRoundTrip(t *testing.T) {
	_, lease, custody, pointer, inv := fixture(t)
	root := mustPointerRoot(t, custody, pointer, inv)
	codec := codecFor(t, root, inv)
	owner, pin, _ := ownerPin(t)
	keys, err := DeriveCrossSigning(root, inv)
	if err != nil {
		t.Fatal(err)
	}
	_, w, key := working(t)
	device, err := w.DeviceKeys(agentMXID, agentDev)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := NewIdentityEvidence(keys, device, pin, 42)
	if err != nil {
		t.Fatal(err)
	}
	state, err := w.Checkpoint(key)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := Snapshot{Version: 1, Revision: 1, Engine: state, Identity: &ev}
	if err = lease.SaveSnapshot(codec, pointer.Binding, snapshot, true); err != nil {
		t.Fatal(err)
	}
	loaded, err := lease.LoadSnapshot(codec, pointer.Binding)
	if err != nil || !reflect.DeepEqual(loaded.Identity, &ev) {
		t.Fatal("evidence readback", err)
	}
	if err = loaded.Identity.MatchesKeys(keys, device); err != nil {
		t.Fatal("restored evidence matches derived keys", err)
	}
	before, err := lease.read("state.bin", MaxSnapshot+envelopeOverhead)
	if err != nil {
		t.Fatal(err)
	}
	flag := ev
	flag.State = StateOwnerVerified
	planted := snapshot
	planted.Identity = &flag
	planted.Revision = 2
	if err = lease.SaveSnapshot(codec, pointer.Binding, planted, false); err != ErrIntegrity {
		t.Fatal("local trust flag saved", err)
	}
	after, err := lease.read("state.bin", MaxSnapshot+envelopeOverhead)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("refused save changed the snapshot", err)
	}
	raw, err := json.Marshal(planted)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeSnapshot(raw); err != ErrIntegrity {
		t.Fatal("local trust flag decoded", err)
	}
	if err = lease.WriteSealed(codec, pointer.Binding, raw, false); err != nil {
		t.Fatal(err)
	}
	if _, err = lease.LoadSnapshot(codec, pointer.Binding); err != ErrIntegrity {
		t.Fatal("planted trust flag loaded", err)
	}
	// Control: the genuine owner signature makes the same record valid.
	master, err := ev.MasterKeyObject(agentMXID)
	if err != nil {
		t.Fatal(err)
	}
	flag.OwnerUserSigningKeyID = pin.Record.UserSigningKeyID
	if flag.OwnerSignature, err = owner.SignAsUser(master); err != nil {
		t.Fatal(err)
	}
	verified := snapshot
	verified.Identity = &flag
	verified.Revision = 2
	if err = lease.SaveSnapshot(codec, pointer.Binding, verified, false); err != nil {
		t.Fatal("verified record refused", err)
	}
	loaded, err = lease.LoadSnapshot(codec, pointer.Binding)
	if err != nil || loaded.Identity.State != StateOwnerVerified {
		t.Fatal("verified readback", err)
	}
	if err = VerifyStoredOwnerSignature(pin, agentMXID, *loaded.Identity); err != nil {
		t.Fatal("stored signature after restart", err)
	}
}
