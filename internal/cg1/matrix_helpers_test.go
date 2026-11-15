package cg1

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/relux-works/a2a-swarm/internal/admission"
	"github.com/relux-works/a2a-swarm/internal/cg1cosign"
	"github.com/relux-works/a2a-swarm/internal/matrix"
	"github.com/relux-works/swarma-chain-lab/experiments/grantcheck"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-envelope/record"
)

// fakeGrantcheckVerdicts records adapter calls; it never claims a live chain grant.
type fakeGrantcheckVerdicts struct {
	inCalls, outCalls int
	sender            grantcheck.SenderProof
	recipients        grantcheck.RecipientProof
	presentation      *grantcheck.Presentation
	result            grantcheck.Verdict
	onCall            func(context.Context)
}

func (f *fakeGrantcheckVerdicts) InboundFrom(ctx context.Context, p grantcheck.SenderProof, g *grantcheck.Presentation) grantcheck.Verdict {
	f.inCalls++
	f.sender = p
	f.presentation = g
	if f.onCall != nil {
		f.onCall(ctx)
	}
	return f.result
}
func (f *fakeGrantcheckVerdicts) OutboundFrom(ctx context.Context, p grantcheck.RecipientProof) grantcheck.Verdict {
	f.outCalls++
	f.recipients = p
	if f.onCall != nil {
		f.onCall(ctx)
	}
	return f.result
}

type matrixFixture struct {
	c          *matrixChecker
	cfg        matrixSettings
	fake       *fakeGrantcheckVerdicts
	alice, bob ed25519.PrivateKey
	now        time.Time
	att        map[string]string
}

const matrixAlice = "@alice:fixture.invalid"
const matrixBob = "@bob:fixture.invalid"
const matrixRoom = "!pair:fixture.invalid"

func testEd(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
}
func edID(k ed25519.PrivateKey) string {
	return "ed25519:" + base64.RawURLEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
}
func signedEd(t *testing.T, k ed25519.PrivateKey, body map[string]any) []byte {
	t.Helper()
	kind := body["type"].(string)
	key := edID(k)
	id, e := record.ContentID(kind, body)
	if e != nil {
		t.Fatal(e)
	}
	pre, e := record.SigningPreimage(kind, key, "author", body)
	if e != nil {
		t.Fatal(e)
	}
	sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(k, pre))
	raw, e := record.Canonical(map[string]any{"version": "swarm-envelope/2", "body": body, "id": id, "signatures": []any{map[string]any{"role": "author", "key": key, "sig": sig}}})
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func evidenceJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func newMatrixFixture(t *testing.T) *matrixFixture {
	return newMatrixFixtureAt(t, time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC))
}

func newMatrixFixtureAt(t *testing.T, now time.Time) *matrixFixture {
	t.Helper()
	dir := stateDir(t)
	state := filepath.Join(dir, "matrix-cg1-state")
	if e := os.Mkdir(state, 0700); e != nil {
		t.Fatal(e)
	}
	f := &matrixFixture{alice: testEd(10), bob: testEd(11), now: now, att: map[string]string{}}
	root, revoker := testEd(20), testEd(21)
	f.cfg = matrixSettings{grantPolicy: testGrantPolicy(t), Version: 1, Identity: "alice", UserID: matrixAlice, Audience: "a2a-link.cg1.regtest", ConstructionProfile: "W", AgentName: "id/test-agent", LandlordName: "id/test-landlord", IssuerPubkey: xonly(5), TimeoutMS: 1000, RPC: su.Route{Host: "127.0.0.1", Port: 18443, Username: "w3-observer", Password: "public-fixture-rpc-password"}, Pins: map[string]matrixPeer{matrixAlice: {Key: xonly(1), Author: edID(f.alice)}, matrixBob: {Key: xonly(2), Author: edID(f.bob)}}, Evidence: map[string]json.RawMessage{}, InitialWatermark: f.now.Format("2006-01-02T15:04:05Z")}
	attestations, generations := map[string]any{}, map[string]any{}
	for i, k := range []ed25519.PrivateKey{f.alice, f.bob} {
		binding := map[string]any{"owner": "fixture-owner", "path": "fixture/message", "generation": "g1", "registration_number": int64(i + 1), "master_epoch": "epoch-1", "uid": int64(1000 + i)}
		body := map[string]any{"type": "attestation/1", "issuer": edID(root), "subject": map[string]any{"algorithm": "Ed25519", "key_id": edID(k), "public_bytes": base64.RawURLEncoding.EncodeToString(k.Public().(ed25519.PublicKey))}, "key_class": "agent", "purpose": "swarma-msg", "roles": []any{"author"}, "actions": []any{"message.sign"}, "iat": f.now.Add(-time.Minute).Format("2006-01-02T15:04:05Z"), "exp": f.now.Add(time.Hour).Format("2006-01-02T15:04:05Z"), "binding": binding}
		raw := signedEd(t, root, body)
		id, e := record.ContentID("attestation/1", body)
		if e != nil {
			t.Fatal(e)
		}
		f.att[edID(k)] = id
		attestations[id] = base64.RawURLEncoding.EncodeToString(raw)
		active := map[string]any{"active": true}
		for a, b := range binding {
			active[a] = b
		}
		generations[edID(k)] = active
	}
	snapshot := signedEd(t, revoker, map[string]any{"type": "revocation/1", "issuer": edID(revoker), "issued_at": f.now.Format("2006-01-02T15:04:05Z"), "complete": true, "entries": []any{}})
	values := map[string]any{"service_root": map[string]any{"key": edID(root), "purpose": int64(5)}, "agent_revocation_root": map[string]any{"key": edID(revoker), "purpose": "registry-revocation", "attestation_root": edID(root)}, "attestations": attestations, "active_generations": generations, "revocations": map[string]any{edID(revoker): map[string]any{"availability": "available", "max_age": int64(60), "rollback_safe": true, "snapshot": base64.RawURLEncoding.EncodeToString(snapshot)}}, "time": map[string]any{"trusted": true, "fresh": true, "authority_until": f.now.Add(5 * time.Minute).Format("2006-01-02T15:04:05Z")}}
	for k, v := range values {
		f.cfg.Evidence[k] = evidenceJSON(t, v)
	}
	f.save(t, dir)
	binding := matrixBinding(f.cfg)
	if e := initializeMatrixJournal(state, binding, f.cfg.InitialWatermark); e != nil {
		t.Fatal(e)
	}
	f.fake = &fakeGrantcheckVerdicts{result: grantcheck.Verdict{Decision: grantcheck.Live, Code: grantcheck.CodeLive}}
	f.c = &matrixChecker{core: f.fake, cosign: cg1cosign.BIP340{}, dir: dir, state: state, binding: binding, identity: "alice", userID: matrixAlice, timeout: time.Second, now: func() time.Time { return f.now }}
	t.Cleanup(func() { f.c.Close() })
	return f
}
func (f *matrixFixture) save(t *testing.T, dir string) {
	t.Helper()
	file := filepath.Join(dir, matrixConfigName)
	if e := os.WriteFile(file, evidenceJSON(t, f.cfg), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(file, 0700); e != nil {
		t.Fatal(e)
	}
}
func (f *matrixFixture) body(sender, to, text string, args map[string]any) map[string]any {
	k := f.bob
	if sender == matrixAlice {
		k = f.alice
	}
	sum := sha256.Sum256([]byte(text))
	return map[string]any{"type": "message/1", "aud": f.cfg.Audience, "nonce": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16)), "iat": f.now.Add(-time.Second).Format("2006-01-02T15:04:05Z"), "exp": f.now.Add(time.Minute).Format("2006-01-02T15:04:05Z"), "author": edID(k), "author_attestation": f.att[edID(k)], "action": matrixMessageAction, "target": map[string]any{"kind": "station", "id": "cg1"}, "arguments": args, "room": matrixRoom, "to": to, "body_sha256": hex.EncodeToString(sum[:])}
}
func (f *matrixFixture) content(t *testing.T, sender, to string, body map[string]any) map[string]any {
	t.Helper()
	key, fixture := f.bob, "bob"
	if sender == matrixAlice {
		key, fixture = f.alice, "alice"
	}
	raw := signedEd(t, key, body)
	encoded, e := matrix.EncodeEnvelope(raw)
	if e != nil {
		t.Fatal(e)
	}
	co, e := cg1cosign.FixtureSign(raw, fixture)
	if e != nil {
		t.Fatal(e)
	}
	return map[string]any{"msgtype": "m.text", "body": "hello", "works.relux.swarm.envelope": encoded, cg1cosign.ContentKey: co}
}
func (f *matrixFixture) incoming(t *testing.T, content map[string]any) admission.Inbound {
	return admission.Inbound{RoomID: matrixRoom, EventID: "$message", Sender: matrixBob, Kind: "m.room.message", Body: jsonBytes(t, content)}
}
func (f *matrixFixture) outgoing(t *testing.T, content map[string]any) admission.Outbound {
	return admission.Outbound{Identity: "alice", RoomID: matrixRoom, TransactionID: "txn-1", Kind: "m.room.message", Request: jsonBytes(t, content)}
}
