package cg1

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/a2a-swarm/internal/admission"
	"github.com/relux-works/a2a-swarm/internal/cg1cosign"
	"github.com/relux-works/a2a-swarm/internal/matrix"
	"github.com/relux-works/swarma-chain-lab/experiments/grantcheck"
)

func cloneContent(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	var n map[string]any
	if e := json.Unmarshal(jsonBytes(t, m), &n); e != nil {
		t.Fatal(e)
	}
	return n
}
func envelopeBytes(t *testing.T, m map[string]any) []byte {
	t.Helper()
	b, e := matrix.DecodeEnvelope(m[matrix.EnvelopeContentKey].(string))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func replaceEnvelope(t *testing.T, m map[string]any, raw []byte, fixture string) {
	t.Helper()
	encoded, e := matrix.EncodeEnvelope(raw)
	if e != nil {
		t.Fatal(e)
	}
	co, e := cg1cosign.FixtureSign(raw, fixture)
	if e != nil {
		t.Fatal(e)
	}
	m[matrix.EnvelopeContentKey] = encoded
	m[cg1cosign.ContentKey] = co
}
func proofArgs(n int) map[string]any {
	raw := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("p", n)))
	chunks := []any{}
	for len(raw) > 4096 {
		chunks = append(chunks, raw[:4096])
		raw = raw[4096:]
	}
	if raw != "" {
		chunks = append(chunks, raw)
	}
	return map[string]any{"cg1": map[string]any{"grant_id": strings.Repeat("a", 64), "proof": chunks}}
}

// Each case proves its named refusal is definite, precedes grantcheck and leaves the journal unchanged; the adjacent valid control reaches only the co-signing key.
func TestMatrixInboundRefusals(t *testing.T) {
	for _, name := range []string{"no-envelope", "bad-envelope-signature", "cosign-missing", "cosign-bad", "cosign-different-bytes", "cosign-different-key", "matrix-id-key", "to-mismatch", "oversize-presentation", "text-mismatch", "room-mismatch", "unknown-action", "malformed-presentation"} {
		t.Run(name, func(t *testing.T) {
			f := newMatrixFixture(t)
			good := f.content(t, matrixBob, matrixAlice, f.body(matrixBob, matrixAlice, "hello", map[string]any{"cg1": nil}))
			bad := cloneContent(t, good)
			switch name {
			case "no-envelope":
				delete(bad, matrix.EnvelopeContentKey)
			case "bad-envelope-signature":
				var wire map[string]any
				json.Unmarshal(envelopeBytes(t, bad), &wire)
				sig := wire["signatures"].([]any)[0].(map[string]any)
				sig["sig"] = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
				replaceEnvelope(t, bad, jsonBytes(t, wire), "bob")
			case "cosign-missing":
				delete(bad, cg1cosign.ContentKey)
			case "cosign-bad":
				bad[cg1cosign.ContentKey].(map[string]any)["sig"] = strings.Repeat("0", 128)
			case "cosign-different-bytes":
				co, e := cg1cosign.FixtureSign(append(envelopeBytes(t, bad), '\n'), "bob")
				if e != nil {
					t.Fatal(e)
				}
				bad[cg1cosign.ContentKey] = co
			case "cosign-different-key":
				co, e := cg1cosign.FixtureSign(envelopeBytes(t, bad), "alice")
				if e != nil {
					t.Fatal(e)
				}
				bad[cg1cosign.ContentKey] = co
			case "matrix-id-key":
				bad[cg1cosign.ContentKey].(map[string]any)["key"] = matrixBob
			case "to-mismatch":
				bad = f.content(t, matrixBob, matrixBob, f.body(matrixBob, matrixBob, "hello", map[string]any{"cg1": nil}))
			case "oversize-presentation":
				bad = f.content(t, matrixBob, matrixAlice, f.body(matrixBob, matrixAlice, "hello", proofArgs(grantcheck.MaxPresentationBytes+1)))
			case "text-mismatch":
				bad["body"] = "forged text"
			case "room-mismatch":
				body := f.body(matrixBob, matrixAlice, "hello", map[string]any{"cg1": nil})
				body["room"] = "!elsewhere:fixture.invalid"
				bad = f.content(t, matrixBob, matrixAlice, body)
			case "unknown-action":
				body := f.body(matrixBob, matrixAlice, "hello", map[string]any{"cg1": nil})
				body["action"] = "exec.anything"
				bad = f.content(t, matrixBob, matrixAlice, body)
			case "malformed-presentation":
				bad = f.content(t, matrixBob, matrixAlice, f.body(matrixBob, matrixAlice, "hello", map[string]any{"cg1": map[string]any{"grant_id": "bad", "proof": []any{"bad"}}}))
			}
			journal := filepath.Join(f.c.state, matrixJournalName)
			before := admissionReadMatrix(t, journal)
			d, e := f.c.Inbound(context.Background(), f.incoming(t, bad))
			want(t, d, e, admission.Refused, "denied", false)
			if f.fake.inCalls != 0 || f.fake.outCalls != 0 {
				t.Fatal("refusal reached grantcheck")
			}
			if string(before) != string(admissionReadMatrix(t, journal)) {
				t.Fatal("refusal changed replay journal")
			}
			d, e = f.c.Inbound(context.Background(), f.incoming(t, good))
			want(t, d, e, admission.Live, "allowed", false)
			if f.fake.inCalls != 1 || f.fake.sender.Transport != grantcheck.SwarmEnvelopeV2 || f.fake.sender.Key != xonly(2) || f.fake.presentation != nil {
				t.Fatal("verified co-signing key/provenance was not passed")
			}
		})
	}
}
func admissionReadMatrix(t *testing.T, p string) []byte {
	t.Helper()
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

// Proves outbound resolves the one signed recipient through its protected pin and freshly rechecks the same transaction after an earlier Live.
func TestMatrixOutboundPinsAndRetry(t *testing.T) {
	f := newMatrixFixture(t)
	good := f.content(t, matrixAlice, matrixBob, f.body(matrixAlice, matrixBob, "hello", map[string]any{"cg1": nil}))
	d, e := f.c.Outbound(context.Background(), f.outgoing(t, good))
	want(t, d, e, admission.Live, "allowed", false)
	if f.fake.outCalls != 1 || f.fake.recipients.Transport != grantcheck.SwarmEnvelopeV2 || len(f.fake.recipients.Keys) != 1 || f.fake.recipients.Keys[0] != xonly(2) {
		t.Fatal("outbound did not resolve exact pinned recipient")
	}
	f.fake.result = grantcheck.Verdict{Decision: grantcheck.Refused, Code: grantcheck.CodeSealSpent, Closed: true}
	d, e = f.c.Outbound(context.Background(), f.outgoing(t, good))
	want(t, d, e, admission.Refused, "denied", false)
	if f.fake.outCalls != 2 {
		t.Fatal("outbound reused a cached Live")
	}
}

// Proves an unpinned to, a nonlocal co-signer and a forged signed author cannot reach an outbound grant check; each neighbor passes with the local signer and pinned to.
func TestMatrixOutboundRefusals(t *testing.T) {
	for _, name := range []string{"to-unpinned", "signer-mismatch", "author-mismatch", "no-envelope", "oversize-presentation"} {
		t.Run(name, func(t *testing.T) {
			f := newMatrixFixture(t)
			good := f.content(t, matrixAlice, matrixBob, f.body(matrixAlice, matrixBob, "hello", map[string]any{"cg1": nil}))
			bad := cloneContent(t, good)
			switch name {
			case "to-unpinned":
				bad = f.content(t, matrixAlice, "@unbound:fixture.invalid", f.body(matrixAlice, "@unbound:fixture.invalid", "hello", map[string]any{"cg1": nil}))
			case "signer-mismatch":
				co, e := cg1cosign.FixtureSign(envelopeBytes(t, bad), "bob")
				if e != nil {
					t.Fatal(e)
				}
				bad[cg1cosign.ContentKey] = co
			case "author-mismatch":
				bad = f.content(t, matrixBob, matrixBob, f.body(matrixBob, matrixBob, "hello", map[string]any{"cg1": nil}))
				co, _ := cg1cosign.FixtureSign(envelopeBytes(t, bad), "alice")
				bad[cg1cosign.ContentKey] = co
			case "no-envelope":
				delete(bad, matrix.EnvelopeContentKey)
			case "oversize-presentation":
				bad = f.content(t, matrixAlice, matrixBob, f.body(matrixAlice, matrixBob, "hello", proofArgs(grantcheck.MaxPresentationBytes+1)))
			}
			d, e := f.c.Outbound(context.Background(), f.outgoing(t, bad))
			want(t, d, e, admission.Refused, "denied", false)
			if f.fake.outCalls != 0 {
				t.Fatal("outbound refusal reached grantcheck")
			}
			d, e = f.c.Outbound(context.Background(), f.outgoing(t, good))
			want(t, d, e, admission.Live, "allowed", false)
		})
	}
}

// Proves the maximum decoded presentation is carried byte-exactly, and a different event cannot replay an admitted envelope after a checker reopen.
func TestMatrixPresentationAndReplay(t *testing.T) {
	f := newMatrixFixture(t)
	m := f.content(t, matrixBob, matrixAlice, f.body(matrixBob, matrixAlice, "hello", proofArgs(grantcheck.MaxPresentationBytes)))
	in := f.incoming(t, m)
	d, e := f.c.Inbound(context.Background(), in)
	want(t, d, e, admission.Live, "allowed", false)
	if f.fake.presentation == nil || len(f.fake.presentation.Bytes) != grantcheck.MaxPresentationBytes || string(f.fake.presentation.Bytes) != strings.Repeat("p", grantcheck.MaxPresentationBytes) {
		t.Fatal("presentation bytes changed")
	}
	reopened := &matrixChecker{core: f.fake, cosign: cg1cosign.BIP340{}, dir: f.c.dir, state: f.c.state, binding: f.c.binding, identity: f.c.identity, userID: f.c.userID, timeout: time.Second, now: f.c.now}
	in.EventID = "$replayed"
	d, e = reopened.Inbound(context.Background(), in)
	want(t, d, e, admission.Refused, "denied", false)
	if f.fake.inCalls != 1 {
		t.Fatal("different event replay reached grantcheck")
	}
	in.EventID = "$message"
	d, e = reopened.Inbound(context.Background(), in)
	want(t, d, e, admission.Live, "allowed", false)
	if f.fake.inCalls != 2 {
		t.Fatal("same-event crash recovery was not freshly checked")
	}
}

// Proves stale protected time evidence and a cancelled or closed checker cannot turn a fake Live into permission.
func TestMatrixDependencyAndLifetime(t *testing.T) {
	for _, mode := range []string{"stale", "cancelled", "closed", "during-check"} {
		t.Run(mode, func(t *testing.T) {
			f := newMatrixFixture(t)
			m := f.content(t, matrixBob, matrixAlice, f.body(matrixBob, matrixAlice, "hello", map[string]any{"cg1": nil}))
			ctx := context.Background()
			switch mode {
			case "stale":
				f.cfg.Evidence["time"] = evidenceJSON(t, map[string]any{"trusted": true, "fresh": false, "authority_until": f.now.Add(time.Hour).Format("2006-01-02T15:04:05Z")})
				f.save(t, f.c.dir)
			case "cancelled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			case "closed":
				f.c.Close()
			case "during-check":
				f.fake.onCall = func(ctx context.Context) { f.c.Close() }
			}
			d, e := f.c.Inbound(ctx, f.incoming(t, m))
			reason, retry := "dependency_unavailable", true
			if mode == "closed" {
				reason, retry = "policy_error", false
			}
			want(t, d, e, admission.Refused, reason, retry)
		})
	}
}

// Proves the adapter uses the closed string mapping, preserves dependency retries and refuses unknown verdicts, with Exchange restricted to inbound.
func TestMatrixVerdictMapping(t *testing.T) {
	for _, tc := range []struct {
		v        grantcheck.Verdict
		in       bool
		decision admission.Verdict
		reason   string
		retry    bool
	}{
		{grantcheck.Verdict{Decision: grantcheck.Live, Code: grantcheck.CodeLive}, true, admission.Live, "allowed", false},
		{grantcheck.Verdict{Decision: grantcheck.Refused, Code: grantcheck.CodeVerifierUnavailable}, true, admission.Refused, "dependency_unavailable", true},
		{grantcheck.Verdict{Decision: grantcheck.Refused, Code: grantcheck.CodeStateUnavailable}, true, admission.Refused, "storage_error", true},
		{grantcheck.Verdict{Decision: grantcheck.Refused, Code: grantcheck.Code("future")}, true, admission.Refused, "policy_invalid", false},
		{grantcheck.Verdict{Decision: grantcheck.Exchange, Code: grantcheck.CodeNoGrant}, true, admission.Exchange, "exchange", false},
		{grantcheck.Verdict{Decision: grantcheck.Exchange, Code: grantcheck.CodeNoGrant}, false, admission.Refused, "exchange_outbound", false},
	} {
		want(t, matrixDecision(tc.v, tc.in), nil, tc.decision, tc.reason, tc.retry)
	}
}

// Proves trusted clock progress admits new messages while a rollback below the durable floor refuses without another grant check.
func TestMatrixClockProgressAndRollback(t *testing.T) {
	f := newMatrixFixture(t)
	for i := 0; i < 2; i++ {
		m := f.content(t, matrixBob, matrixAlice, f.body(matrixBob, matrixAlice, "hello", map[string]any{"cg1": nil}))
		in := f.incoming(t, m)
		in.EventID += string(rune('a' + i))
		d, e := f.c.Inbound(context.Background(), in)
		want(t, d, e, admission.Live, "allowed", false)
		f.now = f.now.Add(2 * time.Second)
	}
	f.now = f.now.Add(-4 * time.Second)
	m := f.content(t, matrixBob, matrixAlice, f.body(matrixBob, matrixAlice, "hello", map[string]any{"cg1": nil}))
	d, e := f.c.Inbound(context.Background(), f.incoming(t, m))
	want(t, d, e, admission.Refused, "dependency_unavailable", true)
	if f.fake.inCalls != 2 {
		t.Fatal("rollback reached grantcheck")
	}
}

// Proves an envelope that expires, or whose trust pin changes, during a grant check cannot use that check's Live result.
func TestMatrixRecheckAfterGrant(t *testing.T) {
	for _, mode := range []string{"expired", "pin-change", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			f := newMatrixFixture(t)
			m := f.content(t, matrixBob, matrixAlice, f.body(matrixBob, matrixAlice, "hello", map[string]any{"cg1": nil}))
			f.fake.onCall = func(ctx context.Context) {
				switch mode {
				case "expired":
					f.now = f.now.Add(time.Minute)
				case "pin-change":
					p := f.cfg.Pins[matrixBob]
					p.Key = xonly(3)
					f.cfg.Pins[matrixBob] = p
					f.save(t, f.c.dir)
				case "deadline":
					<-ctx.Done()
				}
			}
			if mode == "deadline" {
				f.c.timeout = time.Second
			}
			before := admissionReadMatrix(t, filepath.Join(f.c.state, matrixJournalName))
			d, e := f.c.Inbound(context.Background(), f.incoming(t, m))
			reason, retry := "denied", false
			if mode == "pin-change" {
				reason = "policy_invalid"
			}
			if mode == "deadline" {
				reason, retry = "dependency_unavailable", true
			}
			want(t, d, e, admission.Refused, reason, retry)
			if f.fake.inCalls != 1 || string(before) != string(admissionReadMatrix(t, filepath.Join(f.c.state, matrixJournalName))) {
				t.Fatalf("interrupted check path/history: calls=%d changed=%t", f.fake.inCalls, string(before) != string(admissionReadMatrix(t, filepath.Join(f.c.state, matrixJournalName))))
			}
		})
	}
}

// Proves the committed public vector passes full Ed25519 plus BIP-340 admission and retains its exact envelope digest and fixture signature.
func TestMatrixWireVector(t *testing.T) {
	var v struct {
		Envelope string         `json:"envelope_base64"`
		SHA      string         `json:"envelope_sha256"`
		Digest   string         `json:"digest"`
		Co       map[string]any `json:"cosignature"`
	}
	data, e := os.ReadFile("testdata/matrix-cosignature-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	if json.Unmarshal(data, &v) != nil {
		t.Fatal("vector decode")
	}
	raw, e := base64.RawURLEncoding.DecodeString(v.Envelope)
	if e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256(raw)
	digest, e := cg1cosign.Digest(raw)
	if e != nil || hex.EncodeToString(hash[:]) != v.SHA || hex.EncodeToString(digest[:]) != v.Digest {
		t.Fatal("wire vector digest changed")
	}
	generated, e := cg1cosign.FixtureSign(raw, "bob")
	if e != nil || string(jsonBytes(t, generated)) != string(jsonBytes(t, v.Co)) {
		t.Fatal("wire vector signature changed")
	}
	f := newMatrixFixture(t)
	content := map[string]any{"msgtype": "m.text", "body": "hello", matrix.EnvelopeContentKey: v.Envelope, cg1cosign.ContentKey: v.Co}
	d, e := f.c.Inbound(context.Background(), f.incoming(t, content))
	want(t, d, e, admission.Live, "allowed", false)
}

// Proves an outbound transaction cannot switch to a different signed record after an accepted request, while the identical retry remains valid.
func TestMatrixTransactionBinding(t *testing.T) {
	f := newMatrixFixture(t)
	m := f.content(t, matrixAlice, matrixBob, f.body(matrixAlice, matrixBob, "hello", map[string]any{"cg1": nil}))
	out := f.outgoing(t, m)
	d, e := f.c.Outbound(context.Background(), out)
	want(t, d, e, admission.Live, "allowed", false)
	body := f.body(matrixAlice, matrixBob, "hello", map[string]any{"cg1": nil})
	body["nonce"] = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("n", 16)))
	other := f.content(t, matrixAlice, matrixBob, body)
	d, e = f.c.Outbound(context.Background(), f.outgoing(t, other))
	want(t, d, e, admission.Refused, "denied", false)
	if f.fake.outCalls != 1 {
		t.Fatal("changed transaction reached grantcheck")
	}
	d, e = f.c.Outbound(context.Background(), out)
	want(t, d, e, admission.Live, "allowed", false)
	if f.fake.outCalls != 2 {
		t.Fatal("identical transaction was not rechecked")
	}
}
