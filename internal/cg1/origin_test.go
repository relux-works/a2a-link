package cg1

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/a2a-swarm/internal/cg1cosign"
	"github.com/relux-works/a2a-swarm/internal/matrix"
	"github.com/relux-works/swarma-chain-lab/experiments/grantcheck"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-envelope/record"
)

// fakeOriginNode serves tip facts only. It holds no key and opens no socket.
type fakeOriginNode struct {
	mu              sync.Mutex
	infoCalls       int
	best            string
	blocks, headers int64
	initial, fail   bool
	time            int64
}

func (n *fakeOriginNode) Call(_ context.Context, method string, args ...any) (json.RawMessage, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.fail {
		return nil, errNode
	}
	switch method {
	case "getblockchaininfo":
		n.infoCalls++
		return json.Marshal(map[string]any{"blocks": n.blocks, "headers": n.headers, "bestblockhash": n.best, "initialblockdownload": n.initial})
	case "getblockheader":
		if len(args) != 1 || args[0] != n.best {
			return nil, errNode
		}
		return json.Marshal(map[string]any{"hash": n.best, "time": n.time})
	}
	return nil, errNode
}
func (n *fakeOriginNode) set(change func(*fakeOriginNode)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	change(n)
}
func (n *fakeOriginNode) reads() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.infoCalls
}

type originFixture struct {
	*matrixFixture
	origin *OriginChecker
	node   *fakeOriginNode
}

func newOriginFixture(t *testing.T) *originFixture {
	t.Helper()
	f := newMatrixFixture(t)
	node := &fakeOriginNode{best: strings.Repeat("c", 64), blocks: 100, headers: 100, time: f.now.Unix() - 30}
	life, cancel := context.WithCancel(context.Background())
	c := &OriginChecker{core: f.fake, cosign: cg1cosign.BIP340{}, node: node, dir: f.c.dir, binding: f.c.binding, identity: "alice", userID: matrixAlice, timeout: matrixFixtureTimeout, now: func() time.Time { return f.now }, life: life, cancel: cancel}
	t.Cleanup(func() { c.Close() })
	return &originFixture{matrixFixture: f, origin: c, node: node}
}

// goodBody is a signed inner request from bob to alice that presents a grant.
func (f *originFixture) goodBody() map[string]any {
	return f.body(matrixBob, matrixAlice, "hello", proofArgs(64))
}
func (f *originFixture) event(t *testing.T, content map[string]any) OriginEvent {
	t.Helper()
	return OriginEvent{RoomID: matrixRoom, EventID: "$message", Sender: matrixBob, Content: jsonBytes(t, content)}
}
func (f *originFixture) control(t *testing.T) OriginFacts {
	t.Helper()
	facts, code := f.origin.Check(context.Background(), f.event(t, f.content(t, matrixBob, matrixAlice, f.goodBody())))
	if code != OriginLive || facts == (OriginFacts{}) {
		t.Fatalf("valid control refused: %s", code)
	}
	return facts
}
func refusedOrigin(t *testing.T, facts OriginFacts, code, want OriginCode) {
	t.Helper()
	if facts != (OriginFacts{}) {
		t.Fatal("refusal carried origin facts")
	}
	if code != want {
		t.Fatalf("origin code=%s want=%s", code, want)
	}
}

// forgedContent claims one author key while another key made the signature.
// The record is canonical, so only signature verification can refuse it.
func (f *originFixture) forgedContent(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	kind := body["type"].(string)
	key := edID(f.bob)
	id, e := record.ContentID(kind, body)
	if e != nil {
		t.Fatal(e)
	}
	pre, e := record.SigningPreimage(kind, key, "author", body)
	if e != nil {
		t.Fatal(e)
	}
	sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.alice, pre))
	raw, e := record.Canonical(map[string]any{"version": "swarm-envelope/2", "body": body, "id": id, "signatures": []any{map[string]any{"role": "author", "key": key, "sig": sig}}})
	if e != nil {
		t.Fatal(e)
	}
	encoded, e := matrix.EncodeEnvelope(raw)
	if e != nil {
		t.Fatal(e)
	}
	co, e := cg1cosign.FixtureSign(raw, "bob")
	if e != nil {
		t.Fatal(e)
	}
	return map[string]any{"msgtype": "m.text", "body": "hello", matrix.EnvelopeContentKey: encoded, cg1cosign.ContentKey: co}
}

// Claim: a verified request with a Live grant on a fresh tip yields exactly the
// inner request content ID, the presented grant ID and the tip that was read;
// the event ID is never a Matrix ID; no delivery is recorded; and a second
// check of the same event is a new grant check and a new chain read.
func TestOriginCheckLiveFacts(t *testing.T) {
	f := newOriginFixture(t)
	body := f.goodBody()
	id, e := record.ContentID("message/1", body)
	if e != nil {
		t.Fatal(e)
	}
	journal := filepath.Join(f.c.state, matrixJournalName)
	before, e := os.ReadFile(journal)
	if e != nil {
		t.Fatal(e)
	}
	ev := f.event(t, f.content(t, matrixBob, matrixAlice, body))
	facts, code := f.origin.Check(context.Background(), ev)
	if code != OriginLive {
		t.Fatalf("valid control refused: %s", code)
	}
	want := OriginFacts{RequestID: strings.TrimPrefix(id, "sha256:"), GrantID: strings.Repeat("a", 64), TipHash: strings.Repeat("c", 64)}
	if facts != want || !validID(facts.RequestID) || strings.Contains(facts.RequestID, "$") || facts.RequestID == ev.EventID {
		t.Fatalf("origin facts=%+v", facts)
	}
	if f.fake.inCalls != 1 || f.fake.sender.Key != xonly(2) || f.fake.presentation == nil || f.fake.presentation.GrantID != want.GrantID {
		t.Fatal("grant check did not receive the verified signer and presented grant")
	}
	if f.node.reads() != 2 {
		t.Fatal("tip was not read before and after the grant check")
	}
	after, e := os.ReadFile(journal)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("origin check recorded a delivery")
	}
	entries, e := os.ReadDir(f.c.state)
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "envelope-") {
			t.Fatal("origin check persisted an envelope")
		}
	}
	again, code := f.origin.Check(context.Background(), ev)
	if code != OriginLive || again != want {
		t.Fatalf("repeated check refused: %s", code)
	}
	if f.fake.inCalls != 2 || f.node.reads() != 4 {
		t.Fatal("repeated check reused an earlier verdict or tip")
	}
}

// Claim: an inner request whose author signature, co-signature, signed text or
// pinned signer does not verify is refused as inner_request_invalid, carries no
// facts and never reaches the grant check; the valid control beside it is Live.
func TestOriginCheckInnerSignatureInvalid(t *testing.T) {
	for _, name := range []string{"forged-author-signature", "text-mismatch", "cosign-missing", "cosign-bad", "cosign-different-key", "unpinned-sender", "no-envelope"} {
		t.Run(name, func(t *testing.T) {
			f := newOriginFixture(t)
			f.control(t)
			calls := f.fake.inCalls
			bad := f.content(t, matrixBob, matrixAlice, f.goodBody())
			ev := f.event(t, bad)
			switch name {
			case "forged-author-signature":
				ev = f.event(t, f.forgedContent(t, f.goodBody()))
			case "text-mismatch":
				bad["body"] = "forged text"
				ev = f.event(t, bad)
			case "cosign-missing":
				delete(bad, cg1cosign.ContentKey)
				ev = f.event(t, bad)
			case "cosign-bad":
				bad[cg1cosign.ContentKey].(map[string]any)["sig"] = strings.Repeat("0", 128)
				ev = f.event(t, bad)
			case "cosign-different-key":
				co, e := cg1cosign.FixtureSign(envelopeBytes(t, bad), "alice")
				if e != nil {
					t.Fatal(e)
				}
				bad[cg1cosign.ContentKey] = co
				ev = f.event(t, bad)
			case "unpinned-sender":
				ev.Sender = "@mallory:fixture.invalid"
			case "no-envelope":
				delete(bad, matrix.EnvelopeContentKey)
				ev = f.event(t, bad)
			}
			facts, code := f.origin.Check(context.Background(), ev)
			refusedOrigin(t, facts, code, OriginInnerInvalid)
			if f.fake.inCalls != calls {
				t.Fatal("unverified inner request reached the grant check")
			}
		})
	}
}

// Claim: a correctly signed inner request addressed to another agent is refused
// as inner_request_recipient before any grant check; the control is Live.
func TestOriginCheckInnerRequestForAnotherAgent(t *testing.T) {
	f := newOriginFixture(t)
	f.control(t)
	calls := f.fake.inCalls
	body := f.body(matrixBob, matrixBob, "hello", proofArgs(64))
	facts, code := f.origin.Check(context.Background(), f.event(t, f.content(t, matrixBob, matrixBob, body)))
	refusedOrigin(t, facts, code, OriginRecipientMismatch)
	if f.fake.inCalls != calls {
		t.Fatal("request for another agent reached the grant check")
	}
}

// Claim: every grant state other than a consistent Live verdict maps to its
// typed refusal with no facts; Exchange is never Live; the same request is Live
// beside each negative when the grant is Live.
func TestOriginCheckGrantRefusals(t *testing.T) {
	cases := []struct {
		name    string
		verdict grantcheck.Verdict
		want    OriginCode
	}{
		{"terms-invalid", grantcheck.Verdict{Decision: grantcheck.Refused, Code: grantcheck.CodeTermsInvalid}, OriginTermsInvalid},
		{"binding-mismatch", grantcheck.Verdict{Decision: grantcheck.Refused, Code: grantcheck.CodeBindingMismatch}, OriginBindingMismatch},
		{"no-grant", grantcheck.Verdict{Decision: grantcheck.Exchange, Code: grantcheck.CodeNoGrant}, OriginGrantAbsent},
		{"expired", grantcheck.Verdict{Decision: grantcheck.Exchange, Code: grantcheck.CodeExpired}, OriginGrantExpired},
		{"seal-spent", grantcheck.Verdict{Decision: grantcheck.Exchange, Code: grantcheck.CodeSealSpent, Closed: true}, OriginSealSpent},
		{"landlord-changed", grantcheck.Verdict{Decision: grantcheck.Exchange, Code: grantcheck.CodeLandlordChanged, Closed: true}, OriginLandlordChanged},
		{"stale-tip-verdict", grantcheck.Verdict{Decision: grantcheck.Refused, Code: grantcheck.CodeTipStale, Retryable: true}, OriginTipStale},
		{"verifier-unavailable", grantcheck.Verdict{Decision: grantcheck.Refused, Code: grantcheck.CodeVerifierUnavailable, Retryable: true}, OriginUnavailable},
		{"inconsistent-live", grantcheck.Verdict{Decision: grantcheck.Refused, Code: grantcheck.CodeLive}, OriginGrantRefused},
		{"closed-live", grantcheck.Verdict{Decision: grantcheck.Live, Code: grantcheck.CodeLive, Closed: true}, OriginGrantRefused},
		{"retryable-live", grantcheck.Verdict{Decision: grantcheck.Live, Code: grantcheck.CodeLive, Retryable: true}, OriginGrantRefused},
		{"unknown-code", grantcheck.Verdict{Decision: grantcheck.Refused, Code: grantcheck.Code("future")}, OriginGrantRefused},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newOriginFixture(t)
			f.control(t)
			f.fake.result = tc.verdict
			facts, code := f.origin.Check(context.Background(), f.event(t, f.content(t, matrixBob, matrixAlice, f.goodBody())))
			refusedOrigin(t, facts, code, tc.want)
			if f.fake.inCalls != 2 {
				t.Fatal("grant state was not freshly checked")
			}
		})
	}
	t.Run("no-presentation", func(t *testing.T) {
		f := newOriginFixture(t)
		f.control(t)
		body := f.body(matrixBob, matrixAlice, "hello", map[string]any{"cg1": nil})
		facts, code := f.origin.Check(context.Background(), f.event(t, f.content(t, matrixBob, matrixAlice, body)))
		refusedOrigin(t, facts, code, OriginGrantAbsent)
		if f.fake.inCalls != 1 {
			t.Fatal("request without a presented grant reached the grant check")
		}
	})
}

// Claim: a tip that is old, unsynced, unreadable, ahead of the clock or that
// changes during the grant check never yields facts; the fake node supplies the
// chain facts and the control beside each negative is Live.
func TestOriginCheckTipFreshness(t *testing.T) {
	cases := []struct {
		name       string
		change     func(f *originFixture)
		want       OriginCode
		grantCalls int
	}{
		{"stale", func(f *originFixture) { f.node.set(func(n *fakeOriginNode) { n.time = f.now.Unix() - 601 }) }, OriginTipStale, 1},
		{"headers-ahead", func(f *originFixture) { f.node.set(func(n *fakeOriginNode) { n.headers = n.blocks + 1 }) }, OriginTipStale, 1},
		{"initial-download", func(f *originFixture) { f.node.set(func(n *fakeOriginNode) { n.initial = true }) }, OriginTipStale, 1},
		{"future", func(f *originFixture) { f.node.set(func(n *fakeOriginNode) { n.time = f.now.Unix() + 121 }) }, OriginUnavailable, 1},
		{"node-down", func(f *originFixture) { f.node.set(func(n *fakeOriginNode) { n.fail = true }) }, OriginUnavailable, 1},
		{"malformed-tip", func(f *originFixture) { f.node.set(func(n *fakeOriginNode) { n.best = "$not-a-hash" }) }, OriginUnavailable, 1},
		{"moved-during-grant-check", func(f *originFixture) {
			f.fake.onCall = func(context.Context) { f.node.set(func(n *fakeOriginNode) { n.best = strings.Repeat("d", 64) }) }
		}, OriginTipMoved, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newOriginFixture(t)
			f.control(t)
			tc.change(f)
			facts, code := f.origin.Check(context.Background(), f.event(t, f.content(t, matrixBob, matrixAlice, f.goodBody())))
			refusedOrigin(t, facts, code, tc.want)
			if f.fake.inCalls != tc.grantCalls {
				t.Fatalf("grant calls=%d want=%d", f.fake.inCalls, tc.grantCalls)
			}
		})
	}
}

// Claim: a cancelled call, a closed checker and a checker closed while the
// grant check runs never turn a Live verdict into facts; Close is idempotent.
func TestOriginCheckLifetime(t *testing.T) {
	for _, mode := range []string{"cancelled", "closed", "closed-during-check"} {
		t.Run(mode, func(t *testing.T) {
			f := newOriginFixture(t)
			f.control(t)
			ctx := context.Background()
			want := OriginUnavailable
			switch mode {
			case "cancelled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			case "closed":
				if f.origin.Close() != nil || f.origin.Close() != nil {
					t.Fatal("close is not idempotent")
				}
				want = OriginClosed
			case "closed-during-check":
				f.fake.onCall = func(context.Context) { f.origin.Close() }
			}
			facts, code := f.origin.Check(ctx, f.event(t, f.content(t, matrixBob, matrixAlice, f.goodBody())))
			refusedOrigin(t, facts, code, want)
		})
	}
}

// Claim: a protected policy that changes or disappears, also during the grant
// check, refuses as policy_invalid; a Live verdict obtained meanwhile is dropped.
func TestOriginCheckPolicyChange(t *testing.T) {
	for _, mode := range []string{"pin-changed-during-check", "policy-removed"} {
		t.Run(mode, func(t *testing.T) {
			f := newOriginFixture(t)
			f.control(t)
			switch mode {
			case "pin-changed-during-check":
				f.fake.onCall = func(context.Context) {
					p := f.cfg.Pins[matrixBob]
					p.Key = xonly(3)
					f.cfg.Pins[matrixBob] = p
					f.save(t, f.c.dir)
				}
			case "policy-removed":
				if e := os.Remove(filepath.Join(f.c.dir, matrixConfigName)); e != nil {
					t.Fatal(e)
				}
			}
			facts, code := f.origin.Check(context.Background(), f.event(t, f.content(t, matrixBob, matrixAlice, f.goodBody())))
			refusedOrigin(t, facts, code, OriginPolicyInvalid)
			if _, code = f.origin.Terms(); code != OriginPolicyInvalid {
				t.Fatalf("terms code=%s", code)
			}
		})
	}
}

// Claim: the terms accessor returns exactly the protected, already validated
// contract terms by hash.
func TestOriginTerms(t *testing.T) {
	f := newOriginFixture(t)
	terms, code := f.origin.Terms()
	raw := unitTerms(t)
	if code != OriginLive || len(terms) != 1 || !bytes.Equal(terms[rental.Hash(raw)], raw) {
		t.Fatalf("terms code=%s entries=%d", code, len(terms))
	}
}

// Claim: the production constructor gives each checker its own state scope and
// refuses a used scope, a permissive scope, a missing policy and a policy for
// another identity; two valid controls open beside the negatives.
func TestOpenOriginCheckerOwnsScope(t *testing.T) {
	f := newMatrixFixture(t)
	policy := stateDir(t)
	f.save(t, policy)
	open := func(scope string) (*OriginChecker, error) {
		return OpenOriginChecker(OriginScope{Identity: "alice", UserID: matrixAlice, PolicyDir: policy, ScopeDir: scope})
	}
	first, second := stateDir(t), stateDir(t)
	a, e := open(first)
	if e != nil {
		t.Fatal("valid control refused", e)
	}
	defer a.Close()
	b, e := open(second)
	if e != nil {
		t.Fatal("second valid control refused", e)
	}
	defer b.Close()
	if a == b || a.Scope() == b.Scope() || a.Scope() != first || b.Scope() != second || a.core == b.core || a.node == b.node {
		t.Fatal("two checkers share a scope, grant backend or node route")
	}
	for _, scope := range []string{first, second} {
		if st, e := os.Lstat(filepath.Join(scope, "grantcheck-state")); e != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
			t.Fatal("checker has no private grant state inside its own scope")
		}
	}
	if c, e := open(first); e == nil || c != nil {
		t.Fatal("a used scope was adopted by another checker")
	}
	permissive := stateDir(t)
	if e = os.Chmod(permissive, 0755); e != nil {
		t.Fatal(e)
	}
	if c, e := open(permissive); e == nil || c != nil {
		t.Fatal("a permissive scope was accepted")
	}
	if c, e := OpenOriginChecker(OriginScope{Identity: "bob", UserID: matrixBob, PolicyDir: policy, ScopeDir: stateDir(t)}); e == nil || c != nil {
		t.Fatal("a policy for another identity was accepted")
	}
	if c, e := OpenOriginChecker(OriginScope{Identity: "alice", UserID: matrixAlice, PolicyDir: stateDir(t), ScopeDir: stateDir(t)}); e == nil || c != nil {
		t.Fatal("a missing policy was accepted")
	}
}
