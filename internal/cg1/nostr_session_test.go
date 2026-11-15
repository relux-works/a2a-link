package cg1

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/a2a-swarm/internal/nostrsession"
	fx "github.com/relux-works/a2a-swarm/internal/nostrtest"
	tr "github.com/relux-works/a2a-swarm/transport"
	nt "github.com/relux-works/a2a-transport-nostr/nostrtransport"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	gn "github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

// Production session.Open + published transport/CG1/K1 + genuine issuer/Core:
// only the live grantee reaches ordinary inbox and enables an outbound reply.
// Missing, expired, wrong-grantee, duplicate and revoked proof never do; forged
// rumor author is rejected before CG1. No checker or clock is injected here.
func TestCoreNostrSession(t *testing.T) {
	if os.Getenv("CG1_REGTEST") != "1" {
		t.Skip("requires isolated pinned Core")
	}
	ctx := context.Background()
	base := fx.Root(t)
	r := fx.Relay(t)
	agent, renter, outsider := fx.Key(t), fx.Key(t), fx.Key(t)
	l := newCoreLab(t, agent.PubKeyHex())
	renterGrantKey, e := gn.PrivKeyFromBytes(renter.Bytes())
	if e != nil {
		t.Fatal("fixture key conversion")
	}
	seal := l.seal()
	now := time.Now().Unix()
	proof := l.grantAt(renterGrantKey, "session-live", seal, true, now)
	expiredProof := l.grantAt(renterGrantKey, "session-expired", l.seal(), true, now-2000)
	carrier := func(proof []byte) json.RawMessage {
		id, e := kernel.PresentationID(proof)
		if e != nil {
			t.Fatal(e)
		}
		return fx.Carrier(t, id, proof)
	}
	root := fx.Provision(t, base, "station", r.URL, "cg1", agent, nil)
	fx.Write(t, filepath.Join(root, "admission", "cg1.json"), jsonBytes(t, settings{grantPolicy: testGrantPolicy(t), Version: 1, AgentName: e2eAgentName, LandlordName: e2eLandlordName, IssuerPubkey: l.issuerPub, TimeoutMS: 5000, RPC: l.route}))
	s, e := nostrsession.Open(ctx, base, "station")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { s.Close() }()
	peer := fx.Adapter(t, filepath.Join(base, "peer"), r.URL, renter)
	conv, e := peer.ConversationFor([]tr.PrincipalID{tr.PrincipalID(agent.PubKeyHex())}, "")
	if e != nil {
		t.Fatal(e)
	}
	post := func(text string, p json.RawMessage) string {
		t.Helper()
		m := tr.Message{Text: text}
		if p != nil {
			m.Extensions = map[string]json.RawMessage{nt.GrantExtension: p}
		}
		result, e := peer.Send(ctx, tr.SendRequest{Conversation: conv, Message: m, IdempotencyKey: text})
		if e != nil || result.Outcome != tr.ACK {
			t.Fatal("fixture send", result, e)
		}
		return string(result.Event)
	}
	sync := func() tr.Batch {
		t.Helper()
		b, e := s.Sync(ctx)
		if e != nil || len(b.Events) != 0 {
			t.Fatal("sync", e)
		}
		return b
	}
	pending := func() []nostrsession.Record {
		t.Helper()
		var rows []nostrsession.Record
		stop := errors.New("no receipt")
		if e := s.ReadInbox(ctx, 50, func(r []nostrsession.Record) error { rows = r; return stop }); e != stop {
			t.Fatal(e)
		}
		return rows
	}
	replyConv, e := s.Conversation(ctx, []tr.PrincipalID{tr.PrincipalID(renter.PubKeyHex())}, "")
	if e != nil {
		t.Fatal(e)
	}
	reply := tr.SendRequest{Conversation: replyConv, Message: tr.Message{Text: "reply"}, IdempotencyKey: "reply-stable"}
	refuse := func(req tr.SendRequest, reason string) {
		t.Helper()
		calls := r.Calls()
		if _, e := s.Send(ctx, req); e == nil || e.Error() != "admission: "+reason {
			t.Fatal("unexpected refusal", e)
		}
		if r.Calls() != calls {
			t.Fatal("refused send reached relay")
		}
	}
	refuse(reply, "no_grant")
	post("absent", nil)
	sync()
	if len(pending()) != 0 {
		t.Fatal("absent grant delivered")
	}
	post("expired", carrier(expiredProof))
	sync()
	if len(pending()) != 0 {
		t.Fatal("expired grant delivered")
	}
	refuse(reply, "no_grant")
	// Duplicate certificate keys are visible to AL2 even though the outer
	// transport envelope map is already decoded (the latter is the separate SJ1).
	for i, raw := range []string{`{"version":0,"\u0076ersion":3}`, `{"\u0076ersion":3,"version":0}`} {
		post("duplicate-"+string(rune('a'+i)), fx.Carrier(t, strings.Repeat("a", 64), []byte(raw)))
	}
	body, _ := json.Marshal(map[string]any{"v": 1, "text": "wrong grantee", "extensions": map[string]json.RawMessage{nt.GrantExtension: carrier(proof)}})
	fx.Inject(t, r.URL, outsider, agent.PubKeyHex(), "", body)
	fx.Inject(t, r.URL, outsider, agent.PubKeyHex(), renter.PubKeyHex(), body)
	fx.Misroute(t, r.URL, renter, agent.PubKeyHex(), outsider.PubKeyHex())
	b := sync()
	if b.Dropped < 2 || len(pending()) != 0 {
		t.Fatal("forgery/wrong grantee/duplicate reached ordinary inbox")
	}
	st, e := s.Status(ctx)
	if e != nil || st.Counts["invalid_presentation"] != 2 || st.Counts["binding_mismatch"] != 1 {
		t.Fatal("closed rejection counts", st.Counts, e)
	}
	liveID := post("live", carrier(proof))
	sync()
	rows := pending()
	if len(rows) != 1 || rows[0].ID != liveID || rows[0].Sender != renter.PubKeyHex() {
		t.Fatal("live grantee not delivered")
	}
	raw, _ := json.Marshal(rows)
	if strings.Contains(string(raw), "grant_id") || strings.Contains(string(raw), l.issuerPub) {
		t.Fatal("proof leaked")
	}
	// A restart must retain both the ordinary mailbox and the real admitted
	// public proof cache; the next send still performs fresh Core validation.
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = nostrsession.Open(ctx, base, "station")
	if e != nil {
		t.Fatal(e)
	}
	if len(pending()) != 1 {
		t.Fatal("mailbox lost at restart")
	}
	replyConv, e = s.Conversation(ctx, []tr.PrincipalID{tr.PrincipalID(renter.PubKeyHex())}, "")
	if e != nil {
		t.Fatal(e)
	}
	reply.Conversation = replyConv
	result, e := s.Send(ctx, reply)
	if e != nil || result.Outcome != tr.ACK {
		t.Fatal("live reply", result, e)
	}
	group, e := s.Conversation(ctx, []tr.PrincipalID{tr.PrincipalID(renter.PubKeyHex()), tr.PrincipalID(outsider.PubKeyHex())}, "")
	if e != nil {
		t.Fatal(e)
	}
	refuse(tr.SendRequest{Conversation: group, Message: tr.Message{Text: "mixed"}, IdempotencyKey: "mixed"}, "no_grant")
	sync()
	if len(pending()) != 1 {
		t.Fatal("selfcopy surfaced as peer work")
	}
	l.revoke(seal)
	refuse(reply, "seal_spent") // retry of an ACK'd operation is checked again
	post("revoked", nil)
	sync()
	if len(pending()) != 1 {
		t.Fatal("revoked grantee delivered")
	}
	exchange, e := os.ReadFile(filepath.Join(root, "admission", "exchange.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	for _, reason := range []string{"no_grant", "expired", "seal_spent"} {
		if !strings.Contains(string(exchange), `"reason":"`+reason+`"`) {
			t.Fatal("missing closed exchange reason", reason)
		}
	}
	t.Log("genuine NIP17/issuer/Core: absent, expired, duplicate, wrong-grantee, forged-author, live, restart, mixed-recipient and revoked retry controls passed")
}
