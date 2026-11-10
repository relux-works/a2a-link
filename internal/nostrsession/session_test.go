package nostrsession

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/a2a-swarm/internal/admission"
	"github.com/relux-works/a2a-swarm/internal/config"
	fx "github.com/relux-works/a2a-swarm/internal/nostrtest"
	tr "github.com/relux-works/a2a-swarm/transport"
	"github.com/relux-works/a2a-transport-nostr/nostr"
	nt "github.com/relux-works/a2a-transport-nostr/nostrtransport"
	"github.com/relux-works/a2a-transport-nostr/testrelay"
)

type world struct {
	base                   string
	r                      *testrelay.Relay
	s                      *Session
	peer                   *nt.Adapter
	key, peerKey, otherKey *nostr.PrivKey
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{base: fx.Root(t), r: fx.Relay(t), key: fx.Key(t), peerKey: fx.Key(t), otherKey: fx.Key(t)}
	fx.Provision(t, w.base, "alice", w.r.URL, "none", w.key, nil)
	w.restart(t)
	w.peer = fx.Adapter(t, filepath.Join(w.base, "peer"), w.r.URL, w.peerKey)
	return w
}
func (w *world) restart(t *testing.T) {
	t.Helper()
	if w.s != nil {
		if e := w.s.Close(); e != nil {
			t.Fatal(e)
		}
	}
	s, e := Open(context.Background(), w.base, "alice")
	if e != nil {
		t.Fatal(e)
	}
	w.s = s
	t.Cleanup(func() { s.Close() })
}
func (w *world) post(t *testing.T, text string, proof json.RawMessage) string {
	t.Helper()
	c, e := w.peer.ConversationFor([]tr.PrincipalID{tr.PrincipalID(w.key.PubKeyHex())}, "")
	if e != nil {
		t.Fatal(e)
	}
	m := tr.Message{Text: text, Kind: "request"}
	if proof != nil {
		m.Extensions = map[string]json.RawMessage{nt.GrantExtension: proof}
	}
	r, e := w.peer.Send(context.Background(), tr.SendRequest{Conversation: c, Message: m, IdempotencyKey: text})
	if e != nil || r.Outcome != tr.ACK {
		t.Fatal("positive peer send", r, e)
	}
	return string(r.Event)
}
func (w *world) request(t *testing.T, group bool) tr.SendRequest {
	t.Helper()
	ps := []tr.PrincipalID{tr.PrincipalID(w.peerKey.PubKeyHex())}
	if group {
		ps = append(ps, tr.PrincipalID(w.otherKey.PubKeyHex()))
	}
	c, e := w.s.Conversation(context.Background(), ps, "")
	if e != nil {
		t.Fatal(e)
	}
	return tr.SendRequest{Conversation: c, IdempotencyKey: "stable", Message: tr.Message{Text: "ordinary"}}
}
func pending(t *testing.T, s *Session) []Record {
	t.Helper()
	var records []Record
	stop := errors.New("leave pending")
	e := s.ReadInbox(context.Background(), 50, func(r []Record) error { records = r; return stop })
	if e != stop {
		t.Fatal(e)
	}
	return records
}
func syncSession(t *testing.T, s *Session) tr.Batch {
	t.Helper()
	b, e := s.Sync(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if len(b.Events) != 0 || len(b.Invites) != 0 {
		t.Fatal("unadmitted payload escaped Sync")
	}
	return b
}

type spy struct {
	in         []admission.Inbound
	out        []admission.Outbound
	inDecision admission.Decision
	deny       string
	entered    chan struct{}
}

func (p *spy) Inbound(_ context.Context, in admission.Inbound) (admission.Decision, error) {
	p.in = append(p.in, in)
	return p.inDecision, nil
}
func (p *spy) Outbound(ctx context.Context, out admission.Outbound) (admission.Decision, error) {
	p.out = append(p.out, out)
	if p.entered != nil {
		close(p.entered)
		<-ctx.Done()
		return admission.Decision{}, ctx.Err()
	}
	if out.Nostr.Recipient == p.deny {
		return admission.Decision{Verdict: admission.Refused, Reason: "seal_spent"}, nil
	}
	return admission.Decision{Verdict: admission.Live, Reason: "allowed"}, nil
}
func (*spy) Close() error { return nil }
func useSpy(s *Session) *spy {
	p := &spy{inDecision: admission.Decision{Verdict: admission.Live, Reason: "allowed"}}
	s.policy.Close()
	s.policy = p
	return p
}
func noSendEffects(t *testing.T, w *world, calls int) {
	t.Helper()
	if w.r.Calls() != calls {
		t.Fatal("rejected send reached relay")
	}
	entries, e := os.ReadDir(filepath.Join(w.s.root, "transport", "seam-send"))
	if e != nil || len(entries) != 0 {
		t.Fatal("rejected send created signing journal", e)
	}
}

// A wiring spy tests selection/timing only (not CG1 correctness): any rejected
// group member prevents all relay/journal work; the same retry rechecks policy.
func TestEveryTargetAndRetryGuarded(t *testing.T) {
	w := newWorld(t)
	p := useSpy(w.s)
	req := w.request(t, true)
	p.deny = w.otherKey.PubKeyHex()
	calls := w.r.Calls()
	if _, e := w.s.Send(context.Background(), req); e == nil || e.Error() != "admission: seal_spent" {
		t.Fatal("mixed group not rejected", e)
	}
	noSendEffects(t, w, calls)
	p.deny = ""
	p.out = nil
	r, e := w.s.Send(context.Background(), req)
	if e != nil || r.Outcome != tr.ACK {
		t.Fatal("valid group", r, e)
	}
	got := map[string]bool{}
	for _, v := range p.out {
		got[v.Nostr.Recipient] = true
	}
	if len(p.out) != 2 || !got[w.peerKey.PubKeyHex()] || !got[w.otherKey.PubKeyHex()] || got[w.key.PubKeyHex()] {
		t.Fatal("external target set wrong")
	}
	calls = w.r.Calls()
	p.deny = w.peerKey.PubKeyHex()
	p.out = nil
	if _, e := w.s.Send(context.Background(), req); e == nil || e.Error() != "admission: seal_spent" {
		t.Fatal("ACK retry bypassed admission", e)
	}
	if w.r.Calls() != calls || len(p.out) == 0 {
		t.Fatal("retry not guarded")
	}
}

// UNKNOWN retries recheck before consulting/publishing the transport journal.
func TestUnknownRetryGuarded(t *testing.T) {
	w := newWorld(t)
	p := useSpy(w.s)
	req := w.request(t, false)
	w.r.SetRecipientMode(w.peerKey.PubKeyHex(), "after-submit")
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	r, e := w.s.Send(ctx, req)
	if e != nil || r.Outcome != tr.UNKNOWN {
		t.Fatal("expected uncertain real publication", r, e)
	}
	w.r.SetRecipientMode(w.peerKey.PubKeyHex(), "")
	p.deny = w.peerKey.PubKeyHex()
	calls := w.r.Calls()
	if _, e := w.s.Send(context.Background(), req); e == nil || e.Error() != "admission: seal_spent" {
		t.Fatal("UNKNOWN retry bypassed check", e)
	}
	if w.r.Calls() != calls {
		t.Fatal("revoked retry reached relay")
	}
	p.deny = ""
	r, e = w.s.Send(context.Background(), req)
	if e != nil || r.Outcome != tr.ACK {
		t.Fatal("valid retry cannot recover", r, e)
	}
}

// Explicit To subsets check only actual external targets. Nonmembers, media and
// user-authored host grant overrides fail before any transport publication.
func TestTargetSubsetAndClosedOperations(t *testing.T) {
	w := newWorld(t)
	p := useSpy(w.s)
	req := w.request(t, true)
	for i, change := range []func(*tr.SendRequest){
		func(r *tr.SendRequest) { r.Message.To = []tr.PrincipalID{tr.PrincipalID(fx.Key(t).PubKeyHex())} },
		func(r *tr.SendRequest) { r.Message.Attachments = []tr.MediaRef{tr.NewMediaRef("forbidden")} },
		func(r *tr.SendRequest) {
			r.Message.Extensions = map[string]json.RawMessage{nt.GrantExtension: fx.Carrier(t, strings.Repeat("a", 64), []byte(`{}`))}
		},
	} {
		q := req
		change(&q)
		calls := w.r.Calls()
		if _, e := w.s.Send(context.Background(), q); e == nil || e.Error() != []string{"nostr: invalid_recipient", ErrUnsupported.Error(), ErrPresentation.Error()}[i] {
			t.Fatal("unsupported send accepted or wrong refusal", e)
		}
		noSendEffects(t, w, calls)
	}
	p.deny = w.otherKey.PubKeyHex()
	req.Message.To = []tr.PrincipalID{tr.PrincipalID(w.peerKey.PubKeyHex()), tr.PrincipalID(w.peerKey.PubKeyHex())}
	r, e := w.s.Send(context.Background(), req)
	if e != nil || r.Outcome != tr.ACK || len(p.out) != 1 || p.out[0].Nostr.Recipient != w.peerKey.PubKeyHex() {
		t.Fatal("subset check mismatch", r, e)
	}
}

// Only the authenticated own-key copy is bookkeeping. A signed external peer
// addressing this identity still reaches admission with the verified tuple.
func TestTrustedTupleSelfCopyAndForgery(t *testing.T) {
	w := newWorld(t)
	p := useSpy(w.s)
	req := w.request(t, false)
	if r, e := w.s.Send(context.Background(), req); e != nil || r.Outcome != tr.ACK {
		t.Fatal(e)
	}
	syncSession(t, w.s)
	if len(p.in) != 0 || len(pending(t, w.s)) != 0 {
		t.Fatal("self copy admitted")
	}
	id := w.post(t, "external to self", fx.Carrier(t, strings.Repeat("a", 64), []byte(`{"certificate":"untrusted"}`)))
	fx.Inject(t, w.r.URL, w.peerKey, w.key.PubKeyHex(), w.otherKey.PubKeyHex(), []byte(`{"v":1,"text":"forged author"}`))
	fx.Misroute(t, w.r.URL, w.peerKey, w.key.PubKeyHex(), w.otherKey.PubKeyHex())
	b := syncSession(t, w.s)
	if b.Dropped < 2 || len(p.in) != 1 {
		t.Fatal("forged author reached admission or valid neighbor missing")
	}
	n := p.in[0].Nostr
	if n == nil || n.Sender != w.peerKey.PubKeyHex() || n.Recipient != w.key.PubKeyHex() || n.EventID != id || n.Time.IsZero() || n.Time.UnixMilli() != p.in[0].Timestamp {
		t.Fatal("trusted tuple incorrectly mapped")
	}
	rows := pending(t, w.s)
	if len(rows) != 1 || rows[0].ID != id || rows[0].Sender != n.Sender {
		t.Fatal("wrong ordinary mailbox")
	}
	raw, _ := json.Marshal(rows)
	if strings.Contains(string(raw), "certificate") || strings.Contains(string(raw), "grant") {
		t.Fatal("grant leaked into ordinary inbox")
	}
}

// A crash before append leaves the cursor untouched; a crash after append
// replays safely after restart, without losing or duplicating an ordinary event.
func TestMailboxBeforeCursorAndReceipt(t *testing.T) {
	for _, stage := range []string{"before", "after"} {
		t.Run(stage, func(t *testing.T) {
			w := newWorld(t)
			id := w.post(t, "durable "+stage, nil)
			injected := errors.New("append interruption")
			if stage == "before" {
				w.s.beforeAppend = func() error { return injected }
			} else {
				w.s.afterAppend = func() error { return injected }
			}
			if _, e := w.s.Sync(context.Background()); e != injected {
				t.Fatal("fault did not occur", e)
			}
			st, e := config.LoadState(w.s.paths, w.s.name)
			if e != nil || st.NextBatch != "" {
				t.Fatal("cursor advanced before durable processing", e)
			}
			rows := pending(t, w.s)
			want := 0
			if stage == "after" {
				want = 1
			}
			if len(rows) != want {
				t.Fatal("wrong crash mailbox", len(rows))
			}
			w.restart(t)
			syncSession(t, w.s)
			rows = pending(t, w.s)
			if len(rows) != 1 || rows[0].ID != id {
				t.Fatal("restart lost/duplicated event")
			}
			w.restart(t)
			if !reflect.DeepEqual(rows, pending(t, w.s)) {
				t.Fatal("output failure lost pending data")
			}
			if e := w.s.ReadInbox(context.Background(), 50, func(got []Record) error {
				if !reflect.DeepEqual(rows, got) {
					t.Fatal("receipt output changed")
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
			w.restart(t)
			syncSession(t, w.s)
			if len(pending(t, w.s)) != 0 {
				t.Fatal("receipt lost on restart")
			}
		})
	}
}

// Retryable rejection is private/durable, and its verified tuple is rechecked
// on a later empty sync before one ordinary delivery; exchange never delivers.
func TestHeldAndExchangeNeverEscape(t *testing.T) {
	w := newWorld(t)
	p := useSpy(w.s)
	p.inDecision = admission.Decision{Verdict: admission.Refused, Retryable: true, Reason: "dependency_unavailable"}
	id := w.post(t, "held", nil)
	syncSession(t, w.s)
	if len(pending(t, w.s)) != 0 {
		t.Fatal("held exposed")
	}
	w.restart(t)
	p = useSpy(w.s)
	syncSession(t, w.s)
	rows := pending(t, w.s)
	if len(rows) != 1 || rows[0].ID != id || len(p.in) != 1 || p.in[0].Nostr.Recipient != w.s.Self() {
		t.Fatal("held lost authenticated tuple")
	}
	p.inDecision = admission.Decision{Verdict: admission.Exchange, Reason: "no_grant"}
	w.post(t, "exchange", nil)
	syncSession(t, w.s)
	if len(pending(t, w.s)) != 1 {
		t.Fatal("exchange exposed")
	}
	raw, e := os.ReadFile(filepath.Join(w.s.root, "admission", "exchange.jsonl"))
	if e != nil || !strings.Contains(string(raw), `"reason":"no_grant"`) {
		t.Fatal("exchange not persisted", e)
	}
}

// Close cancels an in-flight check and forbids publication and later operations;
// host config changes also fail closed rather than changing a live policy.
func TestCloseAndConfigChangeFailClosed(t *testing.T) {
	w := newWorld(t)
	p := useSpy(w.s)
	req := w.request(t, false)
	p.entered = make(chan struct{})
	done := make(chan error, 1)
	calls := w.r.Calls()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _, e := w.s.Send(ctx, req); done <- e }()
	select {
	case <-p.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("check not entered")
	}
	closed := make(chan error, 1)
	go func() { closed <- w.s.Close() }()
	select {
	case e := <-closed:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		cancel()
		<-done
		<-closed
		t.Fatal("Close did not cancel check")
	}
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("cancelled send accepted")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not cancel check")
	}
	noSendEffects(t, w, calls)
	if _, e := w.s.Sync(context.Background()); e != ErrUnavailable {
		t.Fatal("closed session usable")
	}
	w.restart(t)
	raw, e := os.ReadFile(filepath.Join(w.s.root, "session.json"))
	if e != nil {
		t.Fatal(e)
	}
	fx.Write(t, filepath.Join(w.s.root, "session.json"), append(raw, ' '))
	if _, e := w.s.Send(context.Background(), req); e != ErrConfiguration {
		t.Fatal("changed config silently accepted")
	}
	noSendEffects(t, w, calls)
}
