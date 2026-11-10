package nostrsession

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	fx "github.com/relux-works/a2a-swarm/internal/nostrtest"
	tr "github.com/relux-works/a2a-swarm/transport"
)

// Signed/encrypted ambiguous envelopes are dropped before ordinary delivery.
// A plain-key neighbor with escaped string values survives sync and restart.
func TestTransportUpgradeInbound(t *testing.T) {
	w := newWorld(t)
	bad := []string{
		`{"v":1,"v":2,"text":"duplicate"}`,
		`{"v":2,"v":1,"text":"duplicate-reverse"}`,
		`{"\u0076":1,"text":"escaped-key"}`,
		`{"V":1,"text":"case-alias"}`,
		`{"v":1,"text":"nested","extensions":{"ordinary":{"x":1,"x":2}}}`,
	}
	for _, raw := range bad {
		fx.Inject(t, w.r.URL, w.peerKey, w.key.PubKeyHex(), "", []byte(raw))
	}
	good := fx.Inject(t, w.r.URL, w.peerKey, w.key.PubKeyHex(), "", []byte(`{"v":1,"text":"line\n<>&","extensions":{"<tag>&":{"<nested>&":"value"}}}`))
	b := syncSession(t, w.s)
	got := pending(t, w.s)
	if b.Dropped != len(bad) || len(got) != 1 || got[0].ID != good || got[0].Text != "line\n<>&" {
		t.Fatal("strict transport boundary admitted malformed traffic or lost valid neighbor")
	}
	w.restart(t)
	syncSession(t, w.s)
	if got := pending(t, w.s); len(got) != 1 || got[0].ID != good {
		t.Fatal("restart lost or duplicated valid neighbor")
	}
}

// The session's real adapter rejects ambiguous ordinary extensions without
// relay/journal effects. Legal HTML-sensitive keys round-trip and retry after
// restart; a corrupt retry journal refuses without rewriting it or the key.
func TestTransportUpgradeSendAndJournal(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	req := w.request(t, false)
	keyPath := filepath.Join(w.s.root, "transport", "identity.key")
	keyBefore, e := os.ReadFile(keyPath)
	if e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{`{"x":1,"x":2}`, `{"x":2,"x":1}`, `{"\u0078":1}`} {
		req.Message.Extensions = map[string]json.RawMessage{"ordinary": json.RawMessage(raw)}
		calls := w.r.Calls()
		if _, e := w.s.Send(ctx, req); tr.Code(e) != "invalid_reference" {
			t.Fatal("ambiguous ordinary extension accepted", e)
		}
		noSendEffects(t, w, calls)
	}
	value := json.RawMessage(`{"<nested>&":"line\n<>&"}`)
	req.Message.Extensions = map[string]json.RawMessage{"<tag>&": value}
	good, e := w.s.Send(ctx, req)
	if e != nil || good.Outcome != tr.ACK {
		t.Fatal("valid extension refused", e)
	}
	batch, e := w.peer.Sync(ctx, nil, tr.SyncOptions{Initial: true})
	if e != nil || len(batch.Events) != 1 || batch.Events[0].ID != good.Event || !bytes.Equal(batch.Events[0].Message.Extensions["<tag>&"], value) {
		t.Fatal("legal raw keys lost on wire", e)
	}
	dir := filepath.Join(w.s.root, "transport", "seam-send")
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 1 {
		t.Fatal("missing unique send journal", e)
	}
	path := filepath.Join(dir, entries[0].Name())
	original, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	w.restart(t)
	calls := w.r.Calls()
	again, e := w.s.Send(ctx, req)
	if e != nil || again.Outcome != tr.ACK || again.Event != good.Event || w.r.Calls() != calls {
		t.Fatal("restart retry changed event or republished", e)
	}
	corrupt := bytes.Replace(original, []byte(`"v":1`), []byte(`"v":1,"v":1`), 1)
	if bytes.Equal(corrupt, original) {
		t.Fatal("journal control not applied")
	}
	fx.Write(t, path, corrupt)
	got, e := w.s.Send(ctx, req)
	after, readErr := os.ReadFile(path)
	keyAfter, keyErr := os.ReadFile(keyPath)
	if e != nil || got.Outcome != tr.UNKNOWN || readErr != nil || keyErr != nil || w.r.Calls() != calls || !bytes.Equal(after, corrupt) || !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("corrupt journal retry published or altered durable state", e)
	}
	fx.Write(t, path, original)
	again, e = w.s.Send(ctx, req)
	if e != nil || again.Outcome != tr.ACK || again.Event != good.Event || w.r.Calls() != calls {
		t.Fatal("repaired journal cannot recover same ACK", e)
	}
}
