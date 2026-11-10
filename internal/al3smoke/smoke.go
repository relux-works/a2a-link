// Package al3smoke runs a bounded exchange between two already provisioned CG1
// identities. It never creates custody, grants, admission cache or another transport.
package al3smoke

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/relux-works/a2a-swarm/internal/config"
	"github.com/relux-works/a2a-swarm/internal/nostrsession"
	tr "github.com/relux-works/a2a-swarm/transport"
	"github.com/relux-works/a2a-transport-nostr/relay"
)

var ErrSmoke = errors.New("al3: smoke refused")

type Options struct{ Base, Identity, Peer, Relay, Role, RunID string }

// Evidence contains only public smoke observations; no grant or RPC credentials.
type Evidence struct {
	Type      string              `json:"type"`
	Role      string              `json:"role"`
	ID        string              `json:"id,omitempty"`
	Sender    string              `json:"sender,omitempty"`
	Recipient string              `json:"recipient,omitempty"`
	Text      string              `json:"text,omitempty"`
	Routes    map[string][]string `json:"routes,omitempty"`
	Pending   int                 `json:"pending"`
}

func hexValue(v string, n int) bool {
	if len(v) != n {
		return false
	}
	for _, c := range v {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func (o Options) Validate() error {
	u, e := url.Parse(o.Relay)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "wss" && !(u.Scheme == "ws" && u.Hostname() == "127.0.0.1")) {
		return ErrSmoke
	}
	if !filepath.IsAbs(o.Base) || filepath.Clean(o.Base) != o.Base || config.ValidateName(o.Identity) != nil || !hexValue(o.Peer, 64) || !hexValue(o.RunID, 16) || (o.Role != "a" && o.Role != "b") {
		return ErrSmoke
	}
	return nil
}
func checkConfig(raw []byte, relayURL string) bool {
	var c struct {
		Policy       string            `json:"admission_policy"`
		Settings     map[string]string `json:"settings"`
		Presentation json.RawMessage   `json:"presentation"`
	}
	if json.Unmarshal(raw, &c) != nil || c.Policy != "cg1" || len(c.Presentation) == 0 || string(c.Presentation) == "null" {
		return false
	}
	for _, name := range []string{"read_relays", "write_relays", "dm_relays", "discovery_relays"} {
		var urls []string
		if json.Unmarshal([]byte(c.Settings[name]), &urls) != nil || len(urls) != 1 || urls[0] != relayURL {
			return false
		}
	}
	return true
}
func emit(out io.Writer, v Evidence) error {
	raw, e := json.Marshal(v)
	if e != nil {
		return ErrSmoke
	}
	raw = append(raw, '\n')
	n, e := out.Write(raw)
	if e != nil {
		return e
	}
	if n != len(raw) {
		return io.ErrShortWrite
	}
	return nil
}

// Run records callback output before Session.ReadInbox writes its receipt. The
// caller must make each successful Write durable (the CLI fsyncs every line).
// Failures preserve mailbox state and return a closed error, never raw custody.
func Run(ctx context.Context, o Options, out io.Writer) error {
	if o.Validate() != nil || out == nil || ctx == nil {
		return ErrSmoke
	}
	root := nostrsession.Root(o.Base, o.Identity)
	raw, e := os.ReadFile(filepath.Join(root, "session.json"))
	if e != nil || !checkConfig(raw, o.Relay) {
		return ErrSmoke
	}
	s, e := nostrsession.Open(ctx, o.Base, o.Identity)
	if e != nil {
		return ErrSmoke
	}
	defer s.Close()
	st, e := s.Status(ctx)
	if e != nil || st.Policy != "cg1" || st.Pending != 0 || s.Self() == o.Peer {
		return ErrSmoke
	}
	// Pinned v0.2.0 does not store discovery events. Confirm the precondition;
	// empty discovery uses existing configured-write fallback, not egress pinning.
	client := &relay.Client{URL: o.Relay}
	defer client.Close()
	found, e := client.Query(ctx, "al3-discovery", relay.Filter{Kinds: []int{10002, 10050}, Authors: []string{s.Self(), o.Peer}})
	if e != nil || len(found) != 0 {
		return ErrSmoke
	}
	if e = emit(out, Evidence{Type: "ready", Role: o.Role, Sender: s.Self(), Recipient: o.Peer}); e != nil {
		return ErrSmoke
	}
	conv, e := s.Conversation(ctx, []tr.PrincipalID{tr.PrincipalID(o.Peer)}, "")
	if e != nil {
		return ErrSmoke
	}
	ping, pong := "al3:"+o.RunID+":ping", "al3:"+o.RunID+":pong"
	send := func(text string) error {
		idempotency := text + ":" + o.Role
		result, e := s.Send(ctx, tr.SendRequest{Conversation: conv, Message: tr.Message{Kind: "al3-smoke", Text: text, To: []tr.PrincipalID{tr.PrincipalID(o.Peer)}}, IdempotencyKey: idempotency})
		if e != nil || result.Outcome != tr.ACK || !hexValue(string(result.Event), 64) {
			return ErrSmoke
		}
		routes, e := observedRoutes(root, idempotency, o.Relay, s.Self(), o.Peer)
		if e != nil {
			return ErrSmoke
		}
		return emit(out, Evidence{Type: "sent", Role: o.Role, ID: string(result.Event), Sender: s.Self(), Recipient: o.Peer, Text: text, Routes: routes})
	}
	if o.Role == "a" {
		if e = send(ping); e != nil {
			return ErrSmoke
		}
	}
	received := false
	for !received {
		if _, e = s.Sync(ctx); e != nil {
			return ErrSmoke
		}
		e = s.ReadInbox(ctx, 50, func(rows []nostrsession.Record) error {
			if len(rows) == 0 {
				return nil
			}
			if len(rows) != 1 {
				return ErrSmoke
			}
			want := ping
			if o.Role == "a" {
				want = pong
			}
			r := rows[0]
			if r.Sender != o.Peer || r.Text != want || r.Kind != "al3-smoke" || !hexValue(r.ID, 64) || r.Gap != "" || len(r.To) != 1 || string(r.To[0]) != s.Self() {
				return ErrSmoke
			}
			if e := emit(out, Evidence{Type: "received", Role: o.Role, ID: r.ID, Sender: r.Sender, Recipient: s.Self(), Text: r.Text}); e != nil {
				return e
			}
			received = true
			return nil
		})
		if e != nil {
			return ErrSmoke
		}
		if !received {
			select {
			case <-ctx.Done():
				return ErrSmoke
			case <-time.After(25 * time.Millisecond):
			}
		}
	}
	if o.Role == "b" {
		if e = send(pong); e != nil {
			return ErrSmoke
		}
	}
	st, e = s.Status(ctx)
	if e != nil || st.Pending != 0 {
		return ErrSmoke
	}
	return emit(out, Evidence{Type: "complete", Role: o.Role, Pending: st.Pending})
}

// Inspect the actual v0.3.0 send journal after ACK. This is an observation of
// selected destinations, not an allowlist or proof of arbitrary future egress.
func observedRoutes(root, idempotency, relayURL, self, peer string) (map[string][]string, error) {
	h := sha256.Sum256([]byte(idempotency))
	raw, e := os.ReadFile(filepath.Join(root, "transport", "seam-send", hex.EncodeToString(h[:])+".json"))
	if e != nil {
		return nil, ErrSmoke
	}
	var record struct {
		Parts map[string]struct {
			Relays []string `json:"relays"`
			Ack    bool     `json:"ack"`
		} `json:"parts"`
	}
	if json.Unmarshal(raw, &record) != nil || len(record.Parts) != 2 {
		return nil, ErrSmoke
	}
	routes := map[string][]string{}
	for p, v := range record.Parts {
		if (p != self && p != peer) || !v.Ack || len(v.Relays) != 1 || v.Relays[0] != relayURL {
			return nil, ErrSmoke
		}
		routes[p] = v.Relays
	}
	return routes, nil
}
