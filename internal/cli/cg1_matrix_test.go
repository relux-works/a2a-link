package cli

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/a2a-swarm/internal/admission"
	"github.com/relux-works/a2a-swarm/internal/cg1cosign"
	"github.com/relux-works/a2a-swarm/internal/config"
	"github.com/relux-works/a2a-swarm/internal/matrix"
)

type refusingPeerAdmission struct{ in, out int }

func (p *refusingPeerAdmission) Inbound(context.Context, admission.Inbound) (admission.Decision, error) {
	p.in++
	return admission.Decision{Verdict: admission.Refused, Reason: "denied"}, nil
}
func (p *refusingPeerAdmission) Outbound(context.Context, admission.Outbound) (admission.Decision, error) {
	p.out++
	return admission.Decision{Verdict: admission.Refused, Reason: "denied"}, nil
}
func (p *refusingPeerAdmission) Close() error { return nil }

// Proves protected owner DM bypasses refusing peer admission in both directions, while a foreign sender/room or forged flag reaches the peer refusal.
func TestCG1MatrixOwnerDMBypass(t *testing.T) {
	e, c, _ := ownerActiveFixture(t)
	a := NewApp()
	a.Stdout, a.Stderr = io.Discard, io.Discard
	a.Getenv = func(k string) string {
		if k == config.EnvConfigDir {
			return e.dir
		}
		return ""
	}
	a.as = "bob"
	a.HTTP = e.hs.srv.Client()
	s, err := a.session()
	if err != nil {
		t.Fatal(err)
	}
	defer a.closeAdmission()
	peer := &refusingPeerAdmission{}
	s.admission = &identityAdmission{checker: peer, ownerBypass: s.ownerAdmissionBypass}
	ctx := context.Background()
	incoming := admission.Inbound{RoomID: c.Room, Sender: c.Owner, Body: []byte(`{"body":"owner message without envelope"}`)}
	d, err := s.admission.Inbound(ctx, incoming)
	if err != nil || d.Verdict != admission.Live || peer.in != 0 {
		t.Fatal("owner inbound was gated", d, err)
	}
	outgoing := admission.Outbound{Identity: s.name, RoomID: c.Room, Request: []byte(`{"body":"owner reply without envelope"}`)}
	d, err = s.admission.Outbound(ctx, outgoing)
	if err != nil || d.Verdict != admission.Live || peer.out != 0 {
		t.Fatal("owner outbound was gated", d, err)
	}
	incoming.Sender = "@mallory:" + testServer
	incoming.Body = []byte(`{"owner":true,"admission_bypass":true}`)
	d, err = s.admission.Inbound(ctx, incoming)
	if err != nil || d.Verdict != admission.Refused || peer.in != 1 {
		t.Fatal("foreign sender bypassed admission", d, err)
	}
	outgoing.RoomID = "!not-owner:test.local"
	d, err = s.admission.Outbound(ctx, outgoing)
	if err != nil || d.Verdict != admission.Refused || peer.out != 1 {
		t.Fatal("foreign room bypassed admission", d, err)
	}
	// A current third participant closes even the formerly pinned owner's route.
	e.hs.mu.Lock()
	e.hs.rooms[c.Room].members["@mallory:"+testServer] = "join"
	e.hs.mu.Unlock()
	incoming.Sender = c.Owner
	d, err = s.admission.Inbound(ctx, incoming)
	if err != nil || d.Verdict != admission.Refused || peer.in != 2 {
		t.Fatal("changed owner audience bypassed admission", d, err)
	}
}

// Proves the optional fork carrier preserves exact envelope bytes and the co-signature object, and refuses malformed/ambiguous modes before sending.
func TestCG1MatrixCosignatureCarrier(t *testing.T) {
	e, room := world(t)
	e.as("alice", "topic", "new", room, "cg1-carrier", "Carrier").ok(t)
	envelope := []byte(envelopeCLIJSON)
	co, err := cg1cosign.FixtureSign(envelope, "alice")
	if err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(t.TempDir(), "envelope.json")
	coFile := filepath.Join(t.TempDir(), "cosignature.json")
	if err = os.WriteFile(envFile, envelope, 0600); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(co)
	if err = os.WriteFile(coFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	r := e.as("alice", "post", room, "--topic", "cg1-carrier", "--envelope", "@"+envFile, "--cg1-cosignature", "@"+coFile, "hello").ok(t)
	id := strings.TrimSpace(r.stdout)
	e.hs.mu.Lock()
	var content json.RawMessage
	for _, ev := range e.hs.events {
		if ev.EventID == id {
			content = ev.Content
		}
	}
	e.hs.mu.Unlock()
	var object map[string]any
	if json.Unmarshal(content, &object) != nil {
		t.Fatal("missing sent event")
	}
	raw, err := matrix.DecodeEnvelope(object[matrix.EnvelopeContentKey].(string))
	if err != nil || string(raw) != string(envelope) {
		t.Fatal("envelope bytes changed")
	}
	if _, err = (cg1cosign.BIP340{}).Verify(raw, object[cg1cosign.ContentKey]); err != nil {
		t.Fatal("co-signature carriage changed", err)
	}
	before := e.eventCount()
	for _, args := range [][]string{
		{"--cg1-cosignature", "@" + coFile},
		{"--envelope", "@" + envFile, "--cg1-cosignature", coFile},
		{"--envelope", "@" + envFile, "--cg1-cosignature", "@" + coFile, "--cg1-cosignature", "@" + coFile},
	} {
		argv := append([]string{"post", room, "--topic", "cg1-carrier"}, args...)
		argv = append(argv, "hello")
		e.as("alice", argv...).failsWith(t, ExitUsage, "--cg1-cosignature")
	}
	if err = os.WriteFile(coFile, []byte(`{"key":"one","key":"two"}`), 0600); err != nil {
		t.Fatal(err)
	}
	e.as("alice", "post", room, "--topic", "cg1-carrier", "--envelope", "@"+envFile, "--cg1-cosignature", "@"+coFile, "hello").failsWith(t, ExitError, "cosignature_malformed")
	if e.eventCount() != before {
		t.Fatal("invalid co-signature carriage sent an event")
	}
}
