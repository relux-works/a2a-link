package cg1

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/relux-works/a2a-swarm/internal/admission"
	"github.com/relux-works/swarma-chain-lab/experiments/grantcheck"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernelbind"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

// The actual published CG1/K1, real issuer and isolated hash-pinned Core produce
// live permission only for the grantee; missing/expired/spent/wrong-grantee never
// permit a send. This tests the adapter foundation, not NIP-17 transport wiring.
func TestCoreAdmission(t *testing.T) {
	if os.Getenv("CG1_REGTEST") != "1" {
		t.Skip("requires isolated pinned Core")
	}
	agent, e := nostr.GeneratePrivKey()
	if e != nil {
		t.Fatal(e)
	}
	l := newCoreLab(t, agent.PubKeyHex())
	renter, e := nostr.GeneratePrivKey()
	if e != nil {
		t.Fatal(e)
	}
	seal := l.seal()
	raw := l.grant(renter, "adapter", seal, true)
	id, e := kernel.PresentationID(raw)
	if e != nil {
		t.Fatal(e)
	}
	// Independently construct the directly required published binding to confirm
	// the fixture is live, without pre-populating CG1's separate state/cache.
	kdir := filepath.Join(l.private, "kernel-control")
	if e = os.Mkdir(kdir, 0700); e != nil {
		t.Fatal(e)
	}
	k, e := kernelbind.New(l.observer, kdir, e2eAgentName, e2eLandlordName, l.issuerPub, "W")
	if e != nil {
		t.Fatal(e)
	}
	kr, e := k.Check(context.Background(), raw, e2eAgentName, renter.PubKeyHex(), 500)
	if e != nil || kr.Verdict != kernel.Live || kr.Reason != "LIVE" {
		t.Fatal("live kernel control", kr, e)
	}
	newAt := func(label string, now int64) *checker {
		dir := filepath.Join(l.private, label)
		if e = os.Mkdir(dir, 0700); e != nil {
			t.Fatal(e)
		}
		core, e := grantcheck.New(grantcheck.Config{ConstructionProfile: "W", Identity: label, AgentName: e2eAgentName, LandlordName: e2eLandlordName, IssuerPubkey: l.issuerPub, StateDir: dir, Node: l.observer, Now: func() time.Time { return time.Unix(now, 0) }})
		if e != nil {
			t.Fatal(e)
		}
		return &checker{core: core, identity: label, own: agent.PubKeyHex(), timeout: 5 * time.Second}
	}
	c := newAt("live", 500)
	in := incoming(c)
	in.Nostr.Sender = renter.PubKeyHex()
	out := admission.Outbound{Identity: c.identity, Nostr: &admission.TrustedNostrOutbound{Recipient: renter.PubKeyHex()}}
	d, e := c.Inbound(context.Background(), in)
	want(t, d, e, admission.Exchange, "no_grant", false)
	d, e = c.Outbound(context.Background(), out)
	want(t, d, e, admission.Refused, "no_grant", false)
	in.Nostr.Presentation = &admission.NostrPresentation{GrantID: id, Bytes: raw}
	d, e = c.Inbound(context.Background(), in)
	want(t, d, e, admission.Live, "live", false)
	d, e = c.Outbound(context.Background(), out)
	want(t, d, e, admission.Live, "live", false)
	wrong := *in.Nostr
	wrong.Sender = xonly(9)
	d, e = c.Inbound(context.Background(), admission.Inbound{Nostr: &wrong})
	want(t, d, e, admission.Refused, "binding_mismatch", false)
	expired := newAt("expired", 1000)
	d, e = expired.Inbound(context.Background(), in)
	want(t, d, e, admission.Exchange, "expired", false)
	l.revoke(seal)
	d, e = c.Outbound(context.Background(), out)
	want(t, d, e, admission.Refused, "seal_spent", false)
	in.Nostr.Presentation = nil
	d, e = c.Inbound(context.Background(), in)
	want(t, d, e, admission.Exchange, "seal_spent", false)
	t.Log("real issuer/Core: live inbound/outbound, absent, expired, wrong grantee and spent seal controls passed")
}
