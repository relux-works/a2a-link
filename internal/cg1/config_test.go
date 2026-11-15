package cg1

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/a2a-swarm/internal/admission"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

func configFixture(t *testing.T) (admission.Config, settings) {
	t.Helper()
	c := admission.Config{Identity: "alice", StateDir: stateDir(t), Nostr: true, NostrPubkey: xonly(3)}
	s := settings{grantPolicy: testGrantPolicy(t), Version: 1, AgentName: "id/test-agent", LandlordName: "id/test-landlord", IssuerPubkey: xonly(1), TimeoutMS: 100, RPC: su.Route{Host: "127.0.0.1", Port: 1, Username: "w3-observer", Password: strings.Repeat("fixture-only-", 2)}}
	return c, s
}
func provision(t *testing.T, c admission.Config, s settings) {
	t.Helper()
	if e := os.WriteFile(filepath.Join(c.StateDir, "cg1.json"), jsonBytes(t, s), 0600); e != nil {
		t.Fatal(e)
	}
}

// Registered Nostr-only factory reads only its private host-provisioned file;
// Matrix cannot construct it, and malformed routes/pins/files fail closed.
func TestFactoryAndConfig(t *testing.T) {
	f, ok := admission.Lookup(Policy)
	if !ok {
		t.Fatal("policy not registered")
	}
	for _, mode := range []string{"valid", "matrix", "missing", "mode", "symlink", "relative-symlink", "hardlink", "extra", "duplicate", "null", "oversize", "version", "timeout", "route", "key", "own-key", "state-link"} {
		t.Run(mode, func(t *testing.T) {
			c, s := configFixture(t)
			path := filepath.Join(c.StateDir, "cg1.json")
			switch mode {
			case "matrix":
				c.Nostr = false
			case "version":
				s.Version = 2
			case "timeout":
				s.TimeoutMS = 5001
			case "route":
				s.RPC.Username = "other"
			case "key":
				s.IssuerPubkey = "not-a-key"
			case "own-key":
				c.NostrPubkey = "claim"
			}
			provision(t, c, s)
			switch mode {
			case "missing":
				os.Remove(path)
			case "mode":
				os.Chmod(path, 0644)
			case "symlink":
				os.Rename(path, path+".target")
				os.Symlink(path+".target", path)
			case "relative-symlink":
				// os.Root resolves relative links internally: O_NOFOLLOW alone is insufficient.
				os.Rename(path, path+".target")
				os.Symlink("cg1.json.target", path)
			case "hardlink":
				os.Link(path, path+".alias")
			case "extra", "duplicate", "null":
				raw := jsonBytes(t, s)
				prefix := `{"extra":true,`
				if mode == "duplicate" {
					prefix = `{"version":1,`
				}
				if mode == "null" {
					prefix = `{"version":null,`
				}
				os.WriteFile(path, append([]byte(prefix), raw[1:]...), 0600)
			case "oversize":
				os.WriteFile(path, []byte(strings.Repeat(" ", 8193)), 0600)
			case "state-link":
				os.Symlink(stateDir(t), filepath.Join(c.StateDir, "cg1-state"))
			}
			ch, e := f(c)
			if mode == "valid" {
				if e != nil {
					t.Fatal(e)
				}
				defer ch.Close()
				d, e := ch.Inbound(context.Background(), incoming(ch.(*checker)))
				want(t, d, e, admission.Exchange, "no_grant", false)
			} else {
				if ch != nil || e == nil {
					t.Fatal("invalid configuration constructed policy")
				}
				if mode == "matrix" && e.Error() != "admission: nostr_required" {
					t.Fatal("capability gate missing")
				}
				if strings.Contains(e.Error(), s.RPC.Password) {
					t.Fatal("private configuration leaked")
				}
				if _, e := os.Stat(filepath.Join(c.StateDir, "cg1-state", "grantcheck.json")); !os.IsNotExist(e) {
					t.Fatal("rejected config wrote checker state")
				}
			}
		})
	}
}

// Trusted Nostr metadata survives private held serialization; nil retains the
// exact upstream JSON shape, so ordinary Matrix/none items acquire no new bytes.
func TestTrustedProjectionSerialization(t *testing.T) {
	old := `{"room":"","event_id":"","sender":"","kind":"","timestamp":0,"body":null}`
	b, _ := json.Marshal(admission.Inbound{})
	if string(b) != old {
		t.Fatalf("nil metadata changed bytes: %s", b)
	}
	c := &checker{own: xonly(3)}
	in := incoming(c)
	in.Nostr.Presentation = &admission.NostrPresentation{GrantID: "proof", Bytes: []byte("data")}
	b, _ = json.Marshal(in)
	var out admission.Inbound
	if json.Unmarshal(b, &out) != nil || out.Nostr == nil || out.Nostr.Sender != in.Nostr.Sender || out.Nostr.Recipient != c.own || out.Nostr.EventID != in.Nostr.EventID || !out.Nostr.Time.Equal(in.Nostr.Time) || string(out.Nostr.Presentation.Bytes) != "data" {
		t.Fatal("held projection lost")
	}
}
