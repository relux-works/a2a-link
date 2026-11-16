//go:build darwin || linux

package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/a2a-swarm/internal/config"
	"github.com/relux-works/a2a-swarm/internal/e2ee"
)

const e2eeOwner = "@owner:test.local"

// e2eeWorld is a legacy file-backed identity whose config base stands in for an
// a2ad identity home: canonical, 0700 and test-owned. The custody gate seam
// admits it; the pin policy trusts the test UID under a fixture trust root.
type e2eeWorld struct {
	e       *env
	name    string
	mxid    string
	device  string
	owner   *e2ee.CrossSigning
	policy  e2ee.PinPolicy
	binding string
	pinPath string
	gated   bool
}

func newE2EEWorld(t *testing.T) *e2eeWorld {
	t.Helper()
	e := newEnv(t)
	canonical, err := filepath.EvalSymlinks(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	// t.TempDir() is 0755 under the usual umask; OpenFileStore requires the
	// custody parent (the a2ad identity home it stands in for) to be 0700.
	if err := os.Chmod(canonical, 0o700); err != nil {
		t.Fatal(err)
	}
	e.dir = canonical
	w := &e2eeWorld{e: e, name: "alice", device: "DEValice", gated: true}
	// The fake whoami answers device DEV<localpart>; the credential file must
	// name that exact device for the bootstrap binding check.
	uid, tok := e.hs.addUser(w.name)
	w.mxid = uid
	e.tokens[w.name] = tok
	p := config.Paths{Base: e.dir}
	if err := os.MkdirAll(filepath.Dir(p.AgentFile(w.name)), 0700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(config.Credentials{UserID: uid, AccessToken: tok, DeviceID: w.device, Homeserver: e.hs.srv.URL})
	if err := os.WriteFile(p.AgentFile(w.name), data, 0600); err != nil {
		t.Fatal(err)
	}
	trustRoot := filepath.Join(canonical, "trust")
	w.policy = e2ee.PinPolicy{Base: trustRoot, TrustedUID: os.Getuid()}
	w.binding = e2ee.LegacyBinding(e.hs.srv.URL, testServer, "file", "agents", w.mxid)
	inv := new(e2ee.Inventory)
	root, err := e2ee.NewRoot(e2ee.Pointer{Version: 1, Namespace: strings.Repeat("0", 64), Binding: e2ee.Binding{Binding: strings.Repeat("a", 64), Identity: e2eeOwner, Device: "OWNERDEV", Generation: strings.Repeat("b", 32)}}, inv)
	if err != nil {
		t.Fatal(err)
	}
	if w.owner, err = e2ee.DeriveCrossSigning(root, inv); err != nil {
		t.Fatal(err)
	}
	if w.pinPath, err = e2ee.PinPath(w.policy, w.binding, "agents", w.mxid, w.name); err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Dir(w.pinPath), 0700); err != nil {
		t.Fatal(err)
	}
	w.writePin(1, nil)
	e.configure = func(a *App) {
		a.e2eePinPolicy = &w.policy
		if w.gated {
			a.e2eeCustodyGate = func() error { return nil }
		}
	}
	return w
}

// writePin renders the host artifact from the generated owner keys. The CLI
// never writes it; only this fixture (standing in for root) does.
func (w *e2eeWorld) writePin(revision uint64, edit func(map[string]any)) {
	w.e.t.Helper()
	m, u := w.owner.Master(), w.owner.UserSigning()
	usk := e2ee.SignedKey{UserID: e2eeOwner, Usage: []string{e2ee.UsageUserSigning}, Keys: map[string]string{u.ID: u.Public}}
	signature, err := w.owner.SignAsMaster(usk)
	if err != nil {
		w.e.t.Fatal(err)
	}
	principal := map[string]any{
		"mxid": e2eeOwner, "master_key_id": m.ID, "master_public_key": m.Public, "master_sha256": m.SHA256,
		"user_signing_key_id": u.ID, "user_signing_public_key": u.Public, "user_signing_sha256": u.SHA256,
		"user_signing_master_signature": signature, "approved_devices": []string{"OWNERDEVICE"},
	}
	file := map[string]any{"v": 1, "binding": w.binding, "identity": w.mxid, "device_id": w.device, "revision": revision, "owner": e2eeOwner, "principals": []any{principal}}
	if edit != nil {
		edit(file)
	}
	raw, err := json.Marshal(file)
	if err != nil {
		w.e.t.Fatal(err)
	}
	if err = os.WriteFile(w.pinPath, raw, 0644); err != nil {
		w.e.t.Fatal(err)
	}
	if err = os.Chmod(w.pinPath, 0644); err != nil {
		w.e.t.Fatal(err)
	}
}

func (w *e2eeWorld) custodyRoot() string {
	return filepath.Join(w.e.dir, "e2ee-"+e2ee.TupleHash(w.mxid)[:32])
}

func (w *e2eeWorld) run(args ...string) result { return w.e.as(w.name, args...) }

// evidence runs identity show --json and decodes the public record.
func (w *e2eeWorld) evidence() e2ee.PublicIdentity {
	w.e.t.Helper()
	r := w.run("e2ee", "identity", "show", "--json").ok(w.e.t)
	var p e2ee.PublicIdentity
	if err := json.Unmarshal([]byte(r.stdout), &p); err != nil {
		w.e.t.Fatal(err, r.stdout)
	}
	return p
}

// storePassword plants the Q2 section the way registration wiring does.
func (w *e2eeWorld) storePassword(password string) {
	w.e.t.Helper()
	store, err := e2ee.OpenFileStore(w.custodyRoot())
	if err != nil {
		w.e.t.Fatal(err)
	}
	defer store.Close()
	lease, err := store.Lock(context.Background())
	if err != nil {
		w.e.t.Fatal(err)
	}
	defer lease.Close()
	if err = lease.CreatePassword(w.mxid, []byte(password), new(e2ee.Inventory)); err != nil {
		w.e.t.Fatal(err)
	}
}

func (w *e2eeWorld) readPassword(mxid string) ([]byte, error) {
	store, err := e2ee.OpenFileStore(filepath.Join(w.e.dir, "e2ee-"+e2ee.TupleHash(mxid)[:32]))
	if err != nil {
		return nil, err
	}
	defer store.Close()
	lease, err := store.Lock(context.Background())
	if err != nil {
		return nil, err
	}
	defer lease.Close()
	return lease.ReadPassword(mxid, new(e2ee.Inventory))
}

func (w *e2eeWorld) keyRequests() int {
	w.e.hs.mu.Lock()
	defer w.e.hs.mu.Unlock()
	n := 0
	for _, raw := range w.e.hs.rawURLs {
		if strings.Contains(raw, "/keys/") {
			n++
		}
	}
	return n
}

// ownerSign records the owner's USK signature over the published agent master,
// or a forged one under the same key ID when forged is set.
func (w *e2eeWorld) ownerSign(p e2ee.PublicIdentity, forged bool) {
	w.e.t.Helper()
	master := e2ee.SignedKey{UserID: p.MXID, Usage: []string{e2ee.UsageMaster}, Keys: map[string]string{p.Master.ID: p.Master.Public}}
	var signature string
	var err error
	if forged {
		signature, err = w.owner.SignAsMaster(master)
	} else {
		signature, err = w.owner.SignAsUser(master)
	}
	if err != nil {
		w.e.t.Fatal(err)
	}
	w.e.hs.signAgentMaster(p.MXID, e2eeOwner, w.owner.UserSigning().ID, signature)
}

func generatedPassword(t *testing.T) string {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	return "planted-" + hex.EncodeToString(raw[:]) + "-secret"
}

// Passwordless bootstrap: init persists roots and state, publishes the device
// keys with the SSK signature and the three cross-signing keys, stops at
// awaiting-owner with exit 0, prints only public evidence, and a repeated init
// or show reports exactly the same key IDs (no rotation).
func TestE2EEInitPasswordlessBootstrap(t *testing.T) {
	w := newE2EEWorld(t)
	if w.run("e2ee", "identity", "show").ok(t).stdout != "identity: "+w.mxid+"\ndevice: "+w.device+"\nstate: absent\n" {
		t.Fatal("absent evidence")
	}
	r := w.run("e2ee", "init").ok(t)
	for _, want := range []string{"identity: " + w.mxid, "device: " + w.device, "state: awaiting-owner", "pin_revision: 1", "owner: " + e2eeOwner, "master: ed25519:", "self_signing: ed25519:", "user_signing: ed25519:", "sha256:"} {
		if !strings.Contains(r.stdout, want) {
			t.Fatalf("missing %q in %s", want, r.stdout)
		}
	}
	for _, name := range []string{"generation.json", "secrets.json", "state.bin"} {
		if _, err := os.Stat(filepath.Join(w.custodyRoot(), name)); err != nil {
			t.Fatal("custody artifact", name, err)
		}
	}
	p := w.evidence()
	if p.State != e2ee.StateAwaitingOwner || p.PinRevision != 1 || p.Master.ID != "ed25519:"+p.Master.Public || p.Master.SHA256 == p.SelfSigning.SHA256 {
		t.Fatal("public evidence", p)
	}
	var master e2ee.SignedKey
	if json.Unmarshal(w.e.hs.publishedMaster(w.mxid), &master) != nil || master.Keys[p.Master.ID] != p.Master.Public {
		t.Fatal("published master differs from evidence")
	}
	var device e2ee.DeviceKeys
	if json.Unmarshal(w.e.hs.publishedDevice(w.mxid, w.device), &device) != nil || device.Signatures[w.mxid][p.SelfSigning.ID] == "" || device.Signatures[w.mxid]["ed25519:"+w.device] == "" {
		t.Fatal("published device lacks self or cross signature")
	}
	if auths, empty := w.e.hs.signingAuths(); len(auths) != 1 || auths[0] != "" || empty != 0 {
		t.Fatal("passwordless upload sent an auth stage", auths)
	}
	again := w.run("e2ee", "init", "--json").ok(t)
	var repeated e2ee.PublicIdentity
	if json.Unmarshal([]byte(again.stdout), &repeated) != nil || repeated.Master != p.Master || repeated.SelfSigning != p.SelfSigning || repeated.UserSigning != p.UserSigning || repeated.State != e2ee.StateAwaitingOwner {
		t.Fatal("repeated init rotated or regressed", again.stdout)
	}
	if auths, _ := w.e.hs.signingAuths(); len(auths) != 1 {
		t.Fatal("repeated init re-uploaded cross-signing keys")
	}
}

// Stored-password UIA: with the server demanding m.login.password and no Q2
// section, init stops at awaiting-uia (exit 1, keys persisted locally, nothing
// published, no empty password sent); control: once the section exists, init
// completes the stage with the stored password and publishes exactly the same
// key IDs, and the password never appears in any output.
func TestE2EEInitUIAFallback(t *testing.T) {
	w := newE2EEWorld(t)
	password := generatedPassword(t)
	w.e.hs.setPassword(w.mxid, password)
	w.e.hs.setE2EE(func(s *fakeE2EE) { s.uia = true })
	r := w.run("e2ee", "init").failsWith(t, ExitError, "e2ee: e2ee_uia_unavailable")
	if strings.Contains(r.stdout+r.stderr, password) {
		t.Fatal("password leaked")
	}
	if w.e.hs.publishedMaster(w.mxid) != nil {
		t.Fatal("awaiting-uia claimed an upload")
	}
	if _, err := os.Stat(filepath.Join(w.custodyRoot(), "state.bin")); err != nil {
		t.Fatal("local keys not persisted before upload", err)
	}
	pending := w.evidence()
	if pending.State != e2ee.StateAwaitingUIA {
		t.Fatal("state", pending.State)
	}
	if auths, empty := w.e.hs.signingAuths(); len(auths) != 1 || auths[0] != "" || empty != 0 {
		t.Fatal("UIA without a stored password sent a stage", auths, empty)
	}
	w.storePassword(password)
	r = w.run("e2ee", "init").ok(t)
	if strings.Contains(r.stdout+r.stderr, password) {
		t.Fatal("password leaked")
	}
	published := w.evidence()
	if published.State != e2ee.StateAwaitingOwner || published.Master != pending.Master || published.SelfSigning != pending.SelfSigning || published.UserSigning != pending.UserSigning {
		t.Fatal("resumed upload rotated keys", published, pending)
	}
	if auths, empty := w.e.hs.signingAuths(); len(auths) != 3 || auths[1] != "" || auths[2] != "m.login.password" || empty != 0 {
		t.Fatal("password fallback sequence", auths, empty)
	}
	if w.e.hs.publishedMaster(w.mxid) == nil {
		t.Fatal("cross-signing keys not published after UIA")
	}
}

// Wrong stored password: the server rejects the stage, init stays awaiting-uia
// and the rejected password is not printed; control: the right password works.
func TestE2EEInitUIARejectedPassword(t *testing.T) {
	w := newE2EEWorld(t)
	right, wrong := generatedPassword(t), generatedPassword(t)
	w.e.hs.setPassword(w.mxid, right)
	w.e.hs.setE2EE(func(s *fakeE2EE) { s.uia = true })
	w.run("e2ee", "init").failsWith(t, ExitError, "e2ee: e2ee_uia_unavailable")
	w.storePassword(wrong)
	r := w.run("e2ee", "init").failsWith(t, ExitError, "e2ee: e2ee_uia_unavailable")
	if strings.Contains(r.stdout+r.stderr, wrong) || w.e.hs.publishedMaster(w.mxid) != nil || w.evidence().State != e2ee.StateAwaitingUIA {
		t.Fatal("rejected password handling")
	}
	w.e.hs.setPassword(w.mxid, wrong)
	if w.run("e2ee", "init").ok(t); w.evidence().State != e2ee.StateAwaitingOwner {
		t.Fatal("control with matching password")
	}
}

// Owner verification: the owner's USK signature over the published master
// (as the Element ceremony records it) moves init to owner-verified and show
// re-verifies it after restart; beside it, a signature under the owner's MSK
// placed under the USK key ID refuses e2ee_owner_signature_invalid and the
// state stays awaiting-owner; an unsigned master stays awaiting-owner.
func TestE2EEOwnerVerification(t *testing.T) {
	t.Run("genuine", func(t *testing.T) {
		w := newE2EEWorld(t)
		w.run("e2ee", "init").ok(t)
		p := w.evidence()
		w.ownerSign(p, false)
		r := w.run("e2ee", "init").ok(t)
		if !strings.Contains(r.stdout, "state: owner-verified") {
			t.Fatal(r.stdout)
		}
		if shown := w.evidence(); shown.State != e2ee.StateOwnerVerified || shown.Master != p.Master {
			t.Fatal("show after restart", shown)
		}
		// A changed pin invalidates the cached verification: show reports changed.
		w.writePin(1, func(f map[string]any) {
			f["principals"].([]any)[0].(map[string]any)["approved_devices"] = []string{"OTHER"}
		})
		if w.evidence().State != e2ee.StateChanged {
			t.Fatal("changed pin still reported verified")
		}
	})
	t.Run("forged", func(t *testing.T) {
		w := newE2EEWorld(t)
		w.run("e2ee", "init").ok(t)
		w.ownerSign(w.evidence(), true)
		w.run("e2ee", "init").failsWith(t, ExitError, "e2ee: e2ee_owner_signature_invalid")
		if w.evidence().State != e2ee.StateAwaitingOwner {
			t.Fatal("forged signature changed state")
		}
	})
	t.Run("unsigned", func(t *testing.T) {
		w := newE2EEWorld(t)
		w.run("e2ee", "init").ok(t)
		if r := w.run("e2ee", "init").ok(t); !strings.Contains(r.stdout, "state: awaiting-owner") {
			t.Fatal(r.stdout)
		}
	})
}

// An interrupted cross-signing upload leaves local-ready; the next init
// re-uploads exactly the persisted public material (same key IDs, device keys
// not re-uploaded) and reaches awaiting-owner.
func TestE2EEInterruptedUploadResumesWithoutRotation(t *testing.T) {
	w := newE2EEWorld(t)
	w.e.hs.setE2EE(func(s *fakeE2EE) { s.failSigning = 1 })
	w.run("e2ee", "init").failsWith(t, ExitError, "e2ee: ")
	first := w.evidence()
	if first.State != e2ee.StateLocalReady || w.e.hs.publishedMaster(w.mxid) != nil || w.e.hs.publishedDevice(w.mxid, w.device) == nil {
		t.Fatal("interrupted state", first.State)
	}
	uploads := w.e.hs.CallCount("POST /_matrix/client/v3/keys/upload")
	w.run("e2ee", "init").ok(t)
	second := w.evidence()
	if second.State != e2ee.StateAwaitingOwner || second.Master != first.Master || second.SelfSigning != first.SelfSigning || second.UserSigning != first.UserSigning {
		t.Fatal("resume rotated keys")
	}
	if w.e.hs.CallCount("POST /_matrix/client/v3/keys/upload") != uploads {
		t.Fatal("device keys re-uploaded on resume")
	}
}

// Published conflicts: keys already published for this device or user without
// local state require explicit recovery and create no custody; a different
// master published after local bootstrap enters changed and stays there.
func TestE2EEPublishedConflicts(t *testing.T) {
	t.Run("recovery-required", func(t *testing.T) {
		w := newE2EEWorld(t)
		w.e.hs.plantDeviceKeys(w.mxid, w.device, json.RawMessage(`{"user_id":"`+w.mxid+`","device_id":"`+w.device+`","keys":{}}`))
		w.run("e2ee", "init").failsWith(t, ExitError, "e2ee: e2ee_recovery_required")
		if _, err := os.Stat(filepath.Join(w.custodyRoot(), "generation.json")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("recovery refusal minted a generation", err)
		}
	})
	t.Run("conflicting-master", func(t *testing.T) {
		w := newE2EEWorld(t)
		w.e.hs.setE2EE(func(s *fakeE2EE) { s.failSigning = 1 })
		w.run("e2ee", "init").failsWith(t, ExitError, "e2ee: ")
		other := e2ee.SignedKey{UserID: w.mxid, Usage: []string{e2ee.UsageMaster}, Keys: map[string]string{w.owner.Master().ID: w.owner.Master().Public}}
		raw, _ := json.Marshal(other)
		w.e.hs.plantMaster(w.mxid, raw)
		w.run("e2ee", "init").failsWith(t, ExitError, "e2ee: e2ee_published_conflict")
		if w.evidence().State != e2ee.StateChanged {
			t.Fatal("conflict did not enter changed")
		}
		// Even with the conflicting key withdrawn, changed is sticky in U2a.
		w.e.hs.setE2EE(func(s *fakeE2EE) { delete(s.master, w.mxid) })
		w.run("e2ee", "init").failsWith(t, ExitError, "e2ee: e2ee_trust_changed")
	})
}

// Pin gates: an agent-writable pin refuses before any key request; after
// bootstrap, the same revision with changed bytes and a decreasing revision
// enter changed, which is sticky even when the original bytes return.
func TestE2EEPinChanges(t *testing.T) {
	t.Run("agent-writable", func(t *testing.T) {
		w := newE2EEWorld(t)
		if err := os.Chmod(w.pinPath, 0666); err != nil {
			t.Fatal(err)
		}
		w.run("e2ee", "init").failsWith(t, ExitError, "e2ee: e2ee_pin_unsafe")
		if w.keyRequests() != 0 {
			t.Fatal("unsafe pin still reached the key endpoints")
		}
		if _, err := os.Stat(w.custodyRoot()); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("unsafe pin created custody")
		}
	})
	t.Run("same-revision-changed-bytes", func(t *testing.T) {
		w := newE2EEWorld(t)
		w.run("e2ee", "init").ok(t)
		w.writePin(1, func(f map[string]any) {
			f["principals"].([]any)[0].(map[string]any)["approved_devices"] = []string{"OTHER"}
		})
		w.run("e2ee", "init").failsWith(t, ExitError, "e2ee: e2ee_trust_changed")
		if w.evidence().State != e2ee.StateChanged {
			t.Fatal("not changed")
		}
		w.writePin(1, nil)
		w.run("e2ee", "init").failsWith(t, ExitError, "e2ee: e2ee_trust_changed")
	})
	t.Run("decreasing-revision", func(t *testing.T) {
		w := newE2EEWorld(t)
		w.writePin(2, nil)
		w.run("e2ee", "init").ok(t)
		w.writePin(1, nil)
		w.run("e2ee", "init").failsWith(t, ExitError, "e2ee: e2ee_trust_changed")
	})
	t.Run("absent", func(t *testing.T) {
		w := newE2EEWorld(t)
		if err := os.Remove(w.pinPath); err != nil {
			t.Fatal(err)
		}
		w.run("e2ee", "init").failsWith(t, ExitError, "e2ee: e2ee_pin_unavailable")
	})
}

// Custody outside a2ad: the real service-user gate refuses on this host, init
// creates nothing and sends no key request; control: the gated world initializes.
func TestE2EECustodyOutsideA2ad(t *testing.T) {
	if err := e2eeServiceUserCheck(); err == nil {
		t.Skip("test runs as the a2ad service user; the outside-a2ad negative needs another UID")
	} else if err != e2ee.ErrCustodyUnavailable {
		t.Fatal("gate code", err)
	}
	w := newE2EEWorld(t)
	w.gated = false
	w.run("e2ee", "init").failsWith(t, ExitError, "e2ee: e2ee_custody_unavailable")
	w.run("e2ee", "identity", "show").failsWith(t, ExitError, "e2ee: e2ee_custody_unavailable")
	if _, err := os.Stat(w.custodyRoot()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("custody created outside a2ad")
	}
	if w.keyRequests() != 0 {
		t.Fatal("key requests without custody")
	}
	w.gated = true
	w.run("e2ee", "init").ok(t)
}

// Q2 wiring: legacy registration under a2ad custody stores the generated
// password in the fixed create-only section before registering, the server
// receives that exact password and no output contains it; control: outside
// a2ad registration keeps its previous behavior and creates no custody.
func TestE2EERegistrationStoresPassword(t *testing.T) {
	w := newE2EEWorld(t)
	w.e.run("register", "bob").ok(t)
	bob := "@bob:" + testServer
	stored, err := w.readPassword(bob)
	if err != nil {
		t.Fatal("password section", err)
	}
	w.e.hs.mu.Lock()
	registered := w.e.hs.passwords[bob]
	w.e.hs.mu.Unlock()
	if string(stored) != registered || len(stored) < 16 {
		t.Fatal("stored password differs from the registered one")
	}
	w.gated = false
	w.e.run("register", "carol").ok(t)
	if _, err := os.Stat(filepath.Join(w.e.dir, "e2ee-"+e2ee.TupleHash("@carol:" + testServer)[:32])); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("custody created outside a2ad")
	}
}

// Scrubbing: a planted stored password never appears in stdout or stderr of
// init or show, on the success path and on the rejected-UIA error path.
func TestE2EEScrubsStoredPassword(t *testing.T) {
	w := newE2EEWorld(t)
	marker := generatedPassword(t)
	w.e.hs.setE2EE(func(s *fakeE2EE) { s.uia = true })
	w.e.hs.setPassword(w.mxid, "another-"+marker)
	w.run("e2ee", "init").failsWith(t, ExitError, "e2ee: e2ee_uia_unavailable")
	w.storePassword(marker)
	for _, args := range [][]string{{"e2ee", "init"}, {"e2ee", "identity", "show"}, {"e2ee", "identity", "show", "--json"}} {
		r := w.run(args...)
		if strings.Contains(r.stdout, marker) || strings.Contains(r.stderr, marker) {
			t.Fatalf("%v leaked the stored password", args)
		}
	}
	w.e.hs.setPassword(w.mxid, marker)
	r := w.run("e2ee", "init").ok(t)
	if strings.Contains(r.stdout, marker) || strings.Contains(r.stderr, marker) {
		t.Fatal("success path leaked the stored password")
	}
}

// Usage: unknown verbs and human accounts are usage errors before any effect.
func TestE2EEUsage(t *testing.T) {
	w := newE2EEWorld(t)
	w.run("e2ee").failsWith(t, ExitUsage, "usage: a2a e2ee")
	w.run("e2ee", "rotate").failsWith(t, ExitUsage, "usage: a2a e2ee")
	w.run("e2ee", "identity").failsWith(t, ExitUsage, "usage: a2a e2ee")
	if _, err := os.Stat(w.custodyRoot()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("usage error created custody")
	}
}
