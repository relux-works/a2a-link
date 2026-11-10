// Package nostrtest provides real loopback NIP-17 fixtures for session and CLI
// tests. It generates disposable keys; no production code imports this package.
package nostrtest

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	tr "github.com/relux-works/a2a-swarm/transport"
	"github.com/relux-works/a2a-transport-nostr/nostr"
	nt "github.com/relux-works/a2a-transport-nostr/nostrtransport"
	"github.com/relux-works/a2a-transport-nostr/relay"
	"github.com/relux-works/a2a-transport-nostr/testrelay"
)

func Root(t *testing.T) string {
	t.Helper()
	p, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(p, 0700); e != nil {
		t.Fatal(e)
	}
	return p
}
func Key(t *testing.T) *nostr.PrivKey {
	t.Helper()
	k, e := nostr.GeneratePrivKey()
	if e != nil {
		t.Fatal(e)
	}
	return k
}
func Relay(t *testing.T) *testrelay.Relay {
	t.Helper()
	r, e := testrelay.StartWithOptions(testrelay.Options{TrueDuplicate: true})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(r.Close)
	return r
}
func Settings(url string) map[string]string {
	b, _ := json.Marshal([]string{url})
	return map[string]string{"read_relays": string(b)}
}
func Write(t *testing.T, path string, raw []byte) {
	t.Helper()
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
}
func Provision(t *testing.T, base, name, url, policy string, key *nostr.PrivKey, grant json.RawMessage) string {
	t.Helper()
	root := filepath.Join(base, "nostr", name)
	cfg := map[string]any{"version": 1, "admission_policy": policy, "settings": Settings(url)}
	if grant != nil {
		cfg["presentation"] = grant
	}
	raw, e := json.Marshal(cfg)
	if e != nil {
		t.Fatal(e)
	}
	Write(t, filepath.Join(root, "session.json"), raw)
	Write(t, filepath.Join(root, "transport", "identity.key"), []byte(key.Hex()+"\n"))
	return root
}
func Adapter(t *testing.T, root, url string, key *nostr.PrivKey) *nt.Adapter {
	t.Helper()
	Write(t, filepath.Join(root, "identity.key"), []byte(key.Hex()+"\n"))
	a, e := nt.Open(tr.Config{StateDir: root, Settings: Settings(url)})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { a.Close() })
	return a
}
func Carrier(t *testing.T, id string, proof []byte) json.RawMessage {
	t.Helper()
	raw, e := nt.EncodeGrantPresentation(nt.GrantPresentationV1{Version: 1, GrantID: id, Bytes: proof})
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

// Inject encrypts and signs the supplied wire JSON using the actual primitives.
// A nonempty claim deliberately changes the rumor author under a valid seal.
func Inject(t *testing.T, url string, sender *nostr.PrivKey, recipient, claim string, body []byte) string {
	t.Helper()
	at := time.Now().Unix()
	rumor, e := nostr.BuildRumor(sender, []string{sender.PubKeyHex(), recipient}, nostr.KindRumor, string(body), nostr.RumorOptions{}, at)
	if e != nil {
		t.Fatal(e)
	}
	if claim != "" {
		rumor.PubKey = claim
		rumor.ID = rumor.ComputeID()
	}
	seal, e := nostr.SealRumor(sender, rumor, recipient, at)
	if e != nil {
		t.Fatal(e)
	}
	wrap, e := nostr.WrapSeal(seal, recipient, at)
	if e != nil {
		t.Fatal(e)
	}
	c := &relay.Client{URL: url}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ack, e := c.Publish(ctx, wrap)
	if e != nil || !ack.Accepted {
		t.Fatal("fixture publication refused", e)
	}
	return rumor.ID
}

// Misroute has a valid outer signature and the receiver's public p tag, but its
// ciphertext is for another key. Routing labels cannot substitute for decryption.
func Misroute(t *testing.T, url string, sender *nostr.PrivKey, recipient, encryptedFor string) {
	t.Helper()
	at := time.Now().Unix()
	rumor, e := nostr.BuildRumor(sender, []string{sender.PubKeyHex(), encryptedFor}, nostr.KindRumor, `{"v":1,"text":"wrong recipient"}`, nostr.RumorOptions{}, at)
	if e != nil {
		t.Fatal(e)
	}
	seal, e := nostr.SealRumor(sender, rumor, encryptedFor, at)
	if e != nil {
		t.Fatal(e)
	}
	key := Key(t)
	ck, e := nostr.ConversationKey(key, encryptedFor)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(seal)
	if e != nil {
		t.Fatal(e)
	}
	content, e := nostr.EncryptNIP44(string(raw), ck, [32]byte{})
	if e != nil {
		t.Fatal(e)
	}
	wrap := &nostr.Event{Kind: 1059, CreatedAt: at, Tags: [][]string{{"p", recipient}}, Content: content}
	if e = key.SignEvent(wrap); e != nil {
		t.Fatal(e)
	}
	c := &relay.Client{URL: url}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ack, e := c.Publish(ctx, wrap)
	if e != nil || !ack.Accepted {
		t.Fatal("misroute fixture publication", e)
	}
}
