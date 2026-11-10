package cg1

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	tn "github.com/relux-works/a2a-transport-nostr/nostr"
	nr "github.com/relux-works/a2a-transport-nostr/relay"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/a2a-swarm/internal/al3smoke"
	"github.com/relux-works/a2a-swarm/internal/nostrsession"
	fx "github.com/relux-works/a2a-swarm/internal/nostrtest"
	tr "github.com/relux-works/a2a-swarm/transport"
	nt "github.com/relux-works/a2a-transport-nostr/nostrtransport"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	gn "github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

// Two fresh real-Core runs provision reciprocal grants via authentic NIP17 and
// production CG1 Sync, then exchange through two OS workers and pinned swarma-relay.
// No cache seeding, policy-none session, injected checker or remote host is used.
func TestCoreAL3TwoProcess(t *testing.T) {
	if os.Getenv("AL3_LOCAL") != "1" {
		t.Skip("requires explicit isolated AL3 local binaries/Core")
	}
	root := os.Getenv("CG1_RUN_ROOT")
	if !filepath.IsAbs(root) {
		t.Fatal("absolute run root")
	}
	var normalized []byte
	for _, label := range []string{"first", "second"} {
		t.Run(label, func(t *testing.T) {
			t.Setenv("CG1_RUN_ROOT", root+"-"+label)
			got := al3Run(t)
			if normalized == nil {
				normalized = got
			} else if !bytes.Equal(normalized, got) {
				t.Fatal("fresh run normalized results differ")
			}
		})
	}
}
func al3Binary(t *testing.T, name string) string {
	t.Helper()
	p := os.Getenv(name)
	want := os.Getenv(name + "_SHA256")
	b, e := os.ReadFile(p)
	if !filepath.IsAbs(p) || len(want) != 64 || e != nil || rental.Hash(b) != want {
		t.Fatal("pinned local binary required", name)
	}
	return p
}
func al3Start(t *testing.T, cmd *exec.Cmd, logPath string) func() error {
	t.Helper()
	f, e := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	cmd.Stdout = f
	cmd.Stderr = f
	if e = cmd.Start(); e != nil {
		f.Close()
		t.Fatal(e)
	}
	fx.Write(t, logPath+".pid", []byte(fmt.Sprint(cmd.Process.Pid)))
	t.Logf("AL3 process pid=%d image=%s", cmd.Process.Pid, filepath.Base(cmd.Path))
	done := make(chan error, 1)
	go func() { done <- cmd.Wait(); f.Close() }()
	var waited bool
	var result error
	wait := func() error {
		if !waited {
			result = <-done
			waited = true
		}
		return result
	}
	t.Cleanup(func() {
		if !waited {
			_ = cmd.Process.Signal(os.Interrupt)
			select {
			case result = <-done:
				waited = true
			case <-time.After(5 * time.Second):
				_ = cmd.Process.Kill()
				result = <-done
				waited = true
			}
		}
	})
	return wait
}
func al3Run(t *testing.T) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	a, b, outsider := fx.Key(t), fx.Key(t), fx.Key(t)
	const nameB = "id/swarma-al3-b"
	l := newCoreLabAgents(t, a.PubKeyHex(), map[string]string{nameB: b.PubKeyHex()})
	lb := *l
	lb.agentName = nameB
	lb.agentNostrPub = b.PubKeyHex()
	grantKey := func(k []byte) *gn.PrivKey {
		v, e := gn.PrivKeyFromBytes(k)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	proofForA := lb.grantAt(grantKey(a.Bytes()), "al3-a", lb.seal(), true, time.Now().Unix())
	proofForB := l.grantAt(grantKey(b.Bytes()), "al3-b", l.seal(), true, time.Now().Unix())
	carrier := func(raw []byte) json.RawMessage {
		id, e := kernel.PresentationID(raw)
		if e != nil {
			t.Fatal(e)
		}
		return fx.Carrier(t, id, raw)
	}
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	addr := listener.Addr().String()
	listener.Close()
	url := "ws://" + addr
	cfg := map[string]any{"state_dir": filepath.Join(l.root, "relay-state"), "public_url": url, "trusted_proxy_ip": "", "require_write_auth": false, "require_read_auth": false, "restrict_gift_wrap_reads": false, "unknown_pow_bits": 0, "known_pubkeys": []string{}, "max_event_bytes": 65536, "max_events": 1024, "max_store_bytes": 32 << 20, "retention_seconds": 7 * 86400, "future_seconds": 300, "max_connections": 32, "max_connections_per_ip": 32, "max_ips": 1024, "frames_per_minute": 10000, "frames_per_ip_minute": 100000, "subscriptions": 8, "queue": 64, "backlog": 32}
	configPath := filepath.Join(l.root, "relay.json")
	fx.Write(t, configPath, jsonBytes(t, cfg))
	relayCmd := exec.Command(al3Binary(t, "AL3_RELAY_BINARY"), "-config", configPath, "-listen", addr)
	al3Start(t, relayCmd, filepath.Join(l.root, "relay.log"))
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, e := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if e == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("relay readiness timeout")
		}
		time.Sleep(20 * time.Millisecond)
	}
	baseA, baseB := filepath.Join(l.root, "peer-a"), filepath.Join(l.root, "peer-b")
	provision := func(base string, key interface{ Hex() string }, proof []byte, agent string) string {
		root := nostrsession.Root(base, "station")
		routes, _ := json.Marshal([]string{url})
		settings := map[string]string{}
		for _, n := range []string{"read_relays", "write_relays", "dm_relays", "discovery_relays"} {
			settings[n] = string(routes)
		}
		fx.Write(t, filepath.Join(root, "session.json"), jsonBytes(t, map[string]any{"version": 1, "admission_policy": "cg1", "settings": settings, "presentation": carrier(proof)}))
		fx.Write(t, filepath.Join(root, "transport", "identity.key"), []byte(key.Hex()+"\n"))
		fx.Write(t, filepath.Join(root, "admission", "cg1.json"), jsonBytes(t, struct {
			Version      int    `json:"version"`
			AgentName    string `json:"agent_name"`
			LandlordName string `json:"landlord_name"`
			IssuerPubkey string `json:"issuer_pubkey"`
			TimeoutMS    int    `json:"timeout_ms"`
			RPC          any    `json:"rpc"`
		}{1, agent, e2eLandlordName, l.issuerPub, 5000, l.route}))
		return root
	}
	rootA := provision(baseA, a, proofForA, e2eAgentName)
	provision(baseB, b, proofForB, nameB)
	sa, e := nostrsession.Open(ctx, baseA, "station")
	if e != nil {
		t.Fatal(e)
	}
	defer sa.Close()
	sb, e := nostrsession.Open(ctx, baseB, "station")
	if e != nil {
		t.Fatal(e)
	}
	defer sb.Close()
	// Existing authenticated provisioning path. Raw adapters carry actual signed
	// proofs over NIP17; only production Session.Sync can populate CG1 admission.
	rawA := fx.Adapter(t, filepath.Join(l.private, "bootstrap-a"), url, a)
	rawB := fx.Adapter(t, filepath.Join(l.private, "bootstrap-b"), url, b)
	post := func(raw *nt.Adapter, peer, text string, p json.RawMessage) string {
		conv, e := raw.ConversationFor([]tr.PrincipalID{tr.PrincipalID(peer)}, "")
		if e != nil {
			t.Fatal(e)
		}
		msg := tr.Message{Text: text, To: []tr.PrincipalID{tr.PrincipalID(peer)}}
		if p != nil {
			msg.Extensions = map[string]json.RawMessage{nt.GrantExtension: p}
		}
		r, e := raw.Send(ctx, tr.SendRequest{Conversation: conv, Message: msg, IdempotencyKey: text})
		if e != nil || r.Outcome != tr.ACK {
			t.Fatal("bootstrap send failed", e, r.Outcome)
		}
		return string(r.Event)
	}
	pending := func(s *nostrsession.Session) int {
		st, e := s.Status(ctx)
		if e != nil {
			t.Fatal(e)
		}
		return st.Pending
	}
	sync := func(s *nostrsession.Session) tr.Batch {
		batch, e := s.Sync(ctx)
		if e != nil {
			t.Fatal(e)
		}
		return batch
	}
	// Fresh guarded outbound must refuse before the authenticated bootstrap.
	for _, p := range []struct {
		s    *nostrsession.Session
		peer string
	}{{sa, b.PubKeyHex()}, {sb, a.PubKeyHex()}} {
		conv, e := p.s.Conversation(ctx, []tr.PrincipalID{tr.PrincipalID(p.peer)}, "")
		if e != nil {
			t.Fatal(e)
		}
		if _, e = p.s.Send(ctx, tr.SendRequest{Conversation: conv, Message: tr.Message{Text: "premature"}, IdempotencyKey: "premature"}); e == nil || e.Error() != "admission: no_grant" {
			t.Fatal("fresh session bypass", e)
		}
	}
	// Non-admitted sender is held in the exchange lane, never ordinary output.
	rawO := fx.Adapter(t, filepath.Join(l.private, "outsider"), url, outsider)
	outsiderID := post(rawO, a.PubKeyHex(), "outsider", nil)
	sync(sa)
	st, e := sa.Status(ctx)
	if e != nil || st.Pending != 0 || st.Counts["no_grant"] != 1 {
		t.Fatal("outsider not refused/held", e)
	}
	exchangeRaw, err := os.ReadFile(filepath.Join(rootA, "admission", "exchange.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var exchange struct {
		EventID string `json:"event_id"`
		Sender  string `json:"sender"`
		Reason  string `json:"reason"`
	}
	if json.Unmarshal(bytes.TrimSpace(exchangeRaw), &exchange) != nil || exchange.EventID != outsiderID || exchange.Sender != outsider.PubKeyHex() || exchange.Reason != "no_grant" {
		t.Fatal("outsider exchange evidence missing")
	}
	idA := post(rawB, a.PubKeyHex(), "provision-a", carrier(proofForB))
	idB := post(rawA, b.PubKeyHex(), "provision-b", carrier(proofForA))
	sync(sa)
	sync(sb)
	for _, p := range []struct {
		s        *nostrsession.Session
		id, peer string
	}{{sa, idA, b.PubKeyHex()}, {sb, idB, a.PubKeyHex()}} {
		if pending(p.s) != 1 {
			t.Fatal("reciprocal real CG1 provisioning failed")
		}
		if e := p.s.ReadInbox(ctx, 50, func(rows []nostrsession.Record) error {
			if len(rows) != 1 || rows[0].ID != p.id || rows[0].Sender != p.peer {
				t.Fatal("wrong provisioning tuple")
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
	}
	// Replay of an already accepted logical operation cannot refill a receipted inbox.
	if idA != post(rawB, a.PubKeyHex(), "provision-a", carrier(proofForB)) {
		t.Fatal("replay changed event")
	}
	sync(sa)
	if pending(sa) != 0 {
		t.Fatal("replay redelivered")
	}
	// Send the identical signed wrap onto the actual wire again; a cached
	// adapter ACK alone would not exercise relay replay handling.
	journal, err := os.ReadFile(filepath.Join(l.private, "bootstrap-b", "seam-send", rental.Hash([]byte("provision-a"))+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var sent struct {
		Parts map[string]struct {
			Wrap *tn.Event `json:"wrap"`
		} `json:"parts"`
	}
	if json.Unmarshal(journal, &sent) != nil || sent.Parts[a.PubKeyHex()].Wrap == nil {
		t.Fatal("replay fixture wrap absent")
	}
	wire := &nr.Client{URL: url}
	reply, err := wire.Publish(ctx, sent.Parts[a.PubKeyHex()].Wrap)
	wire.Close()
	if err != nil || !reply.Stored() {
		t.Fatal("actual relay replay not acknowledged")
	}
	sync(sa)
	if pending(sa) != 0 {
		t.Fatal("wire replay redelivered")
	}
	// Wrong recipient and forged rumor author have valid signed outer envelopes;
	// transport drops them before CG1 while the ordinary mailbox remains empty.
	fx.Misroute(t, url, b, a.PubKeyHex(), outsider.PubKeyHex())
	batch := sync(sa)
	if batch.Dropped != 1 || pending(sa) != 0 {
		t.Fatal("wrong-recipient not dropped")
	}
	body := []byte(`{"v":1,"text":"forged"}`)
	fx.Inject(t, url, b, a.PubKeyHex(), outsider.PubKeyHex(), body)
	batch = sync(sa)
	if batch.Dropped != 2 || pending(sa) != 0 {
		t.Fatal("forged author not independently dropped")
	}

	rawA.Close()
	rawB.Close()
	rawO.Close()
	sa.Close()
	sb.Close()
	worker := al3Binary(t, "AL3_WORKER_BINARY")
	runID := "0123456789abcdef"
	waits := []func() error{}
	for _, p := range []struct{ role, base, peer string }{{"b", baseB, a.PubKeyHex()}, {"a", baseA, b.PubKeyHex()}} {
		cmd := exec.CommandContext(ctx, worker, "-config-root", p.base, "-identity", "station", "-peer", p.peer, "-relay", url, "-role", p.role, "-run-id", runID, "-timeout", "60s", "-output", filepath.Join(l.root, p.role+"-output.jsonl"))
		// Worker HOME/cwd/temp/config are isolated per identity; no ambient host dirs.
		cmd.Dir = p.base
		cmd.Env = append([]string{}, os.Environ()...)
		for _, n := range []string{"home", "tmp", "config", "cache"} {
			if e := os.MkdirAll(filepath.Join(p.base, n), 0700); e != nil {
				t.Fatal(e)
			}
		}
		cmd.Env = append(cmd.Env, "HOME="+filepath.Join(p.base, "home"), "USERPROFILE="+filepath.Join(p.base, "home"), "TMPDIR="+filepath.Join(p.base, "tmp"), "TMP="+filepath.Join(p.base, "tmp"), "TEMP="+filepath.Join(p.base, "tmp"), "XDG_CONFIG_HOME="+filepath.Join(p.base, "config"), "XDG_CACHE_HOME="+filepath.Join(p.base, "cache"))
		waits = append(waits, al3Start(t, cmd, filepath.Join(l.root, p.role+"-worker.log")))
	}
	for _, wait := range waits {
		if e := wait(); e != nil {
			t.Fatal("worker failed; private logs retained", e)
		}
	}
	// Validate IDs across opposite workers before replacing random keys/IDs/URLs
	// with role names. Normalization never discards missing or duplicate events.
	result := al3Normalize(t, l.root, a.PubKeyHex(), b.PubKeyHex(), url, runID)
	// Separate malicious-response fixture: not the real relay positive lane.
	// It cannot create admission: a valid neighbor still carries the real issued proof.
	body, _ = json.Marshal(map[string]any{"v": 1, "text": "malicious-relay-valid-neighbor", "to": []string{a.PubKeyHex()}, "extensions": map[string]json.RawMessage{nt.GrantExtension: carrier(proofForB)}})
	rumor, err := tn.BuildRumor(b, []string{a.PubKeyHex(), b.PubKeyHex()}, tn.KindRumor, string(body), tn.RumorOptions{}, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	seal, err := tn.SealRumor(b, rumor, a.PubKeyHex(), time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	wrap, err := tn.WrapSeal(seal, a.PubKeyHex(), time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	forged := *wrap
	forged.Sig = strings.Repeat("0", 128)
	mockURL := al3MaliciousRelay(t, &forged, wrap, wrap)
	baseM := filepath.Join(l.root, "malicious-fixture-peer")
	rootM := provision(baseM, a, proofForA, e2eAgentName)
	cfgRaw, err := os.ReadFile(filepath.Join(rootM, "session.json"))
	if err != nil {
		t.Fatal(err)
	}
	var maliciousConfig map[string]any
	if json.Unmarshal(cfgRaw, &maliciousConfig) != nil {
		t.Fatal("fixture config")
	}
	routeJSON, _ := json.Marshal([]string{mockURL})
	routesM := map[string]string{}
	for _, n := range []string{"read_relays", "write_relays", "dm_relays", "discovery_relays"} {
		routesM[n] = string(routeJSON)
	}
	maliciousConfig["settings"] = routesM
	fx.Write(t, filepath.Join(rootM, "session.json"), jsonBytes(t, maliciousConfig))
	sm, err := nostrsession.Open(ctx, baseM, "station")
	if err != nil {
		t.Fatal(err)
	}
	defer sm.Close()
	maliciousBatch := sync(sm)
	if maliciousBatch.Dropped < 1 || pending(sm) != 1 {
		t.Fatal("malicious forged/duplicate response escaped")
	}
	var delivered []nostrsession.Record
	if err = sm.ReadInbox(ctx, 50, func(rows []nostrsession.Record) error { delivered = rows; return nil }); err != nil || len(delivered) != 1 || delivered[0].ID != rumor.ID || delivered[0].Sender != b.PubKeyHex() {
		t.Fatal("malicious fixture valid neighbor missing")
	}
	sync(sm)
	if pending(sm) != 0 {
		t.Fatal("duplicate response redelivered after receipt")
	}
	sm.Close()

	fx.Write(t, filepath.Join(l.root, "normalized.json"), result)
	proofs := map[string]any{"a": map[string]string{"presentation_sha256": rental.Hash(proofForA), "grantee": a.PubKeyHex()}, "b": map[string]string{"presentation_sha256": rental.Hash(proofForB), "grantee": b.PubKeyHex()}, "negative_controls": []string{"fresh-outbound:no_grant", "outsider:no_grant", "replay:no-mailbox", "wrong-recipient:dropped", "forged-rumor:dropped", "malicious-relay:forged-signature-dropped", "malicious-relay:duplicate-frame-deduplicated"}}
	fx.Write(t, filepath.Join(l.root, "public-evidence.json"), jsonBytes(t, proofs))
	return result
}
func al3Normalize(t *testing.T, root, a, b, url, runID string) []byte {
	t.Helper()
	all := map[string][]al3smoke.Evidence{}
	for _, role := range []string{"a", "b"} {
		raw, e := os.ReadFile(filepath.Join(root, role+"-output.jsonl"))
		if e != nil {
			t.Fatal(e)
		}
		for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
			var row al3smoke.Evidence
			if json.Unmarshal(line, &row) != nil {
				t.Fatal("output JSON")
			}
			all[role] = append(all[role], row)
		}
	}
	result, e := al3smoke.Normalize(all["a"], all["b"], a, b, url, runID)
	if e != nil {
		t.Fatal("transcript invariant failed")
	}
	return append(result, '\n')
}

// An explicitly adversarial WebSocket fixture sends forged and duplicate EVENT
// responses. It is not substituted for swarma-relay in the positive smoke.
func al3MaliciousRelay(t *testing.T, events ...*tn.Event) string {
	t.Helper()
	upgrade := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, e := upgrade.Upgrade(w, r, nil)
		if e != nil {
			return
		}
		defer c.Close()
		for {
			var frame []json.RawMessage
			if c.ReadJSON(&frame) != nil {
				return
			}
			if len(frame) < 2 {
				continue
			}
			var kind, id string
			_ = json.Unmarshal(frame[0], &kind)
			_ = json.Unmarshal(frame[1], &id)
			if kind != "REQ" {
				continue
			}
			for _, event := range events {
				if c.WriteJSON([]any{"EVENT", id, event}) != nil {
					return
				}
			}
			if c.WriteJSON([]any{"EOSE", id}) != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)
	return "ws" + strings.TrimPrefix(server.URL, "http")
}
