package originproducer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/a2a-swarm/internal/cg1cosign"
	"github.com/relux-works/a2a-swarm/internal/matrix"
	"github.com/relux-works/a2a-swarm/runorigin"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-envelope/record"
)

func compositionJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func compositionEdID(key ed25519.PrivateKey) string {
	return "ed25519:" + base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
}

func compositionSign(t *testing.T, key ed25519.PrivateKey, body map[string]any) []byte {
	t.Helper()
	kind, author := body["type"].(string), compositionEdID(key)
	id, err := record.ContentID(kind, body)
	if err != nil {
		t.Fatal(err)
	}
	preimage, err := record.SigningPreimage(kind, author, "author", body)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := record.Canonical(map[string]any{"version": "swarm-envelope/2", "body": body, "id": id, "signatures": []any{map[string]any{"role": "author", "key": author, "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, preimage))}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// compositionGrant is cryptographically signed public fixture data, not a claim
// that its issuance or identities exist on a chain.
func compositionGrant(t *testing.T, now time.Time) []byte {
	t.Helper()
	seed := make([]byte, 32)
	seed[31] = 5
	issuer, _ := btcec.PrivKeyFromBytes(seed)
	sign := func(digest string) string {
		raw, err := hex.DecodeString(digest)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := schnorr.Sign(issuer, raw)
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(sig.Serialize())
	}
	seed[31] = 2
	renter, err := nostr.PrivKeyFromBytes(seed)
	if err != nil {
		t.Fatal(err)
	}
	hash := rental.Hash(payTerms(t))
	consent := nostr.Event{CreatedAt: now.Unix() - 10, Kind: 8181, Tags: [][]string{{"t", "swarma-rental-consent-v1"}, {"contract", hash}, {"booking", strings.Repeat("b", 64)}, {"privacy", strings.Repeat("c", 64)}}}
	if err = renter.SignEvent(&consent); err != nil {
		t.Fatal(err)
	}
	var event rental.Event
	if err = json.Unmarshal(compositionJSON(t, consent), &event); err != nil {
		t.Fatal(err)
	}
	grant := rental.Grant{Version: 3, Network: "regtest", Genesis: su.RegtestGenesis, AgentName: "id/test-agent", LandlordName: "id/test-landlord", IssuerKey: xonlyKey(5), GranteeKey: xonlyKey(2), ContractSHA256: hash, Scope: []string{"deliver", "pay"}, NotBefore: now.Unix() - 10, NotAfter: now.Unix() + 300, Seal: rental.Point{TxID: strings.Repeat("d", 64)}, Consent: rental.GrantConsent{ContractSHA256: hash, ConsentEvent: event, LandlordSig: sign(hash)}}
	digest, err := grant.SigningHash()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := rental.PresentIssuedGrant(compositionJSON(t, rental.SignedGrant{Grant: grant, Signature: sign(digest)}), strings.Repeat("e", 64))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func compositionPolicy(t *testing.T, f *fixture, host string, port int, now time.Time) map[string]any {
	t.Helper()
	key := func(seed byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32)) }
	receiver, sender, root, revoker := key(10), key(11), key(20), key(21)
	encode := base64.RawURLEncoding.EncodeToString
	attestations, generations, attIDs := map[string]any{}, map[string]any{}, map[string]string{}
	for i, signer := range []ed25519.PrivateKey{receiver, sender} {
		binding := map[string]any{"owner": "fixture-owner", "path": "fixture/message", "generation": "g1", "registration_number": int64(i + 1), "master_epoch": "epoch-1", "uid": int64(1000 + i)}
		body := map[string]any{"type": "attestation/1", "issuer": compositionEdID(root), "subject": map[string]any{"algorithm": "Ed25519", "key_id": compositionEdID(signer), "public_bytes": encode(signer.Public().(ed25519.PublicKey))}, "key_class": "agent", "purpose": "swarma-msg", "roles": []any{"author"}, "actions": []any{"message.sign"}, "iat": now.Add(-time.Minute).Format(time.RFC3339), "exp": now.Add(time.Hour).Format(time.RFC3339), "binding": binding}
		id, err := record.ContentID("attestation/1", body)
		if err != nil {
			t.Fatal(err)
		}
		attIDs[compositionEdID(signer)] = id
		attestations[id] = encode(compositionSign(t, root, body))
		active := map[string]any{"active": true}
		for name, value := range binding {
			active[name] = value
		}
		generations[compositionEdID(signer)] = active
	}
	snapshot := compositionSign(t, revoker, map[string]any{"type": "revocation/1", "issuer": compositionEdID(revoker), "issued_at": now.Format(time.RFC3339), "complete": true, "entries": []any{}})
	evidence := map[string]any{"service_root": map[string]any{"key": compositionEdID(root), "purpose": int64(5)}, "agent_revocation_root": map[string]any{"key": compositionEdID(revoker), "purpose": "registry-revocation", "attestation_root": compositionEdID(root)}, "attestations": attestations, "active_generations": generations, "revocations": map[string]any{compositionEdID(revoker): map[string]any{"availability": "available", "max_age": int64(60), "rollback_safe": true, "snapshot": encode(snapshot)}}, "time": map[string]any{"trusted": true, "fresh": true, "authority_until": now.Add(5 * time.Minute).Format(time.RFC3339)}}
	policy := map[string]any{"version": 1, "identity": fixtureIdentity, "user_id": fixtureUser, "audience": "fixture-origin", "construction_profile": "W", "agent_name": "id/test-agent", "landlord_name": "id/test-landlord", "issuer_pubkey": xonlyKey(5), "timeout_ms": 5000, "rpc": su.Route{Host: host, Port: port, Username: "w3-observer", Password: "public-fixture-rpc-password"}, "pins": map[string]any{fixtureUser: map[string]any{"key": xonlyKey(1), "author": compositionEdID(receiver)}, fixtureSender: map[string]any{"key": xonlyKey(2), "author": compositionEdID(sender)}}, "envelope_evidence": evidence, "initial_watermark": now.Add(-time.Minute).Format(time.RFC3339), "executor_key": xonlyKey(9), "max_tip_age_seconds": 600, "max_future_skew_seconds": 120, "minimum_height": 0, "terms": map[string]any{rental.Hash(payTerms(t)): encode(payTerms(t))}}
	if err := os.WriteFile(filepath.Join(f.policy, "cg1-matrix.json"), compositionJSON(t, policy), 0700); err != nil {
		t.Fatal(err)
	}
	proof := compositionGrant(t, now)
	grantID, err := kernel.PresentationID(proof)
	if err != nil {
		t.Fatal(err)
	}
	textHash := sha256.Sum256([]byte("hello"))
	body := map[string]any{"type": "message/1", "aud": policy["audience"], "nonce": encode(bytes.Repeat([]byte{7}, 16)), "iat": now.Add(-time.Second).Format(time.RFC3339), "exp": now.Add(time.Minute).Format(time.RFC3339), "author": compositionEdID(sender), "author_attestation": attIDs[compositionEdID(sender)], "action": "a2a.message", "target": map[string]any{"kind": "station", "id": "cg1"}, "arguments": map[string]any{"cg1": map[string]any{"grant_id": grantID, "proof": []any{encode(proof)}}}, "room": fixtureRoom, "to": fixtureUser, "body_sha256": hex.EncodeToString(textHash[:])}
	raw := compositionSign(t, sender, body)
	encoded, err := matrix.EncodeEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	co, err := cg1cosign.FixtureSign(raw, strings.TrimPrefix(strings.SplitN(fixtureSender, ":", 2)[0], "@"))
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"msgtype": "m.text", "body": "hello", matrix.EnvelopeContentKey: encoded, cg1cosign.ContentKey: co}
}

// Claim: a real signed retained event reaches the production grant backend's node route and refuses without a Result when that dependency is unavailable; altered text refuses earlier.
func TestProductionCheckerComposition(t *testing.T) {
	f := newFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	var mu sync.Mutex
	methods := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		methods[req.Method]++
		mu.Unlock()
		var result any
		switch req.Method {
		case "getblockchaininfo":
			result = map[string]any{"chain": "regtest", "blocks": 100, "headers": 100, "bestblockhash": strings.Repeat("c", 64), "initialblockdownload": false}
		case "getblockhash":
			result = strings.Repeat("c", 64)
			if len(req.Params) > 0 && string(req.Params[0]) == "0" {
				result = su.RegtestGenesis
			}
		case "getrawmempool":
			result = []string{}
		case "getblockheader":
			hash, height := strings.Repeat("c", 64), 100
			if len(req.Params) > 0 && json.Unmarshal(req.Params[0], &hash) == nil && hash == su.RegtestGenesis {
				height = 0
			}
			result = map[string]any{"hash": hash, "time": now.Unix(), "height": height, "confirmations": 1}
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 1, "result": result, "error": nil})
	}))
	defer server.Close()
	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	nport, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	content := compositionPolicy(t, f, host, nport, now)
	f.replaceContent(content)
	producer, err := newProducer(f.mappingPath, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	s, err := producer.Open(context.Background(), f.selection)
	if err != nil || s == nil {
		t.Fatal("production constructor did not open", err)
	}
	defer s.Close()
	result, err := s.Prepare(context.Background())
	refused(t, result, err, ReasonUnavailable, runorigin.ErrUnavailable)
	mu.Lock()
	backendReads := methods["name_show"]
	t.Logf("production RPC method counts: %v", methods)
	mu.Unlock()
	if backendReads == 0 {
		t.Fatal("signed control never reached the real grant backend's identity read")
	}
	content["body"] = "altered text"
	f.replaceContent(content)
	bad, err := producer.Open(context.Background(), f.selection)
	if err != nil || bad == nil {
		t.Fatal("altered retained event did not open", err)
	}
	defer bad.Close()
	result, err = bad.Prepare(context.Background())
	refused(t, result, err, ReasonInnerInvalid, runorigin.ErrRefused)
	mu.Lock()
	defer mu.Unlock()
	if methods["name_show"] != backendReads {
		t.Fatal("altered text reached the grant backend")
	}
}
