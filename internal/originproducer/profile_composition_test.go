package originproducer

import (
	"bytes"
	"context"
	"crypto/ed25519"
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
	"sync/atomic"
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
)

// compositionTrust re-signs the public pay fixture as a canonical trust /1 grant.
// No issuance or chain existence is asserted by these cryptographic fixtures.
func compositionTrust(t *testing.T, now time.Time) ([]byte, []byte) {
	t.Helper()
	parsed, err := rental.ParseGrantPresentation(compositionGrant(t, now))
	if err != nil {
		t.Fatal(err)
	}
	g := parsed.SignedGrant.Grant
	doc := []byte(`{"profile":"swarma-trust-contract/1","network":"regtest","landlord_name":"` + g.LandlordName + `","agent_name":"` + g.AgentName + `","grantee_key":"` + g.GranteeKey + `","actions":["instruct","review"],"repos":[],"spend_budget":0,"not_before":` + strconv.FormatInt(g.NotBefore, 10) + `,"not_after":` + strconv.FormatInt(g.NotAfter, 10) + `,"note":""}`)
	seed := make([]byte, 32)
	seed[31] = 5
	issuer, _ := btcec.PrivKeyFromBytes(seed)
	sign := func(hash string) string {
		raw, err := hex.DecodeString(hash)
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
	grantee, err := nostr.PrivKeyFromBytes(seed)
	if err != nil {
		t.Fatal(err)
	}
	hash := rental.Hash(doc)
	consent := nostr.Event{CreatedAt: now.Unix() - 10, Kind: 8181, Tags: [][]string{{"t", "swarma-rental-consent-v1"}, {"contract", hash}, {"booking", rental.Hash(append(bytes.Clone(doc), []byte("booking")...))}, {"privacy", rental.Hash([]byte("swarma-trust-privacy-v1"))}}}
	if err := grantee.SignEvent(&consent); err != nil {
		t.Fatal(err)
	}
	var event rental.Event
	if err := json.Unmarshal(compositionJSON(t, consent), &event); err != nil {
		t.Fatal(err)
	}
	g.ContractSHA256, g.Scope = hash, []string{}
	g.Consent = rental.GrantConsent{ContractSHA256: hash, ConsentEvent: event, LandlordSig: sign(hash)}
	digest, err := g.SigningHash()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := rental.PresentIssuedGrant(compositionJSON(t, rental.SignedGrant{Grant: g, Signature: sign(digest)}), strings.Repeat("e", 64))
	if err != nil {
		t.Fatal(err)
	}
	return doc, proof
}

func compositionWithProof(t *testing.T, content map[string]any, proof []byte) map[string]any {
	t.Helper()
	raw, err := matrix.DecodeEnvelope(content[matrix.EnvelopeContentKey].(string))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Body map[string]any `json:"body"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	id, err := kernel.PresentationID(proof)
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	envelope.Body["arguments"] = map[string]any{"cg1": map[string]any{"grant_id": id, "proof": []any{encode(proof)}}}
	raw = compositionSign(t, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, 32)), envelope.Body)
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

// Claim: either cross-profile grant reaches real origin/CG1 construction and refuses as typed terms_invalid with no Result; own-profile controls pass terms to the unavailable identity read.
func TestProductionCrossProfileRefusal(t *testing.T) {
	for _, profile := range []string{"pay", "trust"} {
		t.Run(profile, func(t *testing.T) {
			f := newFixture(t)
			f.mapping.Agents[0].TermsProfile = profile
			f.saveMapping()
			now := time.Now().UTC().Truncate(time.Second)
			var reads atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					Method string            `json:"method"`
					Params []json.RawMessage `json:"params"`
				}
				if json.NewDecoder(r.Body).Decode(&req) != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				var result any
				switch req.Method {
				case "getblockchaininfo":
					result = map[string]any{"chain": "regtest", "blocks": 100, "headers": 100, "bestblockhash": strings.Repeat("c", 64), "initialblockdownload": false}
				case "getblockhash":
					result = strings.Repeat("c", 64)
					if len(req.Params) > 0 && string(req.Params[0]) == "0" {
						result = su.RegtestGenesis
					}
				case "getblockheader":
					hash, height := strings.Repeat("c", 64), 100
					if len(req.Params) > 0 && json.Unmarshal(req.Params[0], &hash) == nil && hash == su.RegtestGenesis {
						height = 0
					}
					result = map[string]any{"hash": hash, "time": now.Unix(), "height": height, "confirmations": 1}
				case "getrawmempool":
					result = []string{}
				case "name_show":
					reads.Add(1)
					w.WriteHeader(http.StatusServiceUnavailable)
					return
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
			doc, trust := compositionTrust(t, now)
			valid, invalid := compositionGrant(t, now), trust
			var policy map[string]any
			path := filepath.Join(f.policy, "cg1-matrix.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(raw, &policy); err != nil {
				t.Fatal(err)
			}
			policy["version"], policy["profile"], policy["network"], policy["genesis"] = 2, profile, "regtest", su.RegtestGenesis
			if profile == "trust" {
				policy["executor_key"] = ""
				policy["terms"].(map[string]any)[rental.Hash(doc)] = base64.RawURLEncoding.EncodeToString(doc)
				valid, invalid = trust, valid
			}
			if err := os.WriteFile(path, compositionJSON(t, policy), 0700); err != nil {
				t.Fatal(err)
			}
			p, err := newProducer(f.mappingPath, uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			check := func(proof []byte, reason Reason, cause error) {
				t.Helper()
				f.replaceContent(compositionWithProof(t, content, proof))
				s, err := p.Open(context.Background(), f.selection)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				result, err := s.Prepare(context.Background())
				refused(t, result, err, reason, cause)
			}
			check(valid, ReasonUnavailable, runorigin.ErrUnavailable)
			before := reads.Load()
			if before == 0 {
				t.Fatal("valid contract did not reach identity read")
			}
			check(invalid, ReasonTermsInvalid, runorigin.ErrRefused)
			if reads.Load() != before {
				t.Fatal("cross-profile grant reached identity read")
			}
			check(valid, ReasonUnavailable, runorigin.ErrUnavailable)
			if reads.Load() <= before {
				t.Fatal("restored valid contract did not reach identity read")
			}
		})
	}
}
