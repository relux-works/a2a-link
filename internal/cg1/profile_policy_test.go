package cg1

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/relux-works/swarma-chain-lab/experiments/grantcheck"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

func explicitPolicy(t *testing.T, profile, network string) grantPolicy {
	t.Helper()
	p := testGrantPolicy(t)
	p.Profile, p.Network, p.Genesis = profile, network, su.RegtestGenesis
	if network == "main" {
		p.Genesis = grantcheck.MainGenesis
	}
	var pay rental.PayTermsV2
	if err := json.Unmarshal(unitTerms(t), &pay); err != nil {
		t.Fatal(err)
	}
	pay.Network, pay.Genesis = p.Network, p.Genesis
	raw, err := rental.EncodePayTermsV2(pay)
	if err != nil {
		t.Fatal(err)
	}
	if profile == "trust" {
		p.ExecutorKey = ""
		raw = bytes.Replace(trustDocument(t), []byte(`"network":"regtest"`), []byte(`"network":"`+network+`"`), 1)
	}
	p.Terms = map[string]string{rental.Hash(raw): base64.RawURLEncoding.EncodeToString(raw)}
	return p
}

// policyFactory gives each startup a fresh namespace; no successful control can mask a refusal.
func policyFactory(t *testing.T, path, profile, network string) ([]byte, func([]byte) error) {
	t.Helper()
	p := explicitPolicy(t, profile, network)
	if path == "nostr" {
		c, cfg := configFixture(t)
		cfg.Version, cfg.grantPolicy = 2, p
		return jsonBytes(t, cfg), func(raw []byte) error {
			if err := os.WriteFile(filepath.Join(c.StateDir, "cg1.json"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			checker, err := open(c)
			if checker != nil {
				checker.Close()
			}
			return err
		}
	}
	f, dir, c := freshMatrixConfig(t)
	f.cfg.Version, f.cfg.grantPolicy = 2, p
	return jsonBytes(t, f.cfg), func(raw []byte) error {
		if err := os.WriteFile(filepath.Join(dir, matrixConfigName), raw, 0700); err != nil {
			t.Fatal(err)
		}
		if path == "matrix" {
			checker, err := openMatrix(c)
			if checker != nil {
				checker.Close()
			}
			return err
		}
		checker, err := OpenOriginChecker(OriginScope{Identity: c.Identity, UserID: c.MatrixUserID, PolicyDir: dir, ScopeDir: stateDir(t), Profile: profile})
		if checker != nil {
			checker.Close()
		}
		return err
	}
}

// Claim: the shared member gate independently refuses each missing, repeated or case-variant binding member beside its valid exact control.
func TestPolicyMemberGate(t *testing.T) {
	p := explicitPolicy(t, "trust", "regtest")
	raw := jsonBytes(t, p)
	for _, field := range []string{"profile", "network", "genesis"} {
		for _, defect := range []string{"missing", "duplicate", "alias-extra"} {
			t.Run(field+"/"+defect, func(t *testing.T) {
				if !grantPolicyNames(raw, 2) {
					t.Fatal("valid control")
				}
				var obj map[string]json.RawMessage
				if err := json.Unmarshal(raw, &obj); err != nil {
					t.Fatal(err)
				}
				if defect == "alias-extra" {
					obj[strings.ToUpper(field)] = obj[field]
				}
				if defect == "missing" {
					delete(obj, field)
				}
				bad := jsonBytes(t, obj)
				if defect == "duplicate" {
					bad = append([]byte(`{"`+field+`":`+string(obj[field])+`,`), bad[1:]...)
				}
				if grantPolicyNames(bad, 2) {
					t.Fatal("invalid member passed")
				}
			})
		}
	}
}

// Claim: the binding gate independently rejects each unknown profile, network or genesis value beside the valid trust pair.
func TestPolicyValueGate(t *testing.T) {
	for _, field := range []string{"profile", "network", "genesis"} {
		t.Run(field, func(t *testing.T) {
			p := explicitPolicy(t, "trust", "regtest")
			if _, _, _, ok := p.binding(); !ok {
				t.Fatal("valid control")
			}
			switch field {
			case "profile":
				p.Profile = "unknown"
			case "network":
				p.Network = "unknown"
			case "genesis":
				p.Genesis = "unknown"
			}
			if _, _, _, ok := p.binding(); ok {
				t.Fatal("unknown value passed")
			}
		})
	}
}

// Claim: all factories require exact version-2 profile/network/genesis members and reject each malformed neighbor with errConfig; valid pay/trust pairs open.
func TestExplicitPolicyMembers(t *testing.T) {
	for _, path := range []string{"matrix", "origin", "nostr"} {
		for _, profile := range []string{"pay", "trust"} {
			for _, network := range []string{"regtest", "main"} {
				t.Run(path+"/"+profile+"/"+network, func(t *testing.T) {
					raw, open := policyFactory(t, path, profile, network)
					if err := open(raw); err != nil {
						t.Fatal("valid control", err)
					}
				})
			}
		}
		for _, field := range []string{"profile", "network", "genesis"} {
			for _, defect := range []string{"missing", "unknown", "empty", "null", "type", "duplicate", "alias", "alias-extra"} {
				t.Run(path+"/"+field+"/"+defect, func(t *testing.T) {
					raw, open := policyFactory(t, path, "trust", "regtest")
					var obj map[string]json.RawMessage
					if err := json.Unmarshal(raw, &obj); err != nil {
						t.Fatal(err)
					}
					switch defect {
					case "missing":
						delete(obj, field)
					case "unknown":
						obj[field] = json.RawMessage(`"unknown"`)
					case "empty":
						obj[field] = json.RawMessage(`""`)
					case "null":
						obj[field] = json.RawMessage(`null`)
					case "type":
						obj[field] = json.RawMessage(`7`)
					case "alias", "alias-extra":
						obj[strings.ToUpper(field)] = obj[field]
						if defect == "alias" {
							delete(obj, field)
						}
					}
					bad := jsonBytes(t, obj)
					if defect == "duplicate" {
						bad = append([]byte(`{"`+field+`":`+string(obj[field])+`,`), bad[1:]...)
					}
					if err := open(bad); !errors.Is(err, errConfig) {
						t.Fatalf("want configuration code, got %v", err)
					}
					if err := open(raw); err != nil {
						t.Fatal("corrected control", err)
					}
				})
			}
		}
	}
}

// Claim: trust rejects a nonempty executor and either cross-network pair at startup on every path, beside an unchanged valid policy.
func TestExplicitPolicyBinding(t *testing.T) {
	for _, path := range []string{"matrix", "origin", "nostr"} {
		for _, field := range []string{"executor_key", "network", "genesis"} {
			t.Run(path+"/"+field, func(t *testing.T) {
				raw, open := policyFactory(t, path, "trust", "regtest")
				var obj map[string]json.RawMessage
				if err := json.Unmarshal(raw, &obj); err != nil {
					t.Fatal(err)
				}
				value := map[string]string{"executor_key": xonly(9), "network": "main", "genesis": grantcheck.MainGenesis}[field]
				obj[field] = jsonBytes(t, value)
				if err := open(jsonBytes(t, obj)); !errors.Is(err, errConfig) {
					t.Fatalf("want configuration code, got %v", err)
				}
				if err := open(raw); err != nil {
					t.Fatal("corrected control", err)
				}
			})
		}
	}
}

// Claim: the unchanged version-1 pay policy still opens and reopens, has no new serialized fields, and cannot opt into trust or any new binding member.
func TestLegacyPolicyStaysPay(t *testing.T) {
	for _, path := range []string{"matrix", "origin", "nostr"} {
		t.Run(path, func(t *testing.T) {
			raw, open := policyFactory(t, path, "pay", "regtest")
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(raw, &obj); err != nil {
				t.Fatal(err)
			}
			obj["version"] = json.RawMessage(`1`)
			for _, name := range []string{"profile", "network", "genesis"} {
				delete(obj, name)
			}
			legacy := jsonBytes(t, obj)
			if err := open(legacy); err != nil {
				t.Fatal("legacy control", err)
			}
			if err := open(legacy); err != nil {
				t.Fatal("legacy reopen", err)
			}
			for _, field := range []string{"profile", "network", "genesis"} {
				obj[field] = json.RawMessage(`"trust"`)
				if err := open(jsonBytes(t, obj)); !errors.Is(err, errConfig) {
					t.Fatalf("old version accepted %s: %v", field, err)
				}
				delete(obj, field)
			}
		})
	}
	p := testGrantPolicy(t)
	profile, network, genesis, ok := p.binding()
	if !ok || profile != "pay" || network != "regtest" || genesis != su.RegtestGenesis {
		t.Fatal("legacy implicit binding changed")
	}
	for _, field := range []string{`"profile":`, `"network":`, `"genesis":`} {
		if bytes.Contains(jsonBytes(t, p), []byte(field)) {
			t.Fatal("legacy serialized binding changed")
		}
	}
}

type bindingNode struct {
	network, genesis string
	calls            int
}

func (n *bindingNode) Call(_ context.Context, method string, _ ...any) (json.RawMessage, error) {
	n.calls++
	switch method {
	case "getblockchaininfo":
		return json.Marshal(map[string]any{"chain": n.network})
	case "getblockhash":
		return json.Marshal(n.genesis)
	default:
		return nil, errNode
	}
}

// Claim: every public grant route refuses a node-pin mismatch before grant parsing, with matching-node controls before and after.
func TestPolicyNodePinsBeforeGrant(t *testing.T) {
	for _, pin := range []string{"network", "genesis"} {
		for _, route := range []string{"inbound", "outbound", "matrix-inbound", "matrix-outbound", "provision"} {
			t.Run(pin+"/"+route, func(t *testing.T) {
				node := &bindingNode{network: "regtest", genesis: su.RegtestGenesis}
				p := explicitPolicy(t, "trust", "regtest")
				c, err := newPolicyChecker(p, grantcheck.Config{ConstructionProfile: "W", Identity: "test", AgentName: "id/test-agent", LandlordName: "id/test-landlord", IssuerPubkey: xonly(1), StateDir: stateDir(t), Node: node}, grantcheck.SwarmEnvelopeV2)
				if err != nil {
					t.Fatal(err)
				}
				if v := c.preflight(context.Background()); v != nil {
					t.Fatal("valid control", v.Code)
				}
				if pin == "network" {
					node.network = "main"
				} else {
					node.genesis = grantcheck.MainGenesis
				}
				var v grantcheck.Verdict
				switch route {
				case "inbound":
					v = c.Inbound(context.Background(), xonly(2), nil)
				case "outbound":
					v = c.Outbound(context.Background(), xonly(2))
				case "matrix-inbound":
					v = c.InboundFrom(context.Background(), grantcheck.SenderProof{}, nil)
				case "matrix-outbound":
					v = c.OutboundFrom(context.Background(), grantcheck.RecipientProof{})
				case "provision":
					v = c.Provision(context.Background(), grantcheck.Presentation{})
				}
				if v.Decision != grantcheck.Refused || v.Code != grantcheck.CodeVerifierUnavailable || !v.Retryable || v.GrantID != "" {
					t.Fatalf("wrong node pin code: %s", v.Code)
				}
				node.network, node.genesis = "regtest", su.RegtestGenesis
				if v := c.preflight(context.Background()); v != nil {
					t.Fatal("restored control", v.Code)
				}
			})
		}
	}
}

// Claim: Matrix and origin use the same policy-selected profile and unchanged network/genesis, and origin refuses a disagreeing protected mapping before construction.
func TestBothPathsUsePolicy(t *testing.T) {
	for _, profile := range []string{"pay", "trust"} {
		for _, network := range []string{"regtest", "main"} {
			t.Run(profile+"/"+network, func(t *testing.T) {
				f, dir, cfg := freshMatrixConfig(t)
				f.cfg.Version, f.cfg.grantPolicy = 2, explicitPolicy(t, profile, network)
				f.save(t, dir)
				m, err := openMatrix(cfg)
				if err != nil {
					t.Fatal("Matrix control", err)
				}
				defer m.Close()
				origin, err := OpenOriginChecker(OriginScope{Identity: cfg.Identity, UserID: cfg.MatrixUserID, PolicyDir: dir, ScopeDir: stateDir(t), Profile: profile})
				if err != nil {
					t.Fatal("origin control", err)
				}
				defer origin.Close()
				for _, backend := range []matrixGrantSource{m.(*matrixChecker).core, origin.core} {
					c, ok := backend.(*policyChecker)
					if !ok || !c.explicit || c.network != f.cfg.Network || c.genesis != f.cfg.Genesis {
						t.Fatal("policy pins lost on a path")
					}
				}
				other := "trust"
				if profile == "trust" {
					other = "pay"
				}
				bad, err := OpenOriginChecker(OriginScope{Identity: cfg.Identity, UserID: cfg.MatrixUserID, PolicyDir: dir, ScopeDir: stateDir(t), Profile: other})
				if bad != nil {
					bad.Close()
				}
				if !errors.Is(err, errConfig) || bad != nil {
					t.Fatal("mapping/profile disagreement admitted")
				}
			})
		}
	}
}

func trustDocument(t *testing.T) []byte {
	t.Helper()
	return []byte(`{"profile":"swarma-trust-contract/1","network":"regtest","landlord_name":"id/test-landlord","agent_name":"id/test-agent","grantee_key":"` + xonly(2) + `","actions":["instruct","review"],"repos":[],"spend_budget":0,"not_before":300,"not_after":1000,"note":""}`)
}

func trustPresentation(t *testing.T, doc []byte) grantcheck.Presentation {
	t.Helper()
	key := make([]byte, 32)
	key[31] = 1
	issuer, _ := btcec.PrivKeyFromBytes(key)
	key[31] = 2
	grantee, err := nostr.PrivKeyFromBytes(key)
	if err != nil {
		t.Fatal(err)
	}
	hash := rental.Hash(doc)
	consent := signEvent(t, grantee, rental.Event{CreatedAt: 200, Kind: 8181, Tags: [][]string{{"t", "swarma-rental-consent-v1"}, {"contract", hash}, {"booking", rental.Hash(append(bytes.Clone(doc), []byte("booking")...))}, {"privacy", rental.Hash([]byte("swarma-trust-privacy-v1"))}}})
	g := proofGrant(t, unitGrant(t)).Grant
	g.Scope, g.ContractSHA256 = []string{}, hash
	g.Consent = rental.GrantConsent{ContractSHA256: hash, ConsentEvent: consent, LandlordSig: signHash(t, issuer, hash)}
	digest, err := g.SigningHash()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := rental.PresentIssuedGrant(jsonBytes(t, rental.SignedGrant{Grant: g, Signature: signHash(t, issuer, digest)}), strings.Repeat("e", 64))
	if err != nil {
		t.Fatal(err)
	}
	return grantcheck.Presentation{GrantID: proofGrant(t, raw).ID(), Bytes: raw}
}

// Claim: the real CG1 parser refuses either cross-profile grant as terms_invalid; each own-profile control passes terms and reaches the unavailable node, not Live.
func TestProfileContractGate(t *testing.T) {
	doc := trustDocument(t)
	trust := trustPresentation(t, doc)
	payRaw := unitGrant(t)
	pay := grantcheck.Presentation{GrantID: proofGrant(t, payRaw).ID(), Bytes: payRaw}
	for _, profile := range []string{"pay", "trust"} {
		t.Run(profile, func(t *testing.T) {
			p := explicitPolicy(t, profile, "regtest")
			valid, invalid := pay, trust
			if profile == "trust" {
				p.Terms[rental.Hash(unitTerms(t))] = base64.RawURLEncoding.EncodeToString(unitTerms(t))
				valid, invalid = trust, pay
			}
			node := &bindingNode{network: "regtest", genesis: su.RegtestGenesis}
			c, err := newPolicyChecker(p, grantcheck.Config{ConstructionProfile: "W", Identity: "test", AgentName: proofGrant(t, payRaw).Grant.AgentName, LandlordName: proofGrant(t, payRaw).Grant.LandlordName, IssuerPubkey: xonly(1), Node: node, StateDir: stateDir(t), Now: func() time.Time { return time.Unix(500, 0) }}, grantcheck.SwarmEnvelopeV2)
			if err != nil {
				t.Fatal(err)
			}
			sender := grantcheck.SenderProof{Transport: grantcheck.SwarmEnvelopeV2, Key: xonly(2)}
			check := func(proof grantcheck.Presentation, want grantcheck.Code) {
				t.Helper()
				v := c.InboundFrom(context.Background(), sender, &proof)
				if v.Decision != grantcheck.Refused || v.Code != want || v.GrantID != "" {
					t.Fatalf("got %s, want %s", v.Code, want)
				}
			}
			check(valid, grantcheck.CodeVerifierUnavailable)
			check(invalid, grantcheck.CodeTermsInvalid)
			check(valid, grantcheck.CodeVerifierUnavailable)
		})
	}
}
