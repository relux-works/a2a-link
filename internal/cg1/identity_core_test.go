package cg1

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/a2a-swarm/internal/admission"
	"github.com/relux-works/swarma-chain-lab/experiments/grantcheck"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Claim: both registered adapters refuse either expired Core identity by name on inbound/outbound/cached re-check, beside renewal, malformed-RPC and stopped-node controls.
func TestCoreIdentityExpired(t *testing.T) {
	if os.Getenv("CG1_REGTEST") != "1" {
		t.Skip("requires isolated pinned Core")
	}
	base := os.Getenv("CG1_RUN_ROOT")
	if !filepath.IsAbs(base) {
		t.Fatal("absolute CG1_RUN_ROOT required")
	}
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"agent", "landlord"} {
		t.Run(role, func(t *testing.T) {
			t.Setenv("CG1_RUN_ROOT", filepath.Join(base, role))
			l := newCoreLab(t, xonly(3))
			key := make([]byte, 32)
			key[31] = 2
			peer, err := nostr.PrivKeyFromBytes(key)
			if err != nil {
				t.Fatal(err)
			}
			p := coreProof(t, l.grant(peer, "identity-expiry", l.seal(), true))
			// Only name_show has an explicit response fault seam; all other RPCs use genuine Core.
			var mu sync.Mutex
			status, body := 0, ""
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					Method string `json:"method"`
					Params []any  `json:"params"`
				}
				if json.NewDecoder(r.Body).Decode(&req) != nil {
					http.Error(w, "bad request", 400)
					return
				}
				mu.Lock()
				s, b := status, body
				mu.Unlock()
				if req.Method == "name_show" && s != 0 {
					w.WriteHeader(s)
					_, _ = w.Write([]byte(b))
					return
				}
				raw, e := l.observer.Call(r.Context(), req.Method, req.Params...)
				if e != nil {
					var application *su.RPCError
					if errors.As(e, &application) {
						w.WriteHeader(500)
						_ = json.NewEncoder(w).Encode(map[string]any{"id": 1, "result": nil, "error": map[string]any{"code": application.Code, "message": application.Message}})
					} else {
						http.Error(w, "observer unavailable", 503)
					}
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"id": 1, "result": raw, "error": nil})
			}))
			t.Cleanup(proxy.Close)
			host, port, _ := net.SplitHostPort(proxy.Listener.Addr().String())
			number, _ := strconv.Atoi(port)
			route := su.Route{Host: host, Port: number, Username: "w3-observer", Password: "fixture-only-proxy-password"}
			// Open the actual factories with protected config, rather than injecting verdicts.
			dir := stateDir(t)
			cfg := settings{grantPolicy: testGrantPolicy(t), Version: 1, AgentName: e2eAgentName, LandlordName: e2eLandlordName, IssuerPubkey: l.issuerPub, TimeoutMS: 5000, RPC: route}
			if err = os.WriteFile(filepath.Join(dir, "cg1.json"), jsonBytes(t, cfg), 0600); err != nil {
				t.Fatal(err)
			}
			nc, err := admission.Open(Policy, admission.Config{Identity: "identity-control", Nostr: true, NostrPubkey: xonly(3), StateDir: dir})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = nc.Close() })
			f := newMatrixFixtureAt(t, time.Now().UTC().Truncate(time.Second))
			dir = stateDir(t)
			f.cfg.AgentName = e2eAgentName
			f.cfg.LandlordName = e2eLandlordName
			f.cfg.IssuerPubkey = l.issuerPub
			f.cfg.RPC = route
			f.cfg.TimeoutMS = 5000
			f.save(t, dir)
			mc, err := admission.Open(MatrixPolicy, admission.Config{Identity: f.cfg.Identity, MatrixUserID: f.cfg.UserID, StateDir: dir})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = mc.Close() })
			seq := 0
			matrixIn := func(proof bool) admission.Decision {
				args := map[string]any{"cg1": nil}
				if proof {
					args = coreArgs(p)
				}
				seq++
				b := f.body(matrixBob, matrixAlice, "hello", args)
				b["nonce"] = base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%016d", seq)))
				in := f.incoming(t, f.content(t, matrixBob, matrixAlice, b))
				in.EventID = fmt.Sprintf("$identity-%d", seq)
				d, e := mc.Inbound(context.Background(), in)
				if e != nil {
					t.Fatal(e)
				}
				return d
			}
			matrixOut := func() admission.Decision {
				seq++
				b := f.body(matrixAlice, matrixBob, "hello", map[string]any{"cg1": nil})
				b["nonce"] = base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%016d", seq)))
				out := f.outgoing(t, f.content(t, matrixAlice, matrixBob, b))
				out.TransactionID = fmt.Sprintf("identity-%d", seq)
				d, e := mc.Outbound(context.Background(), out)
				if e != nil {
					t.Fatal(e)
				}
				return d
			}
			nostrIn := func(proof bool) admission.Decision {
				in := incoming(nc.(*checker))
				if proof {
					in.Nostr.Presentation = &admission.NostrPresentation{GrantID: p.GrantID, Bytes: p.Bytes}
				}
				d, e := nc.Inbound(context.Background(), in)
				if e != nil {
					t.Fatal(e)
				}
				return d
			}
			nostrOut := func() admission.Decision {
				d, e := nc.Outbound(context.Background(), admission.Outbound{Identity: "identity-control", Nostr: &admission.TrustedNostrOutbound{Recipient: peer.PubKeyHex()}})
				if e != nil {
					t.Fatal(e)
				}
				return d
			}
			routes := func(t *testing.T, verdict admission.Verdict, reason string, retry bool) {
				t.Helper()
				for _, r := range []struct {
					name string
					call func() admission.Decision
					live string
				}{
					{"nostr-inbound", func() admission.Decision { return nostrIn(true) }, "live"},
					{"nostr-recheck", func() admission.Decision { return nostrIn(false) }, "live"},
					{"nostr-outbound", nostrOut, "live"},
					{"matrix-inbound", func() admission.Decision { return matrixIn(true) }, "allowed"},
					{"matrix-recheck", func() admission.Decision { return matrixIn(false) }, "allowed"},
					{"matrix-outbound", matrixOut, "allowed"},
				} {
					d := r.call()
					expected := reason
					if reason == "check_failed" && r.live == "allowed" {
						expected = "policy_error"
					}
					if verdict == admission.Live {
						expected = r.live
					}
					if d.Verdict != verdict || d.Reason != expected || d.Retryable != retry {
						t.Fatalf("%s decision=%+v want=%s retry=%v", r.name, d, expected, retry)
					}
				}
			}
			t.Run("Live", func(t *testing.T) { routes(t, admission.Live, "", false) })
			t.Run("RPCEnvelopes", func(t *testing.T) {
				// Claim: malformed name RPC envelopes remain retryable while complete expired and unrelated application errors retain distinct named classifications.
				for _, tc := range []struct {
					name, body, reason string
					retry              bool
				}{
					{"missing-result", `{"id":1,"error":{"code":-4,"message":"name expired"}}`, "verifier_unavailable", true},
					{"non-null-result", `{"id":1,"result":"live","error":{"code":-4,"message":"name expired"}}`, "verifier_unavailable", true},
					{"missing-id", `{"result":null,"error":{"code":-4,"message":"name expired"}}`, "verifier_unavailable", true},
					{"valid-expired", `{"id":1,"result":null,"error":{"code":-4,"message":"name expired"}}`, "identity_expired", false},
					{"valid-other", `{"id":1,"result":null,"error":{"code":-8,"message":"invalid parameter"}}`, "check_failed", false},
				} {
					t.Run(tc.name, func(t *testing.T) {
						mu.Lock()
						status, body = 500, tc.body
						mu.Unlock()
						defer func() { mu.Lock(); status, body = 0, ""; mu.Unlock() }()
						routes(t, admission.Refused, tc.reason, tc.retry)
						mu.Lock()
						status, body = 0, ""
						mu.Unlock()
						routes(t, admission.Live, "", false)
					})
				}
			})
			read := func(name string) su.NameView {
				var v su.NameView
				if e := json.Unmarshal(l.rpc("", "name_show", name, map[string]any{"allowExpired": true}), &v); e != nil {
					t.Fatal(e)
				}
				return v
			}
			expiredName, other := e2eAgentName, e2eLandlordName
			if role == "landlord" {
				expiredName, other = other, expiredName
			}
			l.mine(int(read(expiredName).ExpiresIn) - 2)
			for _, name := range []string{e2eAgentName, e2eLandlordName} {
				l.rpc("issuer", "name_update", name, read(name).Value)
			}
			l.mine(1)
			t.Run("SameValueRenewal", func(t *testing.T) {
				// Claim: same-value renewal before expiry preserves the already-admitted grant on all adapter routes.
				routes(t, admission.Live, "", false)
			})
			l.mine(int(read(expiredName).ExpiresIn) - 2)
			l.rpc("issuer", "name_update", other, read(other).Value)
			l.mine(1)
			routes(t, admission.Live, "", false)
			l.mine(2)
			t.Run("Expired", func(t *testing.T) {
				// Claim: real selective expiry refuses by name, including the adapter's typed HTTP-500 error and current allowExpired projection paths.
				if !read(expiredName).Expired || read(other).Expired {
					t.Fatal("missing selective expiry witness")
				}
				_, e := l.observer.Call(context.Background(), "name_show", expiredName)
				var application *su.RPCError
				if !errors.As(e, &application) || !application.NameExpired() {
					t.Fatalf("genuine Core expiry lost typed reason: %v", e)
				}
				routes(t, admission.Refused, "identity_expired", false)
				// The backend's closed bit is required in addition to the public mapped decision.
				v := nc.(*checker).core.Inbound(context.Background(), peer.PubKeyHex(), &p)
				if v.Code != grantcheck.CodeIdentityExpired || !v.Closed || v.Retryable {
					t.Fatalf("unclosed expiry: %+v", v)
				}
			})
			l.stop()
			t.Run("NodeDown", func(t *testing.T) {
				// Claim: stopping the genuine node yields verifier_unavailable, retryable, even after an earlier observed identity expiry.
				routes(t, admission.Refused, "verifier_unavailable", true)
			})
		})
	}
}
