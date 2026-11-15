package cg1

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/a2a-swarm/internal/admission"
	"github.com/relux-works/a2a-swarm/internal/config"
	"github.com/relux-works/swarma-chain-lab/experiments/grantcheck"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Core RPCs remain real except the explicitly selected headers/frozen observation seams.
type recordedCoreNode struct {
	mu                   sync.Mutex
	real                 su.Node
	frozen, headersAhead bool
	answers              map[string]json.RawMessage
}

func (n *recordedCoreNode) Call(ctx context.Context, method string, args ...any) (json.RawMessage, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	key, _ := json.Marshal([]any{method, args})
	var raw json.RawMessage
	var err error
	if n.frozen {
		raw = n.answers[string(key)]
		if raw == nil {
			return nil, errors.New("unrecorded RPC")
		}
	} else {
		raw, err = n.real.Call(ctx, method, args...)
		if err != nil {
			return nil, err
		}
		n.answers[string(key)] = bytes.Clone(raw)
	}
	if n.headersAhead && method == "getblockchaininfo" {
		var info map[string]json.RawMessage
		if json.Unmarshal(raw, &info) != nil {
			return nil, errors.New("bad chain info")
		}
		var blocks int64
		if json.Unmarshal(info["blocks"], &blocks) != nil {
			return nil, errors.New("bad height")
		}
		info["headers"], _ = json.Marshal(blocks + 1)
		return json.Marshal(info)
	}
	return bytes.Clone(raw), nil
}
func coreProof(t *testing.T, raw []byte) grantcheck.Presentation {
	t.Helper()
	id, err := kernel.PresentationID(raw)
	if err != nil {
		t.Fatal(err)
	}
	return grantcheck.Presentation{GrantID: id, Bytes: raw}
}
func coreTip(t *testing.T, l *coreLab) (su.ChainInfo, int64) {
	t.Helper()
	var info su.ChainInfo
	if err := json.Unmarshal(l.rpc("", "getblockchaininfo"), &info); err != nil {
		t.Fatal(err)
	}
	var header struct {
		Time int64 `json:"time"`
	}
	if err := json.Unmarshal(l.rpc("", "getblockheader", info.Best), &header); err != nil {
		t.Fatal(err)
	}
	return info, header.Time
}
func grantCache(t *testing.T, dir string) json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "matrix-grantcheck-state", "grantcheck.json"))
	if err != nil {
		t.Fatal(err)
	}
	var state map[string]json.RawMessage
	if err = json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(state["cache"])
}
func assertProvisionAudit(t *testing.T, dir string, p grantcheck.Presentation, code string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "matrix-grantcheck-state", "grantcheck.json"))
	if err != nil {
		t.Fatal(err)
	}
	var state struct {
		Provisioning []grantcheck.ProvisionRecord `json:"provisioning"`
	}
	if json.Unmarshal(raw, &state) != nil || len(state.Provisioning) == 0 {
		t.Fatal("missing provision audit")
	}
	r := state.Provisioning[len(state.Provisioning)-1]
	if r.GrantID != p.GrantID || r.Hash != rental.Hash(p.Bytes) || string(r.Result) != code {
		t.Fatal("incorrect provision audit", r)
	}
}
func coreArgs(p grantcheck.Presentation) map[string]any {
	encoded := base64.RawURLEncoding.EncodeToString(p.Bytes)
	chunks := []any{}
	for len(encoded) > 4096 {
		chunks = append(chunks, encoded[:4096])
		encoded = encoded[4096:]
	}
	if encoded != "" {
		chunks = append(chunks, encoded)
	}
	return map[string]any{"cg1": map[string]any{"grant_id": p.GrantID, "proof": chunks}}
}

// Claim: the production Matrix factory/envelope path enforces executor, sync and floor pins on real Core; protected provisioning audits and preserves cache on every named refusal.
func TestCoreMatrixPolicy(t *testing.T) {
	l := newCoreLab(t, xonly(3))
	peerBytes := make([]byte, 32)
	peerBytes[31] = 2
	peer, err := nostr.PrivKeyFromBytes(peerBytes)
	if err != nil {
		t.Fatal(err)
	}
	seal := l.seal()
	p := coreProof(t, l.grant(peer, "matrix-live", seal, true))
	other := coreProof(t, l.grant(peer, "matrix-other", l.seal(), true))
	wrong := coreProof(t, l.grantAt(peer, "matrix-wrong", l.seal(), true, time.Now().Unix(), xonly(8)))
	var pay rental.PayTermsV2
	if json.Unmarshal(unitTerms(t), &pay) != nil {
		t.Fatal("terms")
	}
	pay.ExecutorKey = xonly(8)
	wrongTerms, err := rental.EncodePayTermsV2(pay)
	if err != nil {
		t.Fatal(err)
	}
	recorder := &recordedCoreNode{real: l.observer, answers: map[string]json.RawMessage{}}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			http.Error(w, "bad request", 400)
			return
		}
		raw, err := recorder.Call(r.Context(), req.Method, req.Params...)
		if err != nil {
			http.Error(w, "observer unavailable", 503)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"id": 1, "result": raw, "error": nil})
	}))
	defer proxy.Close()
	host, port, _ := net.SplitHostPort(proxy.Listener.Addr().String())
	nport, _ := strconv.Atoi(port)
	route := su.Route{Host: host, Port: nport, Username: "w3-observer", Password: "public-fixture-proxy-password"}
	openAt := func(t *testing.T, floor int64) (*matrixFixture, *matrixChecker, string) {
		t.Helper()
		f := newMatrixFixtureAt(t, time.Now().UTC().Truncate(time.Second))
		dir := stateDir(t)
		f.cfg.AgentName = e2eAgentName
		f.cfg.LandlordName = e2eLandlordName
		f.cfg.IssuerPubkey = l.issuerPub
		f.cfg.RPC = route
		f.cfg.TimeoutMS = 5000
		f.cfg.MinimumHeight = &floor
		f.cfg.Terms[rental.Hash(wrongTerms)] = base64.RawURLEncoding.EncodeToString(wrongTerms)
		f.save(t, dir)
		c, err := admission.Open(MatrixPolicy, admission.Config{Identity: f.cfg.Identity, MatrixUserID: f.cfg.UserID, StateDir: dir})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return f, c.(*matrixChecker), dir
	}
	inbound := func(t *testing.T, f *matrixFixture, c *matrixChecker, p grantcheck.Presentation) admission.Decision {
		t.Helper()
		content := f.content(t, matrixBob, matrixAlice, f.body(matrixBob, matrixAlice, "hello", coreArgs(p)))
		d, err := c.Inbound(context.Background(), f.incoming(t, content))
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	t.Run("ExecutorPin", func(t *testing.T) {
		// Claim: a genuine issuer-signed wrong-executor grant refuses by name beside a live grant.
		f, c, _ := openAt(t, 0)
		want(t, inbound(t, f, c, p), nil, admission.Live, "allowed", false)
		f, c, dir := openAt(t, 0)
		before := grantCache(t, dir)
		want(t, inbound(t, f, c, wrong), nil, admission.Refused, "executor_mismatch", false)
		if !bytes.Equal(before, grantCache(t, dir)) {
			t.Fatal("executor refusal cached proof")
		}
	})
	t.Run("HeadersAhead", func(t *testing.T) {
		// Claim: the same live Core observation refuses retryably when headers exceed blocks.
		f, c, _ := openAt(t, 0)
		want(t, inbound(t, f, c, p), nil, admission.Live, "allowed", false)
		recorder.mu.Lock()
		recorder.headersAhead = true
		recorder.mu.Unlock()
		defer func() { recorder.mu.Lock(); recorder.headersAhead = false; recorder.mu.Unlock() }()
		f, c, _ = openAt(t, 0)
		want(t, inbound(t, f, c, p), nil, admission.Refused, "node_not_synced", true)
	})
	t.Run("FrozenOldView", func(t *testing.T) {
		// Claim: a recorded consistent old Core view refuses retryably below the configured new trusted floor.
		f, c, _ := openAt(t, 0)
		want(t, inbound(t, f, c, p), nil, admission.Live, "allowed", false)
		old, _ := coreTip(t, l)
		l.mine(1)
		current, _ := coreTip(t, l)
		if current.Blocks != old.Blocks+1 || current.Best == old.Best {
			t.Fatal("no newer Core block witness")
		}
		recorder.mu.Lock()
		recorder.frozen = true
		recorder.mu.Unlock()
		defer func() { recorder.mu.Lock(); recorder.frozen = false; recorder.mu.Unlock() }()
		f, c, _ = openAt(t, old.Blocks)
		want(t, inbound(t, f, c, p), nil, admission.Live, "allowed", false)
		f, c, _ = openAt(t, current.Blocks)
		want(t, inbound(t, f, c, p), nil, admission.Refused, "tip_below_floor", true)
	})
	t.Run("AgeBoundary", func(t *testing.T) {
		// Claim: with a controlled trusted clock, genuine Core tip age exactly A is live and A+1 second is retryably stale.
		_, at := coreTip(t, l)
		frozen := &recordedCoreNode{real: l.observer, answers: map[string]json.RawMessage{}}
		for _, delta := range []int64{0, 60, 61} {
			cfg := testGrantPolicy(t)
			*cfg.MaxTipAgeSeconds = 60
			freshness, terms, err := cfg.resolve()
			if err != nil {
				t.Fatal(err)
			}
			core, err := grantcheck.NewForTransport(grantcheck.Config{ConstructionProfile: "W", Identity: "boundary", AgentName: e2eAgentName, LandlordName: e2eLandlordName, IssuerPubkey: l.issuerPub, ExecutorKey: cfg.ExecutorKey, Freshness: freshness, Terms: terms, StateDir: stateDir(t), Node: frozen, Now: func() time.Time { return time.Unix(at+delta, 0) }}, grantcheck.SwarmEnvelopeV2)
			if err != nil {
				t.Fatal(err)
			}
			d := decision(core.InboundFrom(context.Background(), grantcheck.SenderProof{Transport: grantcheck.SwarmEnvelopeV2, Key: peer.PubKeyHex()}, &p), true)
			if delta <= 60 {
				want(t, d, nil, admission.Live, "live", false)
				if delta == 0 {
					l.mine(1)
					frozen.frozen = true
				}
			} else {
				want(t, d, nil, admission.Refused, "tip_stale", true)
			}
		}
	})
	t.Run("Provisioning", func(t *testing.T) {
		for _, name := range []string{"Tampered", "Uncommitted", "Pending", "WrongExecutor", "Spent"} {
			t.Run(name, func(t *testing.T) {
				// Claim: real valid bootstrap enables cached outbound; each named refusal retains the cache and records the exact result/hash.
				_, c, dir := openAt(t, 0)
				want(t, c.Provision(context.Background(), other), nil, admission.Live, "live", false)
				assertProvisionAudit(t, dir, other, "live")
				v := c.core.OutboundFrom(context.Background(), grantcheck.RecipientProof{Transport: grantcheck.SwarmEnvelopeV2, Keys: []string{peer.PubKeyHex()}})
				if v.Code != grantcheck.CodeLive {
					t.Fatal("bootstrap outbound refused", v)
				}
				bad := grantcheck.Presentation{GrantID: p.GrantID, Bytes: bytes.Clone(p.Bytes)}
				code := "invalid_presentation"
				retry := false
				switch name {
				case "Tampered":
					bad.Bytes[len(bad.Bytes)-2] ^= 1
				case "Uncommitted":
					proof, err := rental.ParseGrantPresentation(p.Bytes)
					if err != nil {
						t.Fatal(err)
					}
					budget := int64(999999)
					proof.SignedGrant.Grant.Budget = &budget
					digest, err := proof.SignedGrant.Grant.SigningHash()
					if err != nil {
						t.Fatal(err)
					}
					proof.SignedGrant.Signature = signHash(t, l.issuer, digest)
					bad = coreProof(t, jsonBytes(t, proof))
					code = "issuance_mismatch"
				case "Pending":
					bad = coreProof(t, l.grant(peer, "matrix-pending", l.seal(), false))
					code = "grant_pending"
					retry = true
				case "WrongExecutor":
					bad = wrong
					code = "executor_mismatch"
				case "Spent":
					l.revoke(seal)
					code = "seal_spent"
				}
				_, cold, coldDir := openAt(t, 0)
				coldBefore := grantCache(t, coldDir)
				want(t, cold.Provision(context.Background(), bad), nil, admission.Refused, code, retry)
				if !bytes.Equal(coldBefore, grantCache(t, coldDir)) {
					t.Fatal("refusal populated cold cache")
				}
				assertProvisionAudit(t, coldDir, bad, code)
				before := grantCache(t, dir)
				want(t, c.Provision(context.Background(), bad), nil, admission.Refused, code, retry)
				if !bytes.Equal(before, grantCache(t, dir)) {
					t.Fatal("refusal changed cache")
				}
				assertProvisionAudit(t, dir, bad, code)
			})
		}
	})
	t.Run("OperatorCommand", func(t *testing.T) {
		// Claim: the actual CLI invokes protected provisioning and bootstraps a cold cache; tampering exits nonzero without replacing it.
		binary := os.Getenv("CG1_A2A_BINARY")
		if binary == "" {
			t.Skip("set CG1_A2A_BINARY to the freshly built a2a")
		}
		f, _, dir := openAt(t, 0)
		base := stateDir(t)
		identityDir := filepath.Join(base, "admission", f.cfg.Identity)
		if err := os.MkdirAll(filepath.Dir(identityDir), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(dir, identityDir); err != nil {
			t.Fatal(err)
		}
		creds := config.Credentials{UserID: f.cfg.UserID, Homeserver: "https://fixture.invalid", AdmissionPolicy: MatrixPolicy}
		file, err := config.CreateCredentialFile(config.Paths{Base: base}, f.cfg.Identity)
		if err != nil {
			t.Fatal(err)
		}
		if err := config.WriteCredentials(file, creds); err != nil {
			t.Fatal(err)
		}
		run := func(p grantcheck.Presentation, wantCode int) {
			t.Helper()
			path := filepath.Join(base, "proof.json")
			if err := os.WriteFile(path, p.Bytes, 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(binary, "--as", f.cfg.Identity, "cg1", "provision", "--proof", path)
			cmd.Env = []string{"A2A_CONFIG_DIR=" + base, "A2A_MATRIX_URL=https://fixture.invalid"}
			var output bytes.Buffer
			cmd.Stdout = &output
			cmd.Stderr = &output
			err := cmd.Start()
			if err != nil {
				t.Fatal(err)
			}
			pid := cmd.Process.Pid
			err = cmd.Wait()
			code := 0
			if err != nil {
				var e *exec.ExitError
				if !errors.As(err, &e) {
					t.Fatal(err)
				}
				code = e.ExitCode()
			}
			t.Logf("operator command pid=%d exit=%d", pid, code)
			if code != wantCode {
				t.Fatalf("operator exit %d: %s", code, output.String())
			}
		}
		run(other, 0)
		assertProvisionAudit(t, identityDir, other, "live")
		before := grantCache(t, identityDir)
		bad := grantcheck.Presentation{Bytes: []byte("tampered")}
		run(bad, 1)
		if !bytes.Equal(before, grantCache(t, identityDir)) {
			t.Fatal("CLI refusal replaced cache")
		}
	})
	t.Run("FutureTip", func(t *testing.T) {
		// Claim: a live genuine Core tip is accepted, while a newly mined tip two hours ahead refuses as tip_future.
		f, c, _ := openAt(t, 0)
		want(t, inbound(t, f, c, other), nil, admission.Live, "allowed", false)
		future := time.Now().Unix() + 7200
		l.rpc("", "setmocktime", future)
		l.mine(1)
		_, header := coreTip(t, l)
		if header != future {
			t.Fatal("future Core header witness missing")
		}
		f, c, _ = openAt(t, 0)
		want(t, inbound(t, f, c, other), nil, admission.Refused, "tip_future", false)
	})
	t.Logf("genuine Core factory/provisioning observations at %s", time.Now().UTC().Format(time.RFC3339))
}
