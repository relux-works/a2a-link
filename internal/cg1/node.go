package cg1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/grantcheck"
	"github.com/relux-works/swarma-chain-lab/experiments/sealwatch"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

var errNode = errors.New("cg1: verifier unavailable")

// Session-owned read-only RPC implements CG1's Node contract. Unlike an ambient
// shared client it has an explicit close lifetime; no keepalive worker survives
// a completed request. Route/method/projection constraints match single-use RPC.
type readNode struct {
	route  su.Route
	client *http.Client
}

func newReadNode(r su.Route) (*readNode, error) {
	ip := net.ParseIP(r.Host)
	if ip == nil || !ip.IsLoopback() || r.Port < 1 || r.Port > 65535 || r.Username != "w3-observer" || len(r.Password) < 16 || len(r.Password) > 256 {
		return nil, errConfig
	}
	return &readNode{r, &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return errNode }}}, nil
}
func (n *readNode) Close() { n.client.CloseIdleConnections() }
func (n *readNode) Call(ctx context.Context, method string, args ...any) (json.RawMessage, error) {
	switch method {
	case "getblockchaininfo", "getblockhash", "getblockheader", "getrawtransaction", "gettxout", "name_show", "getrawmempool", "getblock":
	default:
		return nil, errNode
	}
	if args == nil {
		args = []any{}
	}
	raw, e := json.Marshal(map[string]any{"jsonrpc": "1.0", "id": 1, "method": method, "params": args})
	if e != nil {
		return nil, errNode
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+net.JoinHostPort(n.route.Host, strconv.Itoa(n.route.Port))+"/", bytes.NewReader(raw))
	if e != nil {
		return nil, errNode
	}
	req.SetBasicAuth(n.route.Username, n.route.Password)
	req.Header.Set("Content-Type", "application/json")
	res, e := n.client.Do(req)
	if e != nil {
		return nil, errNode
	}
	defer res.Body.Close()
	raw, e = io.ReadAll(io.LimitReader(res.Body, (8<<20)+1))
	if e != nil || len(raw) > 8<<20 {
		return nil, errNode
	}
	var id int
	var envelope map[string]json.RawMessage
	e = sealwatch.DecodeJSON(raw, &envelope)
	result, rpcError := envelope["result"], envelope["error"]
	// Match the pinned single-use JSON-RPC 1.0 rule before retaining a typed
	// application answer. HTTP failure alone is never an identity lifecycle fact.
	if e != nil || len(envelope) != 3 || json.Unmarshal(envelope["id"], &id) != nil || id != 1 || len(result) == 0 || len(rpcError) == 0 {
		return nil, errNode
	}
	if string(bytes.TrimSpace(rpcError)) != "null" {
		var application su.RPCError
		if !bytes.Equal(bytes.TrimSpace(result), []byte("null")) || sealwatch.ProjectJSON(rpcError, map[string]any{"code": &application.Code, "message": &application.Message}, nil) != nil {
			return nil, errNode
		}
		// Retain only the exact typed expiry answer for caller classification.
		if method == "name_show" && application.NameExpired() {
			if answer, ok := ctx.Value(nodeAnswerKey{}).(*nodeAnswer); ok {
				answer.identityExpired.Store(true)
			}
		}
		return nil, &application
	}
	if res.StatusCode != http.StatusOK {
		return nil, errNode
	}
	return result, nil
}

// A request-local answer retains a typed RPC refusal across #116's kernel
// receipt boundary (which otherwise reduces RPC_APPLICATION_ERROR to check_failed).
// It can refine that refusal only; it never supplies a result or grants admission.
type nodeAnswerKey struct{}
type nodeAnswer struct{ identityExpired atomic.Bool }

func withNodeAnswer(ctx context.Context) (context.Context, *nodeAnswer) {
	answer := new(nodeAnswer)
	return context.WithValue(ctx, nodeAnswerKey{}, answer), answer
}
func (a *nodeAnswer) verdict(v grantcheck.Verdict) grantcheck.Verdict {
	if a.identityExpired.Load() && v.Decision == grantcheck.Refused && v.Code == grantcheck.CodeCheckFailed && !v.Closed && !v.Retryable {
		v.Code = grantcheck.CodeIdentityExpired
		v.Closed = true
	}
	return v
}
