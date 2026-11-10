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
	"time"

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
	if e != nil || len(raw) > 8<<20 || res.StatusCode != http.StatusOK {
		return nil, errNode
	}
	var id int
	var result, rpcError json.RawMessage
	if sealwatch.ProjectJSON(raw, map[string]any{"id": &id}, map[string]any{"result": &result, "error": &rpcError}) != nil || id != 1 || len(result) == 0 || string(bytes.TrimSpace(rpcError)) != "null" {
		return nil, errNode
	}
	return result, nil
}
