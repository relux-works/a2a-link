package cg1

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// The session-owned Node permits only bounded loopback read RPC, refuses
// redirects/mutations/malformed responses, and cancels an actually pending read.
func TestReadNode(t *testing.T) {
	var calls atomic.Int64
	var mode atomic.Int32
	release := make(chan struct{})
	finished := make(chan struct{}, 1)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		calls.Add(1)
		u, p, ok := r.BasicAuth()
		if !ok || u != "w3-observer" || p != "fixture-only-password" {
			t.Error("RPC authentication mismatch")
		}
		switch mode.Load() {
		case 1:
			http.Redirect(w, r, "http://127.0.0.1:1/", http.StatusFound)
		case 2:
			w.Write([]byte(`{"id":1,"result":{},"error":"private-node-error"}`))
		case 3:
			select {
			case <-r.Context().Done():
				finished <- struct{}{}
			case <-release:
			}
		case 4:
			w.Write([]byte(`{"id":2,"result":{},"error":null}`))
		default:
			w.Write([]byte(`{"id":1,"result":{"ok":true},"error":null}`))
		}
	}))
	defer s.Close()
	defer close(release)
	host, port, _ := net.SplitHostPort(s.Listener.Addr().String())
	nport, _ := strconv.Atoi(port)
	route := su.Route{Host: host, Port: nport, Username: "w3-observer", Password: "fixture-only-password"}
	n, e := newReadNode(route)
	if e != nil {
		t.Fatal(e)
	}
	defer n.Close()
	if r, e := n.Call(context.Background(), "getblockchaininfo"); e != nil || string(r) != `{"ok":true}` {
		t.Fatal("valid RPC refused")
	}
	count := calls.Load()
	if _, e := n.Call(context.Background(), "sendtoaddress"); e != errNode || calls.Load() != count {
		t.Fatal("write RPC reached server")
	}
	for _, m := range []int32{1, 2, 4} {
		mode.Store(m)
		if _, e := n.Call(context.Background(), "gettxout"); e != errNode {
			t.Fatal("invalid RPC accepted")
		}
	}
	mode.Store(3)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, e := n.Call(ctx, "getblockhash", 0); e != errNode || time.Since(start) > time.Second {
		t.Fatal("RPC deadline not bounded")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("cancelled RPC handler remained active")
	}
	for _, host := range []string{"example.invalid", "192.0.2.1", "127.0.0.1/path"} {
		bad := route
		bad.Host = host
		if n, e := newReadNode(bad); e == nil || n != nil {
			t.Fatal("non-loopback route accepted")
		}
	}
}
