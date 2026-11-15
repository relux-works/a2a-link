package cg1

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

func rpcFixtureNode(t *testing.T, status int, body string) *readNode {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status); _, _ = w.Write([]byte(body)) }))
	t.Cleanup(server.Close)
	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	number, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	node, err := newReadNode(su.Route{Host: host, Port: number, Username: "w3-observer", Password: "fixture-only-password"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(node.Close)
	return node
}

// Claim: only complete strict JSON-RPC application errors retain typed code/message at HTTP 200/500/503; incomplete/ambiguous bodies stay unavailable without a result.
func TestReadNodeRPCEnvelope(t *testing.T) {
	cases := []struct {
		name, body string
		code       int
		expired    bool
	}{
		{"expired", `{"id":1,"result":null,"error":{"code":-4,"message":"name expired"}}`, -4, true},
		{"expired-name", `{"id":1,"result":null,"error":{"code":-4,"message":"name expired: 'id/test'"}}`, -4, true},
		{"wrong-code", `{"id":1,"result":null,"error":{"code":-8,"message":"name expired"}}`, -8, false},
		{"near-message", `{"id":1,"result":null,"error":{"code":-4,"message":"name expired unexpectedly"}}`, -4, false},
		{"missing-result", `{"id":1,"error":{"code":-4,"message":"name expired"}}`, 0, false},
		{"non-null-result", `{"id":1,"result":"live","error":{"code":-4,"message":"name expired"}}`, 0, false},
		{"missing-id", `{"result":null,"error":{"code":-4,"message":"name expired"}}`, 0, false},
		{"wrong-id", `{"id":2,"result":null,"error":{"code":-4,"message":"name expired"}}`, 0, false},
		{"null-id", `{"id":null,"result":null,"error":{"code":-4,"message":"name expired"}}`, 0, false},
		{"missing-code", `{"id":1,"result":null,"error":{"message":"name expired"}}`, 0, false},
		{"fractional-code", `{"id":1,"result":null,"error":{"code":-4.5,"message":"name expired"}}`, 0, false},
		{"string-code", `{"id":1,"result":null,"error":{"code":"-4","message":"name expired"}}`, 0, false},
		{"null-code", `{"id":1,"result":null,"error":{"code":null,"message":"name expired"}}`, 0, false},
		{"missing-message", `{"id":1,"result":null,"error":{"code":-4}}`, 0, false},
		{"null-message", `{"id":1,"result":null,"error":{"code":-4,"message":null}}`, 0, false},
		{"numeric-message", `{"id":1,"result":null,"error":{"code":-4,"message":7}}`, 0, false},
		{"array-error", `{"id":1,"result":null,"error":[-4,"name expired"]}`, 0, false},
		{"extra-top", `{"id":1,"result":null,"error":{"code":-4,"message":"name expired"},"extra":true}`, 0, false},
		{"duplicate-result", `{"id":1,"result":"live","result":null,"error":{"code":-4,"message":"name expired"}}`, 0, false},
		{"duplicate-code", `{"id":1,"result":null,"error":{"code":-8,"code":-4,"message":"name expired"}}`, 0, false},
		{"trailing", `{"id":1,"result":null,"error":{"code":-4,"message":"name expired"}} {}`, 0, false},
		{"empty", ``, 0, false}, {"text", `service unavailable`, 0, false},
	}
	for _, status := range []int{200, 500, 503} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("%d/%s", status, tc.name), func(t *testing.T) {
				node := rpcFixtureNode(t, status, tc.body)
				raw, err := node.Call(context.Background(), "name_show", "id/test")
				var application *su.RPCError
				if raw != nil {
					t.Fatal("error envelope returned a result")
				}
				if tc.code != 0 {
					if !errors.As(err, &application) || application.Code != tc.code || application.NameExpired() != tc.expired || err.Error() != "RPC_APPLICATION_ERROR" {
						t.Fatalf("typed RPC classification: %v", err)
					}
				} else if err != errNode || errors.As(err, &application) {
					t.Fatalf("malformed envelope became application fact: %v", err)
				}
			})
		}
	}
}

// Claim: only HTTP 200 with a complete success envelope returns bytes; non-200 success-shaped bodies remain unavailable.
func TestReadNodeRPCSuccess(t *testing.T) {
	for _, status := range []int{200, 500, 503} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			node := rpcFixtureNode(t, status, `{"id":1,"result":{"live":true},"error":null}`)
			raw, err := node.Call(context.Background(), "name_show", "id/test")
			if status == 200 {
				if err != nil || string(raw) != `{"live":true}` {
					t.Fatal("valid success refused", err)
				}
			} else if raw != nil || err != errNode {
				t.Fatal("HTTP failure became success")
			}
		})
	}
}
