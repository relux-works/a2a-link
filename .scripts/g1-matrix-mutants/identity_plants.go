package main

import "os"

// Each control names a specific classification witness; no unrelated failure is a kill.
func identityPlants() []plant {
	const node = "internal/cg1/node.go"
	const anchor = `result, rpcError := envelope["result"], envelope["error"]`
	p := []plant{
		{"rpc-expiry-typed-answer", "a complete expired-name RPC answer retains its named lifecycle classification", "./internal/cg1", "TestNodeAnswerScope", "typed expiry answer not retained", []edit{{node, `answer.identityExpired.Store(true)`, `answer.identityExpired.Store(false)`, 1}}},
		{"rpc-missing-result", "result must be explicitly present beside an error", "./internal/cg1", "TestReadNodeRPCEnvelope/500/missing-result", "malformed envelope became application fact", []edit{{node, anchor, `if _,ok:=envelope["result"];!ok {envelope["result"]=json.RawMessage("null")}; ` + anchor, 1}}},
		{"rpc-non-null-result", "result must be null beside an error", "./internal/cg1", "TestReadNodeRPCEnvelope/500/non-null-result", "malformed envelope became application fact", []edit{{node, `!bytes.Equal(bytes.TrimSpace(result), []byte("null")) || `, ``, 1}}},
		{"rpc-missing-id", "the response id must be explicitly present", "./internal/cg1", "TestReadNodeRPCEnvelope/500/missing-id", "malformed envelope became application fact", []edit{{node, anchor, `if _,ok:=envelope["id"];!ok {envelope["id"]=json.RawMessage("1")}; ` + anchor, 1}}},
		{"rpc-duplicate-members", "strict JSON rejects duplicate members", "./internal/cg1", "TestReadNodeRPCEnvelope/500/duplicate-result", "malformed envelope became application fact", []edit{{node, `sealwatch.DecodeJSON(raw, &envelope)`, `json.Unmarshal(raw, &envelope)`, 1}}},
		{"rpc-http-success", "success-shaped non-200 replies remain unavailable", "./internal/cg1", "TestReadNodeRPCSuccess/500", "HTTP failure became success", []edit{{node, `if res.StatusCode != http.StatusOK {`, `if false && res.StatusCode != http.StatusOK {`, 1}}},
		{"rpc-expiry-code", "name-expiry text with another code is not an expiry fact", "./internal/cg1", "TestNodeAnswerScope", "unproved lifecycle answer retained", []edit{{node, `method == "name_show" && application.NameExpired()`, `method == "name_show" && application.Message == "name expired"`, 1}}},
		{"identity-expiry-route", "expiry is closed and refused in both directions", "./internal/cg1", "TestIdentityExpiredMapping", "Reason:check_failed", []edit{{"internal/cg1/checker.go", `case grantcheck.CodeIdentityExpired:
		closed = true`, `case grantcheck.CodeIdentityExpired:
        closed = false`, 1}}},
		{"verifier-unavailable-route", "node unavailability remains named and retryable on Matrix", "./internal/cg1", "TestIdentityExpiredMapping", "Reason:dependency_unavailable", []edit{{checker, `grantcheck.CodeIdentityExpired, grantcheck.CodeVerifierUnavailable,`, `grantcheck.CodeIdentityExpired,`, 1}}},
		{"request-local-expiry", "a typed answer cannot replace successful admission", "./internal/cg1", "TestNodeAnswerScope", "typed answer replaced another verdict", []edit{{node, `a.identityExpired.Load() && v.Decision == grantcheck.Refused && v.Code == grantcheck.CodeCheckFailed && !v.Closed && !v.Retryable`, `a.identityExpired.Load()`, 1}}},
	}
	if os.Getenv("CG1_REGTEST") == "1" {
		p = append(p,
			plant{"core-rpc-expiry-route", "a complete RPC expiry answer crosses the real backend as named refusal", "./internal/cg1", "TestCoreIdentityExpired/agent/RPCEnvelopes/valid-expired", "Reason:check_failed", []edit{{node, `answer.identityExpired.Store(true)`, `answer.identityExpired.Store(false)`, 1}}},
			plant{"core-node-down-route", "stopped genuine Core remains named and retryable on Matrix", "./internal/cg1", "TestCoreIdentityExpired/agent/NodeDown", "Reason:dependency_unavailable", []edit{{checker, `grantcheck.CodeIdentityExpired, grantcheck.CodeVerifierUnavailable,`, `grantcheck.CodeIdentityExpired,`, 1}}},
		)
	}
	return p
}
