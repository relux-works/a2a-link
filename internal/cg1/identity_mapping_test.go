package cg1

import (
	"context"
	"testing"

	"github.com/relux-works/a2a-swarm/internal/admission"
	"github.com/relux-works/swarma-chain-lab/experiments/grantcheck"
)

// Claim: expired identities are closed, named and nonretryable on both adapters/directions; contradictory flags fail closed and node unavailability stays retryable.
func TestIdentityExpiredMapping(t *testing.T) {
	for _, matrix := range []bool{false, true} {
		for _, inbound := range []bool{false, true} {
			mapping := decision
			if matrix {
				mapping = matrixDecision
			}
			v := grantcheck.Verdict{Decision: grantcheck.Refused, Code: grantcheck.CodeIdentityExpired, Closed: true}
			want(t, mapping(v, inbound), nil, admission.Refused, "identity_expired", false)
			for _, field := range []string{"closed", "retry", "decision"} {
				bad := v
				switch field {
				case "closed":
					bad.Closed = false
				case "retry":
					bad.Retryable = true
				case "decision":
					bad.Decision = grantcheck.Exchange
				}
				d := mapping(bad, inbound)
				if d.Verdict != admission.Refused || d.Reason == "identity_expired" || d.Retryable {
					t.Fatalf("contradictory identity expiry admitted: %+v", d)
				}
			}
			down := grantcheck.Verdict{Decision: grantcheck.Refused, Code: grantcheck.CodeVerifierUnavailable, Retryable: true}
			want(t, mapping(down, inbound), nil, admission.Refused, "verifier_unavailable", true)
		}
	}
}

// Claim: a typed expiry answer refines only its own existing check_failed refusal, never Live, retryable/state failures, or another request.
func TestNodeAnswerScope(t *testing.T) {
	ctx, answer := withNodeAnswer(context.Background())
	node := rpcFixtureNode(t, 500, `{"id":1,"result":null,"error":{"code":-4,"message":"name expired"}}`)
	_, err := node.Call(ctx, "name_show", "id/test")
	if err == nil || !answer.identityExpired.Load() {
		t.Fatal("typed expiry answer not retained")
	}
	base := grantcheck.Verdict{Decision: grantcheck.Refused, Code: grantcheck.CodeCheckFailed}
	got := answer.verdict(base)
	if got.Code != grantcheck.CodeIdentityExpired || !got.Closed || got.Retryable || got.Decision != grantcheck.Refused {
		t.Fatalf("expiry refusal lost: %+v", got)
	}
	_, other := withNodeAnswer(context.Background())
	if other.verdict(base).Code != grantcheck.CodeCheckFailed {
		t.Fatal("expiry leaked between requests")
	}
	for _, v := range []grantcheck.Verdict{
		{Decision: grantcheck.Live, Code: grantcheck.CodeLive},
		{Decision: grantcheck.Refused, Code: grantcheck.CodeVerifierUnavailable, Retryable: true},
		{Decision: grantcheck.Refused, Code: grantcheck.CodeStateUnavailable, Retryable: true},
		{Decision: grantcheck.Refused, Code: grantcheck.CodeCheckFailed, Closed: true},
		{Decision: grantcheck.Refused, Code: grantcheck.CodeCheckFailed, Retryable: true},
	} {
		if got := answer.verdict(v); got.Code != v.Code || got.Decision != v.Decision || got.Closed != v.Closed || got.Retryable != v.Retryable {
			t.Fatalf("typed answer replaced another verdict: %+v", got)
		}
	}
	for _, body := range []string{
		`{"id":1,"error":{"code":-4,"message":"name expired"}}`,
		`{"id":1,"result":null,"error":{"code":-8,"message":"name expired"}}`,
		`{"id":1,"result":null,"error":{"code":-4,"message":"name expired unexpectedly"}}`,
	} {
		ctx, answer := withNodeAnswer(context.Background())
		node := rpcFixtureNode(t, 500, body)
		_, _ = node.Call(ctx, "name_show", "id/test")
		if answer.identityExpired.Load() {
			t.Fatal("unproved lifecycle answer retained")
		}
	}
	ctx, answer = withNodeAnswer(context.Background())
	_, _ = node.Call(ctx, "getblock", "block")
	if answer.identityExpired.Load() {
		t.Fatal("non-name RPC became identity lifecycle fact")
	}
}
