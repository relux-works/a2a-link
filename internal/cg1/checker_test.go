package cg1

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/a2a-swarm/internal/admission"
	"github.com/relux-works/swarma-chain-lab/experiments/grantcheck"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
)

type nodeFunc func(context.Context, string, ...any) (json.RawMessage, error)

func (f nodeFunc) Call(c context.Context, m string, a ...any) (json.RawMessage, error) {
	return f(c, m, a...)
}
func testChecker(t *testing.T, node nodeFunc) *checker {
	t.Helper()
	core, e := grantcheck.New(grantcheck.Config{ExecutorKey: xonly(9), Terms: unitTermsLookup, Freshness: testFreshness(600*time.Second, 120*time.Second, 0), ConstructionProfile: "W", Identity: "alice", AgentName: "id/test-agent", LandlordName: "id/test-landlord", IssuerPubkey: xonly(1), StateDir: stateDir(t), Node: node, Now: func() time.Time { return time.Unix(500, 0) }})
	if e != nil {
		t.Fatal(e)
	}
	return &checker{core: core, identity: "alice", own: xonly(3), timeout: 20 * time.Millisecond}
}
func incoming(c *checker) admission.Inbound {
	return admission.Inbound{Nostr: &admission.TrustedNostrInbound{Sender: xonly(2), Recipient: c.own, EventID: strings.Repeat("a", 64), Time: time.Unix(500, 0)}}
}
func want(t *testing.T, d admission.Decision, e error, v admission.Verdict, reason string, retry bool) {
	t.Helper()
	if e != nil || d.Verdict != v || d.Reason != reason || d.Retryable != retry {
		t.Fatalf("decision=%+v err=%v", d, e)
	}
}

// Exact CG1 table: all documented codes preserve direction and retryability;
// inconsistent closed/decision/retry fields and unknown text fail closed.
func TestReasonMapping(t *testing.T) {
	rows := []struct {
		code          grantcheck.Code
		in, out       admission.Verdict
		retry, closed bool
	}{
		{grantcheck.CodeLive, admission.Live, admission.Live, false, false},
		{grantcheck.CodeNoGrant, admission.Exchange, admission.Refused, false, false},
		{grantcheck.CodeNotYet, admission.Exchange, admission.Refused, false, false},
		{grantcheck.CodeExpired, admission.Exchange, admission.Refused, false, false},
		{grantcheck.CodeSealSpent, admission.Exchange, admission.Refused, false, true},
		{grantcheck.CodeLandlordRotated, admission.Exchange, admission.Refused, false, true},
		{grantcheck.CodeLandlordChanged, admission.Exchange, admission.Refused, false, true},
	}
	for _, code := range []grantcheck.Code{grantcheck.CodeIdentityPending, grantcheck.CodeGrantPending, grantcheck.CodeVerifierUnavailable, grantcheck.CodeStateUnavailable, grantcheck.CodeClockInvalid, grantcheck.CodeCancelled, grantcheck.CodeBusy, grantcheck.CodeNodeNotSynced, grantcheck.CodeTipStale, grantcheck.CodeTipBelowFloor} {
		rows = append(rows, struct {
			code          grantcheck.Code
			in, out       admission.Verdict
			retry, closed bool
		}{code, admission.Refused, admission.Refused, true, false})
	}
	for _, code := range []grantcheck.Code{grantcheck.CodeBindingMismatch, grantcheck.CodeInvalidPresentation, grantcheck.CodeOversize, grantcheck.CodeInvalidPeer, grantcheck.CodeCheckFailed, grantcheck.CodeExecutorMismatch, grantcheck.CodeTermsInvalid, grantcheck.CodeTipFuture, grantcheck.CodeIssuanceMismatch, grantcheck.CodeCapacityExceeded} {
		rows = append(rows, struct {
			code          grantcheck.Code
			in, out       admission.Verdict
			retry, closed bool
		}{code, admission.Refused, admission.Refused, false, false})
	}
	for _, r := range rows {
		for _, in := range []bool{false, true} {
			t.Run(string(r.code)+map[bool]string{true: "/in", false: "/out"}[in], func(t *testing.T) {
				w := r.out
				if in {
					w = r.in
				}
				v := grantcheck.Verdict{Code: r.code, Decision: grantcheck.Refused, Retryable: r.retry, Closed: r.closed}
				if w == admission.Live {
					v.Decision = grantcheck.Live
				}
				if w == admission.Exchange {
					v.Decision = grantcheck.Exchange
				}
				want(t, decision(v, in), nil, w, string(r.code), r.retry)
				for _, field := range []string{"closed", "retry", "decision", "code"} {
					b := v
					switch field {
					case "closed":
						b.Closed = !b.Closed
					case "retry":
						b.Retryable = !b.Retryable
					case "decision":
						b.Decision = "unknown"
					case "code":
						b.Code = "private-node-error"
					}
					want(t, decision(b, in), nil, admission.Refused, "check_failed", false)
				}
			})
		}
	}
}

// Metadata comes only from the trusted projection. Plausible Matrix/body claims
// cannot reach CG1; missing proofs route to exchange and never permit a send.
func TestTrustedInputBoundary(t *testing.T) {
	var calls atomic.Int64
	c := testChecker(t, func(context.Context, string, ...any) (json.RawMessage, error) {
		calls.Add(1)
		return nil, errors.New("private-node-error")
	})
	good := incoming(c)
	d, e := c.Inbound(context.Background(), good)
	want(t, d, e, admission.Exchange, "no_grant", false)
	for _, mode := range []string{"missing", "sender", "recipient", "event", "time", "subsecond", "oversize", "empty-proof"} {
		t.Run(mode, func(t *testing.T) {
			in := incoming(c)
			reason := "invalid_peer"
			switch mode {
			case "missing":
				in.Nostr = nil
				in.Sender = xonly(2)
				in.Body = []byte(`{"sender":"` + xonly(2) + `"}`)
			case "sender":
				in.Nostr.Sender = "@alice:example.invalid"
			case "recipient":
				in.Nostr.Recipient = xonly(4)
			case "event":
				in.Nostr.EventID = "claimed"
			case "time":
				in.Nostr.Time = time.Time{}
			case "subsecond":
				in.Nostr.Time = time.Unix(500, 1)
			case "oversize":
				reason = "oversize"
				in.Nostr.Presentation = &admission.NostrPresentation{Bytes: make([]byte, grantcheck.MaxPresentationBytes+1)}
			case "empty-proof":
				reason = "invalid_presentation"
				in.Nostr.Presentation = &admission.NostrPresentation{}
			}
			d, e := c.Inbound(context.Background(), in)
			want(t, d, e, admission.Refused, reason, false)
		})
	}
	for _, out := range []admission.Outbound{{Identity: "alice"}, {Identity: "other", Nostr: &admission.TrustedNostrOutbound{Recipient: xonly(2)}}} {
		d, e := c.Outbound(context.Background(), out)
		want(t, d, e, admission.Refused, "invalid_peer", false)
	}
	d, e = c.Outbound(context.Background(), admission.Outbound{Identity: "alice", Nostr: &admission.TrustedNostrOutbound{Recipient: xonly(2)}})
	want(t, d, e, admission.Refused, "no_grant", false)
	if calls.Load() != 0 {
		t.Fatal("untrusted/absent input reached node")
	}
	c.Close()
	d, e = c.Inbound(context.Background(), good)
	want(t, d, e, admission.Refused, "check_failed", false)
}

// A cryptographically shaped proof reaches the real CG1/K1 Node call. The
// adapter's500ms budget cancels a cooperative blocked node (core default5s),
// without detached work. This is not a bound on a wedged filesystem syscall.
func TestDeadlineAndContention(t *testing.T) {
	entered := make(chan struct{}, 1)
	finished := make(chan struct{}, 1)
	c := testChecker(t, func(ctx context.Context, _ string, _ ...any) (json.RawMessage, error) {
		entered <- struct{}{}
		<-ctx.Done()
		finished <- struct{}{}
		return nil, ctx.Err()
	})
	c.timeout = 500 * time.Millisecond
	in := incoming(c)
	raw := unitGrant(t)
	id, e := kernel.PresentationID(raw)
	if e != nil {
		t.Fatal(e)
	}
	in.Nostr.Presentation = &admission.NostrPresentation{GrantID: id, Bytes: raw}
	done := make(chan admission.Decision, 1)
	started := time.Now()
	parent, stop := context.WithCancel(context.Background())
	defer stop()
	go func() { d, _ := c.Inbound(parent, in); done <- d }()
	select {
	case <-entered:
	case early := <-done:
		t.Fatalf("node not reached; decision=%+v", early)
	case <-time.After(time.Second):
		t.Fatal("node not reached")
	}
	d, e := c.Inbound(context.Background(), in)
	want(t, d, e, admission.Refused, "busy", true)
	select {
	case d = <-done:
	case <-time.After(time.Second):
		t.Fatal("deadline not enforced")
	}
	want(t, d, nil, admission.Refused, "cancelled", true)
	if time.Since(started) > time.Second {
		t.Fatal("deadline not bounded")
	}
	select {
	case <-finished:
	default:
		t.Fatal("node work leaked")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d, e = c.Inbound(ctx, in)
	want(t, d, e, admission.Refused, "cancelled", true)
}

// Closing a session cancels a real in-flight CG1/K1 check, joins its cooperative
// Node call, and cannot turn the interrupted result into Live.
func TestCloseCancels(t *testing.T) {
	entered := make(chan struct{}, 1)
	finished := make(chan struct{}, 1)
	c := testChecker(t, func(ctx context.Context, _ string, _ ...any) (json.RawMessage, error) {
		entered <- struct{}{}
		<-ctx.Done()
		finished <- struct{}{}
		return nil, ctx.Err()
	})
	c.timeout = 5 * time.Second
	c.life, c.cancel = context.WithCancel(context.Background())
	defer c.cancel()
	in := incoming(c)
	raw := unitGrant(t)
	id, err := kernel.PresentationID(raw)
	if err != nil {
		t.Fatal(err)
	}
	in.Nostr.Presentation = &admission.NostrPresentation{GrantID: id, Bytes: raw}
	done := make(chan admission.Decision, 1)
	go func() { d, _ := c.Inbound(context.Background(), in); done <- d }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("close control did not reach node")
	}
	c.Close()
	select {
	case d := <-done:
		want(t, d, nil, admission.Refused, "check_failed", false)
	case <-time.After(time.Second):
		t.Fatal("close did not cancel pending check")
	}
	select {
	case <-finished:
	default:
		t.Fatal("close left node work running")
	}
}
