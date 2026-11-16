package cg1

import (
	"context"
	"encoding/hex"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/a2a-swarm/internal/admission"
	"github.com/relux-works/swarma-chain-lab/experiments/grantcheck"
)

// Only grantcheck.New constructs this production backend. No injectable factory
// or verdict cache can bypass K1. CG1 owns cross-process state/try-locks.
type nostrGrantSource interface {
	Inbound(context.Context, string, *grantcheck.Presentation) grantcheck.Verdict
	Outbound(context.Context, string) grantcheck.Verdict
}

type checker struct {
	core          nostrGrantSource
	own, identity string
	timeout       time.Duration
	closed        atomic.Bool
	life          context.Context
	cancel        context.CancelFunc
	node          *readNode
}

func validID(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func validKey(s string) bool {
	if !validID(s) {
		return false
	}
	b, _ := hex.DecodeString(s)
	_, e := schnorr.ParsePubKey(b)
	return e == nil
}
func deny(reason string) admission.Decision {
	return admission.Decision{Verdict: admission.Refused, Reason: reason}
}

func (c *checker) Inbound(ctx context.Context, in admission.Inbound) (admission.Decision, error) {
	if c.closed.Load() {
		return deny("check_failed"), nil
	}
	n := in.Nostr
	if n == nil || !validKey(n.Sender) || n.Recipient != c.own || !validID(n.EventID) || n.Time.IsZero() || n.Time.Unix() < 0 || n.Time.Unix() > 253402300799 || n.Time.Nanosecond() != 0 {
		return deny("invalid_peer"), nil
	}
	if ctx == nil || ctx.Err() != nil {
		return cancelled(), nil
	}
	ctx, cancel := c.callContext(ctx)
	defer cancel()
	var proof *grantcheck.Presentation
	if n.Presentation != nil {
		if len(n.Presentation.Bytes) > grantcheck.MaxPresentationBytes {
			return deny("oversize"), nil
		}
		proof = &grantcheck.Presentation{GrantID: n.Presentation.GrantID, Bytes: append([]byte(nil), n.Presentation.Bytes...)}
	}
	ctx, answer := withNodeAnswer(ctx)
	v := answer.verdict(c.core.Inbound(ctx, n.Sender, proof))
	if c.closed.Load() {
		return deny("check_failed"), nil
	}
	if ctx.Err() != nil {
		return cancelled(), nil
	}
	return decision(v, true), nil
}
func (c *checker) Outbound(ctx context.Context, out admission.Outbound) (admission.Decision, error) {
	if c.closed.Load() {
		return deny("check_failed"), nil
	}
	if out.Identity != c.identity || out.Nostr == nil || !validKey(out.Nostr.Recipient) {
		return deny("invalid_peer"), nil
	}
	if ctx == nil || ctx.Err() != nil {
		return cancelled(), nil
	}
	ctx, cancel := c.callContext(ctx)
	defer cancel()
	ctx, answer := withNodeAnswer(ctx)
	v := answer.verdict(c.core.Outbound(ctx, out.Nostr.Recipient))
	if c.closed.Load() {
		return deny("check_failed"), nil
	}
	if ctx.Err() != nil {
		return cancelled(), nil
	}
	return decision(v, false), nil
}
func (c *checker) Close() error {
	c.closed.Store(true)
	if c.cancel != nil {
		c.cancel()
	}
	if c.node != nil {
		c.node.Close()
	}
	return nil
}
func (c *checker) callContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(parent, c.timeout)
	if c.life == nil {
		return ctx, cancel
	}
	stop := context.AfterFunc(c.life, cancel)
	return ctx, func() { stop(); cancel() }
}
func cancelled() admission.Decision {
	return admission.Decision{Verdict: admission.Refused, Reason: "cancelled", Retryable: true}
}

// Validate CG1's exact routing table as well as admission's closed vocabulary.
// A malformed/unknown future verdict must never become permission to deliver.
func decision(v grantcheck.Verdict, inbound bool) admission.Decision {
	want := grantcheck.Refused
	retry, closed := false, false
	switch v.Code {
	case grantcheck.CodeLive:
		want = grantcheck.Live
	case grantcheck.CodeNoGrant, grantcheck.CodeNotYet, grantcheck.CodeExpired:
		if inbound {
			want = grantcheck.Exchange
		}
	case grantcheck.CodeIdentityExpired:
		closed = true
	case grantcheck.CodeSealSpent, grantcheck.CodeLandlordRotated, grantcheck.CodeLandlordChanged:
		closed = true
		if inbound {
			want = grantcheck.Exchange
		}
	case grantcheck.CodeVerifierUnavailable, grantcheck.CodeStateUnavailable, grantcheck.CodeBusy, grantcheck.CodeCancelled, grantcheck.CodeClockInvalid, grantcheck.CodeGrantPending, grantcheck.CodeIdentityPending, grantcheck.CodeNodeNotSynced, grantcheck.CodeTipStale, grantcheck.CodeTipBelowFloor:
		retry = true
	case grantcheck.CodeBindingMismatch, grantcheck.CodeInvalidPresentation, grantcheck.CodeOversize, grantcheck.CodeInvalidPeer, grantcheck.CodeCheckFailed, grantcheck.CodeCapacityExceeded, grantcheck.CodeExecutorMismatch, grantcheck.CodeTermsInvalid, grantcheck.CodeTipFuture, grantcheck.CodeIssuanceMismatch:
	default:
		return deny("check_failed")
	}
	if v.Decision != want || v.Retryable != retry || v.Closed != closed {
		return deny("check_failed")
	}
	d := admission.Decision{Verdict: admission.Refused, Reason: string(v.Code), Retryable: retry}
	if want == grantcheck.Live {
		d.Verdict = admission.Live
	}
	if want == grantcheck.Exchange {
		d.Verdict = admission.Exchange
	}
	return admission.Normalize(d, nil)
}
