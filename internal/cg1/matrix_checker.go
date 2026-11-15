package cg1

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"time"

	"github.com/relux-works/a2a-swarm/internal/admission"
	"github.com/relux-works/a2a-swarm/internal/cg1cosign"
	"github.com/relux-works/a2a-swarm/internal/matrix"
	"github.com/relux-works/swarma-chain-lab/experiments/grantcheck"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

type matrixGrantSource interface {
	InboundFrom(context.Context, grantcheck.SenderProof, *grantcheck.Presentation) grantcheck.Verdict
	OutboundFrom(context.Context, grantcheck.RecipientProof) grantcheck.Verdict
}
type matrixChecker struct {
	core                                  matrixGrantSource
	cosign                                cg1cosign.Verifier
	dir, state, binding, identity, userID string
	timeout                               time.Duration
	now                                   func() time.Time
	life                                  context.Context
	cancel                                context.CancelFunc
	node                                  *readNode
	closed                                atomic.Bool
}

func matrixDenied() admission.Decision { return deny("denied") }
func matrixStorage() admission.Decision {
	return admission.Decision{Verdict: admission.Refused, Reason: "storage_error", Retryable: true}
}
func matrixUnavailable() admission.Decision {
	return admission.Decision{Verdict: admission.Refused, Reason: "dependency_unavailable", Retryable: true}
}
func matrixDecision(v grantcheck.Verdict, inbound bool) admission.Decision {
	switch v.Code {
	case grantcheck.CodeCapacityExceeded, grantcheck.CodeExecutorMismatch, grantcheck.CodeTermsInvalid, grantcheck.CodeTipFuture, grantcheck.CodeIssuanceMismatch, grantcheck.CodeNodeNotSynced, grantcheck.CodeTipStale, grantcheck.CodeTipBelowFloor:
		return decision(v, inbound)
	}
	verdict, reason, retry := v.A2ADecision()
	d := admission.Decision{Verdict: admission.Refused, Reason: reason, Retryable: retry}
	switch verdict {
	case "live":
		d.Verdict = admission.Live
	case "exchange":
		if inbound {
			d.Verdict = admission.Exchange
		} else {
			d = deny("exchange_outbound")
		}
	case "refused":
	default:
		return deny("policy_invalid")
	}
	return admission.Normalize(d, nil)
}
func (c *matrixChecker) Inbound(ctx context.Context, in admission.Inbound) (admission.Decision, error) {
	if in.Nostr != nil || in.Kind != "m.room.message" || !matrix.ValidVerificationID(in.EventID, '$') || !matrix.ValidVerificationID(in.Sender, '@') {
		return matrixDenied(), nil
	}
	return c.check(ctx, "in", in.RoomID, in.EventID, in.Sender, in.Body), nil
}
func (c *matrixChecker) Outbound(ctx context.Context, out admission.Outbound) (admission.Decision, error) {
	if out.Nostr != nil || out.Kind != "m.room.message" || out.Identity != c.identity || out.TransactionID == "" || len(out.TransactionID) > 255 {
		return matrixDenied(), nil
	}
	return c.check(ctx, "out", out.RoomID, out.TransactionID, c.userID, out.Request), nil
}
func (c *matrixChecker) Close() error {
	c.closed.Store(true)
	if c.cancel != nil {
		c.cancel()
	}
	if c.node != nil {
		c.node.Close()
	}
	return nil
}
func (c *matrixChecker) check(parent context.Context, direction, room, id, sender string, raw []byte) admission.Decision {
	if c.closed.Load() {
		return deny("policy_error")
	}
	if parent == nil || parent.Err() != nil {
		return matrixUnavailable()
	}
	if !matrix.ValidVerificationID(room, '!') || len(raw) > matrix.EnvelopeEventContentBudget {
		return matrixDenied()
	}
	ctx, cancel := context.WithTimeout(parent, c.timeout)
	defer cancel()
	if c.life != nil {
		stop := context.AfterFunc(c.life, cancel)
		defer stop()
	}
	cfg, e := loadMatrixSettings(c.dir)
	if e != nil || matrixBinding(cfg) != c.binding || cfg.Identity != c.identity || cfg.UserID != c.userID {
		return deny("policy_invalid")
	}
	content, e := matrix.ParseStrictJSON(raw)
	if e != nil {
		return matrixDenied()
	}
	obj, ok := content.(map[string]any)
	if !ok || obj["msgtype"] != "m.text" {
		return matrixDenied()
	}
	text, ok := obj["body"].(string)
	if !ok {
		return matrixDenied()
	}
	encoded, ok := obj[matrix.EnvelopeContentKey].(string)
	if !ok {
		return matrixDenied()
	}
	envelope, e := matrix.DecodeEnvelope(encoded)
	if e != nil {
		return matrixDenied()
	}
	parsed, e := parseMatrixEnvelope(envelope)
	if e != nil {
		return matrixDenied()
	}
	s, e := durable.Open(c.state, "matrix.lock")
	if e != nil {
		return matrixStorage()
	}
	defer s.Close()
	journal, e := readMatrixJournal(s, c.binding)
	if e != nil {
		return matrixStorage()
	}
	key := strings.TrimPrefix(parsed.ID, "sha256:")
	file := "envelope-" + key + ".json"
	previous, e := s.Read(file, matrix.EnvelopeMaxBytes)
	if e != nil {
		return matrixStorage()
	}
	if _, exists := journal.Entries[key]; exists && len(previous) == 0 {
		return matrixStorage()
	}
	now := c.now().UTC().Truncate(time.Second)
	stamp := now.Format("2006-01-02T15:04:05Z")
	if stamp < journal.Watermark {
		return matrixUnavailable()
	}
	recipient := c.userID
	if direction == "out" {
		recipient = parsed.To
	}
	code := verifyMatrixEnvelope(cfg, envelope, room, recipient, []byte(text), now, stamp, parsed.ID, previous)
	if code != "accept" {
		if strings.HasSuffix(code, "_unavailable") {
			return matrixUnavailable()
		}
		return matrixDenied()
	}
	signer, e := c.cosign.Verify(envelope, obj[cg1cosign.ContentKey])
	if e != nil {
		return matrixDenied()
	}
	// The pin narrows the verified signer; it never supplies a substitute SenderProof key.
	peer, exists := cfg.Pins[sender]
	if !exists || peer.Key != signer || peer.Author != parsed.Author {
		return matrixDenied()
	}
	target, exists := cfg.Pins[parsed.To]
	if !exists || !validKey(target.Key) {
		return matrixDenied()
	}
	proof, e := matrixPresentation(parsed.Arguments)
	if e != nil {
		return matrixDenied()
	}
	rec := matrixDelivery{Direction: direction, Room: room, ID: id}
	prior, seen := journal.Entries[key]
	// One actual event/transaction cannot identify two different signed records.
	for knownID, known := range journal.Entries {
		if knownID != key && known == rec {
			return matrixDenied()
		}
	}
	if seen && prior != rec {
		return matrixDenied()
	}
	if !seen && len(journal.Entries) >= 256 {
		return matrixStorage()
	}
	if ctx.Err() != nil || c.closed.Load() {
		return matrixUnavailable()
	}
	var verdict grantcheck.Verdict
	if direction == "in" {
		verdict = c.core.InboundFrom(ctx, grantcheck.SenderProof{Transport: grantcheck.SwarmEnvelopeV2, Key: signer}, proof)
	} else {
		verdict = c.core.OutboundFrom(ctx, grantcheck.RecipientProof{Transport: grantcheck.SwarmEnvelopeV2, Keys: []string{target.Key}})
	}
	if ctx.Err() != nil || c.closed.Load() {
		return matrixUnavailable()
	}
	result := matrixDecision(verdict, direction == "in")
	if result.Verdict != admission.Live && result.Verdict != admission.Exchange {
		return result
	}
	// A grant check can cross an envelope/evidence window or a protected config refresh.
	finalNow := c.now().UTC().Truncate(time.Second)
	if finalNow.Before(now) {
		return matrixUnavailable()
	}
	current, ce := loadMatrixSettings(c.dir)
	if ce != nil || matrixBinding(current) != c.binding {
		return deny("policy_invalid")
	}
	finalStamp := finalNow.Format("2006-01-02T15:04:05Z")
	code = verifyMatrixEnvelope(current, envelope, room, recipient, []byte(text), finalNow, finalStamp, parsed.ID, previous)
	if code != "accept" {
		if strings.HasSuffix(code, "_unavailable") {
			return matrixUnavailable()
		}
		return matrixDenied()
	}
	if ctx.Err() != nil || c.closed.Load() {
		return matrixUnavailable()
	}
	// Persist exact bytes/id/watermark before permitting mailbox delivery or a send.
	if e = s.Write(file, envelope); e != nil {
		return matrixStorage()
	}
	journal.Entries[key] = rec
	if finalStamp > journal.Watermark {
		journal.Watermark = finalStamp
	}
	data, e := json.Marshal(journal)
	if e != nil || s.Write(matrixJournalName, data) != nil {
		return matrixStorage()
	}
	if ctx.Err() != nil || c.closed.Load() {
		return matrixUnavailable()
	}
	return result
}
