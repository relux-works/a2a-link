package cg1

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/relux-works/a2a-swarm/internal/admission"
	"github.com/relux-works/a2a-swarm/internal/cg1cosign"
	"github.com/relux-works/a2a-swarm/internal/matrix"
	"github.com/relux-works/swarma-chain-lab/experiments/grantcheck"
)

// OriginCode is the closed, secret-free outcome of one run-origin check. Only
// OriginLive carries facts; every other value is a refusal without facts.
type OriginCode string

const (
	OriginLive OriginCode = "live"
	// The protected policy is missing, unreadable or no longer the one this
	// checker was opened with.
	OriginPolicyInvalid OriginCode = "policy_invalid"
	// The signed inner request, its co-signature or its pinned signer did not verify.
	OriginInnerInvalid OriginCode = "inner_request_invalid"
	// The signed inner request names a different recipient.
	OriginRecipientMismatch OriginCode = "inner_request_recipient"
	OriginGrantAbsent       OriginCode = "grant_absent"
	OriginGrantExpired      OriginCode = "grant_expired"
	OriginSealSpent         OriginCode = "seal_spent"
	OriginLandlordChanged   OriginCode = "landlord_changed"
	OriginGrantRefused      OriginCode = "grant_refused"
	OriginTipStale          OriginCode = "tip_stale"
	// The chain tip changed while the grant was being checked.
	OriginTipMoved    OriginCode = "tip_moved"
	OriginUnavailable OriginCode = "unavailable"
	OriginClosed      OriginCode = "closed"
)

// OriginScope carries host-derived values only. ScopeDir is an existing, empty,
// private directory that belongs to exactly one checker.
type OriginScope struct {
	Identity  string
	UserID    string
	PolicyDir string
	ScopeDir  string
}

// OriginEvent is a retained Matrix event read by the caller from the agent's
// own store. Nothing in it confers authority before Check verifies it.
type OriginEvent struct {
	RoomID  string
	EventID string
	Sender  string
	Content []byte
}

// OriginFacts are three 64-character lowercase hex values. RequestID is the
// content ID of the verified signed inner request, never a Matrix event ID.
type OriginFacts struct {
	RequestID string
	GrantID   string
	TipHash   string
}

type originNode interface {
	Call(ctx context.Context, method string, args ...any) (json.RawMessage, error)
}

// OriginChecker is a read-only companion of the Matrix admission checker. It
// verifies one retained inbound request without recording a delivery, so the
// same event can be checked again by a later validation. It owns its grant
// state scope and its node route; nothing is shared with another checker.
type OriginChecker struct {
	core                                  matrixGrantSource
	cosign                                cg1cosign.Verifier
	node                                  originNode
	release                               func()
	dir, scope, binding, identity, userID string
	timeout                               time.Duration
	now                                   func() time.Time
	life                                  context.Context
	cancel                                context.CancelFunc
	closed                                atomic.Bool
}

// OpenOriginChecker uses the existing protected Matrix policy loader and the
// existing grant backend constructor. A scope that already holds any entry is
// refused: a checker never adopts state left by another one.
func OpenOriginChecker(s OriginScope) (*OriginChecker, error) {
	if s.Identity == "" || !matrix.ValidVerificationID(s.UserID, '@') {
		return nil, errConfig
	}
	cfg, e := loadMatrixSettings(s.PolicyDir)
	if e != nil || cfg.Identity != s.Identity || cfg.UserID != s.UserID {
		return nil, errConfig
	}
	root, e := openPrivateRoot(s.ScopeDir)
	if e != nil {
		return nil, errConfig
	}
	root.Close()
	entries, e := os.ReadDir(s.ScopeDir)
	if e != nil || len(entries) != 0 {
		return nil, errConfig
	}
	grantState := filepath.Join(s.ScopeDir, "grantcheck-state")
	if e = admission.PrivateDir(grantState); e != nil {
		return nil, errConfig
	}
	freshness, terms, e := cfg.grantPolicy.resolve()
	if e != nil {
		return nil, errConfig
	}
	node, e := newReadNode(cfg.RPC)
	if e != nil {
		return nil, errConfig
	}
	core, e := grantcheck.NewForTransport(grantcheck.Config{ConstructionProfile: "W", Identity: s.Identity, AgentName: cfg.AgentName, LandlordName: cfg.LandlordName, IssuerPubkey: cfg.IssuerPubkey, ExecutorKey: cfg.ExecutorKey, Freshness: freshness, Terms: terms, StateDir: grantState, Node: node, CheckTimeout: time.Duration(cfg.TimeoutMS) * time.Millisecond}, grantcheck.SwarmEnvelopeV2)
	if e != nil {
		node.Close()
		return nil, errConfig
	}
	life, cancel := context.WithCancel(context.Background())
	return &OriginChecker{core: core, cosign: cg1cosign.BIP340{}, node: node, release: node.Close, dir: s.PolicyDir, scope: s.ScopeDir, binding: matrixBinding(cfg), identity: s.Identity, userID: s.UserID, timeout: time.Duration(cfg.TimeoutMS) * time.Millisecond, now: time.Now, life: life, cancel: cancel}, nil
}

// Scope names the private directory this checker owns.
func (c *OriginChecker) Scope() string { return c.scope }

// Close is local and idempotent. It cancels a check in flight.
func (c *OriginChecker) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	if c.cancel != nil {
		c.cancel()
	}
	if c.release != nil {
		c.release()
	}
	return nil
}

func (c *OriginChecker) settings() (matrixSettings, bool) {
	cfg, e := loadMatrixSettings(c.dir)
	if e != nil || matrixBinding(cfg) != c.binding || cfg.Identity != c.identity || cfg.UserID != c.userID {
		return cfg, false
	}
	return cfg, true
}

// Terms returns the protected contract terms by their hash, freshly read. The
// policy loader has already applied the existing terms validator to them.
func (c *OriginChecker) Terms() (map[string][]byte, OriginCode) {
	if c.closed.Load() {
		return nil, OriginClosed
	}
	cfg, ok := c.settings()
	if !ok {
		return nil, OriginPolicyInvalid
	}
	out := make(map[string][]byte, len(cfg.Terms))
	for hash, encoded := range cfg.Terms {
		raw, e := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if e != nil || len(raw) == 0 {
			return nil, OriginPolicyInvalid
		}
		out[hash] = bytes.Clone(raw)
	}
	return out, OriginLive
}

// tip reads the current best block from this checker's own node and applies
// the protected freshness policy to it. Every call is a new chain read.
func (c *OriginChecker) tip(ctx context.Context, cfg matrixSettings, now time.Time) (string, OriginCode) {
	if cfg.MaxTipAgeSeconds == nil || cfg.MaxFutureSkewSeconds == nil || cfg.MinimumHeight == nil {
		return "", OriginPolicyInvalid
	}
	raw, e := c.node.Call(ctx, "getblockchaininfo")
	if e != nil {
		return "", OriginUnavailable
	}
	var info struct {
		Blocks  *int64 `json:"blocks"`
		Headers *int64 `json:"headers"`
		Best    string `json:"bestblockhash"`
		Initial bool   `json:"initialblockdownload"`
	}
	if json.Unmarshal(raw, &info) != nil || info.Blocks == nil || info.Headers == nil || !validID(info.Best) {
		return "", OriginUnavailable
	}
	if info.Initial || *info.Headers != *info.Blocks || *info.Blocks < *cfg.MinimumHeight {
		return "", OriginTipStale
	}
	raw, e = c.node.Call(ctx, "getblockheader", info.Best)
	if e != nil {
		return "", OriginUnavailable
	}
	var header struct {
		Hash string `json:"hash"`
		Time *int64 `json:"time"`
	}
	if json.Unmarshal(raw, &header) != nil || header.Time == nil || header.Hash != info.Best {
		return "", OriginUnavailable
	}
	age := now.Unix() - *header.Time
	if age > *cfg.MaxTipAgeSeconds {
		return "", OriginTipStale
	}
	if -age > *cfg.MaxFutureSkewSeconds {
		return "", OriginUnavailable
	}
	return info.Best, OriginLive
}

func originEnvelopeCode(code string) OriginCode {
	if code == "accept" {
		return OriginLive
	}
	if strings.HasSuffix(code, "_unavailable") {
		return OriginUnavailable
	}
	return OriginInnerInvalid
}

// originGrantCode keeps the existing closed verdict routing: a malformed or
// inconsistent verdict can never become Live, and Exchange is not Live.
func originGrantCode(v grantcheck.Verdict) OriginCode {
	d := matrixDecision(v, true)
	if v.Code == grantcheck.CodeLive {
		if v.Decision == grantcheck.Live && d.Verdict == admission.Live {
			return OriginLive
		}
		return OriginGrantRefused
	}
	switch v.Code {
	case grantcheck.CodeNoGrant, grantcheck.CodeNotYet:
		return OriginGrantAbsent
	case grantcheck.CodeExpired:
		return OriginGrantExpired
	case grantcheck.CodeSealSpent:
		return OriginSealSpent
	case grantcheck.CodeLandlordChanged, grantcheck.CodeLandlordRotated:
		return OriginLandlordChanged
	case grantcheck.CodeTipStale, grantcheck.CodeTipBelowFloor, grantcheck.CodeNodeNotSynced:
		return OriginTipStale
	}
	if d.Verdict == admission.Refused && d.Retryable {
		return OriginUnavailable
	}
	return OriginGrantRefused
}

// Check verifies the exact signed inner request of one retained inbound event,
// the sender's grant and the current tip. It writes no delivery record.
func (c *OriginChecker) Check(parent context.Context, ev OriginEvent) (OriginFacts, OriginCode) {
	var zero OriginFacts
	if c.closed.Load() {
		return zero, OriginClosed
	}
	if parent == nil || parent.Err() != nil {
		return zero, OriginUnavailable
	}
	if !matrix.ValidVerificationID(ev.RoomID, '!') || !matrix.ValidVerificationID(ev.EventID, '$') || !matrix.ValidVerificationID(ev.Sender, '@') || len(ev.Content) > matrix.EnvelopeEventContentBudget {
		return zero, OriginInnerInvalid
	}
	ctx, cancel := context.WithTimeout(parent, c.timeout)
	defer cancel()
	if c.life != nil {
		stop := context.AfterFunc(c.life, cancel)
		defer stop()
	}
	cfg, ok := c.settings()
	if !ok {
		return zero, OriginPolicyInvalid
	}
	content, e := matrix.ParseStrictJSON(ev.Content)
	if e != nil {
		return zero, OriginInnerInvalid
	}
	obj, ok := content.(map[string]any)
	if !ok || obj["msgtype"] != "m.text" {
		return zero, OriginInnerInvalid
	}
	text, ok := obj["body"].(string)
	if !ok {
		return zero, OriginInnerInvalid
	}
	encoded, ok := obj[matrix.EnvelopeContentKey].(string)
	if !ok {
		return zero, OriginInnerInvalid
	}
	envelope, e := matrix.DecodeEnvelope(encoded)
	if e != nil {
		return zero, OriginInnerInvalid
	}
	parsed, e := parseMatrixEnvelope(envelope)
	if e != nil {
		return zero, OriginInnerInvalid
	}
	request := strings.TrimPrefix(parsed.ID, "sha256:")
	if !validID(request) {
		return zero, OriginInnerInvalid
	}
	if parsed.To != c.userID {
		return zero, OriginRecipientMismatch
	}
	now := c.now().UTC().Truncate(time.Second)
	stamp := now.Format("2006-01-02T15:04:05Z")
	if stamp < cfg.InitialWatermark {
		return zero, OriginUnavailable
	}
	code := originEnvelopeCode(verifyMatrixEnvelope(cfg, envelope, ev.RoomID, c.userID, []byte(text), now, stamp, parsed.ID, nil))
	if code != OriginLive { // inner request gate
		return zero, code
	}
	signer, e := c.cosign.Verify(envelope, obj[cg1cosign.ContentKey])
	if e != nil {
		return zero, OriginInnerInvalid
	}
	// The pin narrows the verified signer; it never supplies a substitute key.
	peer, exists := cfg.Pins[ev.Sender]
	if !exists || peer.Key != signer || peer.Author != parsed.Author {
		return zero, OriginInnerInvalid
	}
	target, exists := cfg.Pins[parsed.To]
	if !exists || !validKey(target.Key) {
		return zero, OriginInnerInvalid
	}
	proof, e := matrixPresentation(parsed.Arguments)
	if e != nil {
		return zero, OriginInnerInvalid
	}
	// A private scope holds no provisioned proof. The grant must be the one
	// presented inside the signed inner request.
	if proof == nil {
		return zero, OriginGrantAbsent
	}
	before, code := c.tip(ctx, cfg, now)
	if code != OriginLive {
		return zero, code
	}
	if ctx.Err() != nil || c.closed.Load() {
		return zero, OriginUnavailable
	}
	grantCtx, answer := withNodeAnswer(ctx)
	verdict := answer.verdict(c.core.InboundFrom(grantCtx, grantcheck.SenderProof{Transport: grantcheck.SwarmEnvelopeV2, Key: signer}, proof))
	if ctx.Err() != nil || c.closed.Load() {
		return zero, OriginUnavailable
	}
	if code = originGrantCode(verdict); code != OriginLive { // grant gate
		return zero, code
	}
	// The grant check can cross an envelope window, a policy refresh or a new block.
	finalNow := c.now().UTC().Truncate(time.Second)
	if finalNow.Before(now) {
		return zero, OriginUnavailable
	}
	current, ok := c.settings()
	if !ok {
		return zero, OriginPolicyInvalid
	}
	code = originEnvelopeCode(verifyMatrixEnvelope(current, envelope, ev.RoomID, c.userID, []byte(text), finalNow, finalNow.Format("2006-01-02T15:04:05Z"), parsed.ID, nil))
	if code != OriginLive {
		return zero, code
	}
	peer, exists = current.Pins[ev.Sender]
	if !exists || peer.Key != signer || peer.Author != parsed.Author {
		return zero, OriginInnerInvalid
	}
	after, code := c.tip(ctx, current, finalNow)
	if code != OriginLive {
		return zero, code
	}
	if after != before {
		return zero, OriginTipMoved
	}
	if ctx.Err() != nil || c.closed.Load() {
		return zero, OriginUnavailable
	}
	return OriginFacts{RequestID: request, GrantID: proof.GrantID, TipHash: before}, OriginLive
}
