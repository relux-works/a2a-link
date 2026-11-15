package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
)

// These are logical interfaces only. The native driver, peer/policy issuance,
// encoding, bootstrap and actual invocation boundary remain unimplemented.
type vaultDriver interface {
	Open(context.Context) (vaultConn, error)
}
type vaultConn interface {
	Prepare(context.Context, vaultRequest, vaultServiceVerification) (vaultPrepared, *vaultFailure)
	Close() error
}
type vaultPrepared interface {
	// Single-use. The driver rechecks current live peer/policy at native invoke.
	Invoke(context.Context, vaultServiceVerification) (vaultExchange, error)
	Discard() error
}
type vaultVerificationPoint string

const (
	vaultBeforeOperation vaultVerificationPoint = "before_operation"
	vaultAfterReply      vaultVerificationPoint = "after_reply"
)

type vaultServiceVerifier interface {
	VerifyService(context.Context, vaultConn, vaultVerificationPoint) (vaultServiceVerification, error)
}

// All authority/evidence issuance is absent in production; fixtures instantiate
// private witnesses only in same-package *_test.go files, never a constructor.
type vaultVerificationIssuer struct{ marker byte }
type vaultPeerWitness struct{ marker byte }
type vaultPolicyWitness struct{ marker byte }
type vaultServiceVerification struct {
	issuer *vaultVerificationIssuer
	conn   vaultConn
	peer   *vaultPeerWitness
	policy *vaultPolicyWitness
}

func (p vaultServiceVerification) validFor(c vaultConn) bool {
	return p.issuer != nil && p.peer != nil && p.policy != nil && !vaultIsNil(c) && vaultSameConn(p.conn, c)
}
func (p vaultServiceVerification) same(q vaultServiceVerification) bool {
	return p.issuer == q.issuer && p.peer == q.peer && p.policy == q.policy && vaultSameConn(p.conn, q.conn)
}
func vaultSameConn(a, b vaultConn) (same bool) {
	defer func() {
		if recover() != nil {
			same = false
		}
	}()
	return a == b
}

type vaultReceiptIssuer struct{ marker byte }
type vaultSubmissionReceipt struct {
	issuer    *vaultReceiptIssuer
	conn      vaultConn
	requestID string
	op        vaultOp
	phase     vaultInvocationPhase
}

func (r vaultSubmissionReceipt) Phase() vaultInvocationPhase { return r.phase }
func (r vaultSubmissionReceipt) matches(c vaultConn, req vaultRequest) bool {
	return r.issuer != nil && vaultSameConn(r.conn, c) && r.requestID == req.id && r.op == req.op && (r.phase == vaultNoInvocation || r.phase == vaultInvoked)
}

// The driver transfers ownership of reply buffers on return. The client wipes
// them on all outcomes; public Reply views are detached copies. Prepare must
// never invoke an operation, and its request is already a detached snapshot.
type vaultExchange struct {
	receipt  vaultSubmissionReceipt
	reply    vaultValue
	received bool
}

func (e vaultExchange) Receipt() vaultSubmissionReceipt { return e.receipt }
func (e vaultExchange) Reply() (vaultValue, bool)       { return e.reply.clone(), e.received }

type vaultDependency struct {
	Driver   vaultDriver
	Verifier vaultServiceVerifier
}
type vaultClient struct {
	selection vaultCredentialSelection
	dep       vaultDependency
	rand      io.Reader
}

// Reflection is used solely for the existing typed-nil dependency check; it
// never reads/writes private fixture fields or creates authority/evidence.
func vaultIsNil(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Func, reflect.Interface, reflect.Chan, reflect.Slice:
		return r.IsNil()
	}
	return false
}
func vaultNewClient(s vaultCredentialSelection, d *vaultDependency) (*vaultClient, *vaultFailure) {
	if s.issuer == nil || !s.observed.latched {
		return nil, vaultLocalFailure(vaultEContext)
	}
	if d == nil || vaultIsNil(d.Driver) {
		return nil, vaultLocalFailure(vaultEUnavailable)
	}
	if vaultIsNil(d.Verifier) {
		return nil, vaultLocalFailure(vaultEServerUntrusted)
	}
	s.observed = s.observed.clone()
	return &vaultClient{selection: s, dep: *d, rand: rand.Reader}, nil
}
func (c *vaultClient) requestID() (string, *vaultFailure) {
	var b [16]byte
	if _, e := io.ReadFull(c.rand, b[:]); e != nil {
		return "", vaultLocalFailure(vaultEInternal)
	}
	return hex.EncodeToString(b[:]), nil
}
func vaultGuardCheck(ctx context.Context, g vaultSelectionGuard, s vaultCredentialSelection) *vaultFailure {
	if ctx.Err() != nil {
		return vaultLocalFailure(vaultEUnavailable)
	}
	if vaultIsNil(g) {
		return vaultLocalFailure(vaultEBackendConfig)
	}
	if r := g.Check(ctx, s); r != nil {
		if r.Outcome != vaultNotSubmitted || !r.Code.Known() {
			return vaultLocalFailure(vaultEInternal)
		}
		return vaultLocalFailure(r.Code)
	}
	return nil
}
func vaultSafeCleanup(f func() error) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return f() == nil
}
func (c *vaultClient) Release(ctx context.Context, g vaultSelectionGuard, consume func([]byte) error) (report vaultAttemptReport) {
	report.Handoff = vaultHandoffNotEntered
	report.Cleanup = vaultCleanupNotNeeded
	var conn vaultConn
	var secret []byte
	defer func() {
		if recover() != nil {
			// Invoked work is classified inside operation(), and callback panics
			// have their own recovery below. After known success, a local guard
			// panic must not invent entry into the consumer.
			if report.Release != nil && report.Release.Outcome == vaultSucceeded {
				report.DeliveryDiagnosis = vaultDeliverySelection
			} else if report.Failure == nil {
				report.Failure = vaultLocalFailure(vaultEInternal)
			}
		}
		clear(secret)
		if !vaultIsNil(conn) {
			if vaultSafeCleanup(conn.Close) {
				if report.Cleanup != vaultCleanupFailed {
					report.Cleanup = vaultCleanupClosed
				}
			} else {
				report.Cleanup = vaultCleanupFailed
			}
		}
	}()
	if c == nil || c.selection.issuer == nil || !c.selection.observed.latched {
		report.Failure = vaultLocalFailure(vaultEContext)
		return
	}
	if consume == nil || vaultIsNil(g) {
		report.Failure = vaultLocalFailure(vaultEBackendConfig)
		return
	}
	if r := vaultGuardCheck(ctx, g, c.selection); r != nil {
		r.Stage = vaultStageAdmission
		report.Failure = r
		return
	}
	report.Failure = &vaultFailure{Outcome: vaultNotSubmitted, Code: vaultEInternal, Stage: vaultStageOpen}
	opened, err := c.dep.Driver.Open(ctx)
	conn = opened
	if err != nil || vaultIsNil(conn) {
		report.Failure = &vaultFailure{Outcome: vaultNotSubmitted, Code: vaultEUnavailable, Stage: vaultStageOpen}
		return
	}
	report.Failure = nil
	var session *vaultSession
	if c.selection.observed.mode == vaultSessionRegistered {
		report.Register = &vaultOperationReport{Op: vaultOpRegister}
		session, _, _ = c.operation(ctx, conn, g, report.Register, nil, &report)
		if report.Failure != nil {
			return
		}
	}
	report.Release = &vaultOperationReport{Op: vaultOpRelease}
	_, secret, report.Revision = c.operation(ctx, conn, g, report.Release, session, &report)
	if report.Failure != nil {
		return
	}
	if r := vaultGuardCheck(ctx, g, c.selection); r != nil {
		if ctx.Err() != nil {
			report.DeliveryDiagnosis = vaultDeliveryCancelled
		} else {
			report.DeliveryDiagnosis = vaultDeliverySelection
		}
		return
	}
	report.Handoff = vaultHandoffEntered
	// Isolate callback failures from native state; the valid release is known.
	func() {
		defer func() {
			if recover() != nil {
				report.Handoff = vaultHandoffPanicked
				report.DeliveryDiagnosis = vaultDeliveryPanicked
			}
		}()
		if consume(secret) != nil {
			report.Handoff = vaultHandoffFailed
			report.DeliveryDiagnosis = vaultDeliveryFailed
		} else {
			report.Handoff = vaultHandoffReturned
		}
	}()
	return
}
func (c *vaultClient) operation(ctx context.Context, conn vaultConn, g vaultSelectionGuard, op *vaultOperationReport, session *vaultSession, attempt *vaultAttemptReport) (registered *vaultSession, secret []byte, revision uint64) {
	op.Outcome = vaultNotSubmitted
	op.Invocation = vaultNoInvocation
	op.Stage = vaultStagePrepare
	var prepared vaultPrepared
	var exchange vaultExchange
	fail := func(r *vaultFailure) {
		r.Stage = op.Stage
		r.Op = op.Op
		op.Outcome = r.Outcome
		op.Code = r.Code
		op.Diagnosis = r.Diagnosis
		attempt.Failure = r
	}
	defer func() {
		if recover() != nil {
			if op.Outcome != vaultSucceeded {
				if op.Invocation == vaultNoInvocation {
					fail(vaultLocalFailure(vaultEInternal))
				} else if op.Invocation == "" {
					fail(vaultUnknownFailure(vaultDiagSubmission))
				} else {
					fail(vaultUnknownFailure(vaultDiagInternal))
				}
			}
		}
		exchange.reply.wipe()
		if !vaultIsNil(prepared) && !vaultSafeCleanup(prepared.Discard) {
			attempt.Cleanup = vaultCleanupFailed
		}
	}()
	if r := vaultGuardCheck(ctx, g, c.selection); r != nil {
		fail(r)
		return
	}
	id, r := c.requestID()
	if r != nil {
		fail(r)
		return
	}
	req := vaultReleaseRequest(id, c.selection.observed.identity, session, c.selection.observed.binding)
	if op.Op == vaultOpRegister {
		req = vaultRegisterRequest(id, c.selection.observed.identity)
	}
	op.Stage = vaultStageVerification
	proof, err := c.dep.Verifier.VerifyService(ctx, conn, vaultBeforeOperation)
	if err != nil || !proof.validFor(conn) {
		fail(vaultLocalFailure(vaultEServerUntrusted))
		return
	}
	op.Stage = vaultStagePrepare
	prepared, r = conn.Prepare(ctx, req.clone(), proof)
	if r != nil {
		if r.Outcome != vaultNotSubmitted || !r.Code.Known() {
			r = vaultLocalFailure(vaultEInternal)
		}
		fail(vaultLocalFailure(r.Code))
		return
	}
	if vaultIsNil(prepared) {
		fail(vaultLocalFailure(vaultEInternal))
		return
	}
	if r := vaultGuardCheck(ctx, g, c.selection); r != nil {
		fail(r)
		return
	}
	op.Stage = vaultStageVerification
	current, err := c.dep.Verifier.VerifyService(ctx, conn, vaultBeforeOperation)
	if err != nil || !current.validFor(conn) || !current.same(proof) {
		fail(vaultLocalFailure(vaultEServerUntrusted))
		return
	}
	if ctx.Err() != nil {
		fail(vaultLocalFailure(vaultEUnavailable))
		return
	}
	op.Stage = vaultStageInvoke
	// Until the trusted exact-request receipt returns, invocation is unproven.
	op.Invocation = ""
	exchange, err = prepared.Invoke(ctx, current)
	receipt := exchange.receipt
	if !receipt.matches(conn, req) || (receipt.phase == vaultNoInvocation && exchange.received) {
		fail(vaultUnknownFailure(vaultDiagSubmission))
		return
	}
	op.Invocation = receipt.phase
	if receipt.phase == vaultNoInvocation {
		if err != nil || ctx.Err() != nil {
			local := vaultLocalFailure(vaultEUnavailable)
			var reported *vaultFailure
			if errors.As(err, &reported) && reported != nil && reported.Outcome == vaultNotSubmitted && reported.Code.Known() {
				local = vaultLocalFailure(reported.Code)
			}
			fail(local)
		} else {
			fail(vaultLocalFailure(vaultEInternal))
		}
		return
	}
	if err != nil || !exchange.received {
		fail(vaultUnknownFailure(vaultDiagTransport))
		return
	}
	op.Stage = vaultStageReply
	after, err := c.dep.Verifier.VerifyService(ctx, conn, vaultAfterReply)
	if err != nil || !after.validFor(conn) || !after.same(current) {
		fail(vaultUnknownFailure(vaultDiagPeer))
		return
	}
	result, r := vaultClassify(req, exchange.reply)
	if r != nil {
		fail(r)
		return
	}
	if op.Op == vaultOpRegister {
		s, r := vaultParseRegister(result, c.selection.observed.identity)
		if r != nil {
			fail(r)
			return
		}
		registered = &s
	} else {
		b, rev, r := vaultParseRelease(result, c.selection.observed.identity, c.selection.observed.binding)
		if r != nil {
			fail(r)
			return
		}
		secret = append([]byte(nil), b...)
		revision = rev
	}
	op.Outcome = vaultSucceeded
	op.Code = ""
	op.Diagnosis = ""
	return
}
