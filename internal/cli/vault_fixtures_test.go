package cli

import (
	"context"
	"crypto/rand"
	"errors"
	"github.com/relux-works/a2a-swarm/internal/config"
	"strings"
	"testing"
)

// Fixture issuance lives ONLY in this normal same-package test file. No init,
// registry, native/signature claim, overlay or production fixture constructor.
type vaultFixtureProvider struct {
	value        vaultAdmittedContext
	calls        int
	err          error
	beforeReturn func(int)
}

func (p *vaultFixtureProvider) Current(context.Context) (vaultAdmittedContext, error) {
	p.calls++
	if p.beforeReturn != nil {
		p.beforeReturn(p.calls)
	}
	return p.value, p.err
}
func vaultFixtureContext(o vaultObservedSelection) vaultAdmittedContext {
	return vaultAdmittedContext{issuer: &vaultContextIssuer{1}, declared: o.Identity(), installDomain: o.identity.Domain, mappedIdentity: o.Identity(), binding: o.binding, local: o.local}
}
func vaultFixtureAdmitted(t *testing.T, o vaultObservedSelection) vaultCredentialSelection {
	t.Helper()
	s, r := vaultAdmit(o, vaultFixtureContext(o))
	if r != nil {
		t.Fatal(r)
	}
	return s
}
func vaultFixtureObserved(t *testing.T, mode string) vaultObservedSelection {
	t.Helper()
	c := config.Connection{ID: "fixture-a", URL: "https://matrix-a.example.invalid", ServerName: "a.example.invalid", Store: config.CredentialStore{Backend: config.BackendVaultV1}}
	b, e := c.Binding("fixture", false)
	if e != nil {
		t.Fatal(e)
	}
	o, r := vaultObserve(config.VaultSelection{Identity: config.VaultIdentity{Domain: "fixture-domain", Kind: vaultKindExplicit, Name: "fixture-a"}, SessionMode: mode}, "fixture", b)
	if r != nil {
		t.Fatal(r)
	}
	return o
}
func vaultFixtureGuard() vaultSelectionGuard {
	return vaultSelectionGuardFunc(func(context.Context, vaultCredentialSelection) *vaultFailure { return nil })
}

type vaultFake struct {
	openWithHandle                                       bool
	factory                                              int
	events                                               []string
	requests                                             []vaultRequest
	token                                                []byte
	buffers                                              [][]byte
	openErr, verifyErr, closeErr, discardErr             error
	proofMode                                            string
	panicAt                                              string
	reply                                                func(vaultRequest, int) (vaultValue, error)
	release                                              func(vaultRequest) (vaultValue, error)
	prepareFailure                                       *vaultFailure
	receiptMode                                          string
	failureOp                                            vaultOp
	beforeInvoke                                         func(vaultRequest)
	afterReply                                           func(vaultRequest)
	verifyHook                                           func(vaultVerificationPoint, int, *vaultFakeConn, *vaultServiceVerification)
	verifyCount                                          int
	conns                                                []*vaultFakeConn
	preparations, invocations, effects, closes, discards int
}
type cliVault = vaultFake
type vaultFakeConn struct {
	v             *vaultFake
	peer          *vaultPeerWitness
	policy        *vaultPolicyWitness
	issuer        *vaultVerificationIssuer
	receiptIssuer *vaultReceiptIssuer
}
type vaultFakePrepared struct {
	c    *vaultFakeConn
	req  vaultRequest
	used bool
}

func vaultNewFake(t *testing.T) *vaultFake {
	t.Helper()
	b := make([]byte, 24)
	if _, e := rand.Read(b); e != nil {
		t.Fatal(e)
	}
	return &vaultFake{token: b}
}
func (f *vaultFake) dep() *vaultDependency { return &vaultDependency{Driver: f, Verifier: f} }
func (f *vaultFake) Open(context.Context) (vaultConn, error) {
	f.events = append(f.events, "open")
	if f.panicAt == "open" {
		panic("injected-private")
	}
	if f.openErr != nil && !f.openWithHandle {
		return nil, f.openErr
	}
	c := &vaultFakeConn{f, &vaultPeerWitness{1}, &vaultPolicyWitness{1}, &vaultVerificationIssuer{1}, &vaultReceiptIssuer{1}}
	f.conns = append(f.conns, c)
	return c, f.openErr
}
func (f *vaultFake) VerifyService(_ context.Context, c vaultConn, point vaultVerificationPoint) (vaultServiceVerification, error) {
	f.events = append(f.events, "verify:"+string(point))
	f.verifyCount++
	if f.panicAt == "verify" {
		panic("injected-private")
	}
	if f.verifyErr != nil {
		return vaultServiceVerification{}, f.verifyErr
	}
	fc, ok := c.(*vaultFakeConn)
	if !ok {
		return vaultServiceVerification{}, errors.New("foreign")
	}
	p := vaultServiceVerification{fc.issuer, c, fc.peer, fc.policy}
	switch f.proofMode {
	case "zero":
		p = vaultServiceVerification{}
	case "foreign":
		p.conn = &vaultFakeConn{}
	case "unissued":
		p.issuer = nil
	case "peer_missing":
		p.peer = nil
	case "policy_missing":
		p.policy = nil
	}
	if f.verifyHook != nil {
		f.verifyHook(point, f.verifyCount, fc, &p)
	}
	return p, nil
}
func (c *vaultFakeConn) Prepare(_ context.Context, r vaultRequest, p vaultServiceVerification) (vaultPrepared, *vaultFailure) {
	c.v.events = append(c.v.events, "prepare:"+string(r.op))
	c.v.preparations++
	if c.v.panicAt == "prepare" {
		panic("injected-private")
	}
	if !p.validFor(c) {
		return nil, vaultLocalFailure(vaultEServerUntrusted)
	}
	prep := &vaultFakePrepared{c: c, req: r}
	if c.v.prepareFailure != nil && (c.v.failureOp == "" || c.v.failureOp == r.op) {
		return prep, c.v.prepareFailure
	}
	return prep, nil
}
func (p *vaultFakePrepared) Invoke(_ context.Context, proof vaultServiceVerification) (vaultExchange, error) {
	f := p.c.v
	f.invocations++
	f.events = append(f.events, "invoke:"+string(p.req.op))
	if p.used {
		return vaultExchange{}, errors.New("used")
	}
	p.used = true
	if f.beforeInvoke != nil {
		f.beforeInvoke(p.req)
	}
	receipt := vaultSubmissionReceipt{p.c.receiptIssuer, p.c, p.req.id, p.req.op, vaultInvoked}
	if !proof.validFor(p.c) || proof.peer != p.c.peer || proof.policy != p.c.policy {
		receipt.phase = vaultNoInvocation
		return vaultExchange{receipt: receipt}, vaultLocalFailure(vaultEServerUntrusted)
	}
	affected := f.failureOp == "" || f.failureOp == p.req.op
	if affected && f.receiptMode == "unsent_zero" {
		return vaultExchange{}, errors.New("unproven-private")
	}
	if affected && f.receiptMode == "before" {
		receipt.phase = vaultNoInvocation
		return vaultExchange{receipt: receipt}, errors.New("unavailable-private")
	}
	f.effects++
	f.requests = append(f.requests, p.req.clone())
	if f.panicAt == "invoke" {
		panic("injected-private")
	}
	var value vaultValue
	var e error
	if f.reply != nil {
		value, e = f.reply(p.req, len(f.requests))
	} else if p.req.op == vaultOpRegister {
		value = vaultTestSuccess(p.req, vaultTestRegisterResult(p.req))
	} else if f.release != nil {
		value, e = f.release(p.req)
	} else {
		value = vaultTestSuccess(p.req, f.releaseResult(p.req))
	}
	exchange := vaultExchange{receipt: receipt, reply: value, received: e == nil}
	if affected {
		switch f.receiptMode {
		case "zero":
			exchange.receipt = vaultSubmissionReceipt{}
		case "wrong_id":
			exchange.receipt.requestID = strings.Repeat("0", 32)
		case "wrong_op":
			exchange.receipt.op = vaultOpCloseSession
		case "wrong_conn":
			exchange.receipt.conn = &vaultFakeConn{}
		case "invalid":
			exchange.receipt.phase = "invalid"
		case "contradictory":
			exchange.receipt.phase = vaultNoInvocation
		case "lost":
			exchange.received = false
			e = errors.New("lost-private")
		}
	}
	f.track(exchange.reply)
	if f.afterReply != nil {
		f.afterReply(p.req)
	}
	return exchange, e
}
func (p *vaultFakePrepared) Discard() error {
	f := p.c.v
	f.discards++
	f.events = append(f.events, "discard:"+string(p.req.op))
	if f.panicAt == "discard" {
		panic("injected-private")
	}
	return f.discardErr
}
func (c *vaultFakeConn) Close() error {
	c.v.closes++
	c.v.events = append(c.v.events, "close")
	if c.v.panicAt == "close" {
		panic("injected-private")
	}
	return c.v.closeErr
}
func (f *vaultFake) track(v vaultValue) {
	if v.kind == vaultKindBytes {
		f.buffers = append(f.buffers, v.bytes)
	}
	for _, it := range v.items {
		f.track(it)
	}
	for _, field := range v.fields {
		f.track(field.vaultValue)
	}
}
func (f *vaultFake) releaseResult(r vaultRequest) vaultValue {
	return vaultDict(vaultF("identity", vaultTestGet(r.body, "identity")), vaultF("consumer_binding", vaultTestGet(r.body, "expected_binding")), vaultF("record_revision", vaultUint(1)), vaultF("secret", vaultBytes(f.token)))
}
func vaultTestSuccess(r vaultRequest, result vaultValue) vaultValue {
	return vaultDict(vaultF("v", vaultUint(2)), vaultF("request_id", vaultString(r.id)), vaultF("op", vaultString(string(r.op))), vaultF("ok", vaultBool(true)), vaultF("result", result))
}
func vaultTestRefusal(r vaultRequest, code string) vaultValue {
	return vaultDict(vaultF("v", vaultUint(2)), vaultF("request_id", vaultString(r.id)), vaultF("op", vaultString(string(r.op))), vaultF("ok", vaultBool(false)), vaultF("error", vaultDict(vaultF("code", vaultString(code)))))
}
func vaultTestRegisterResult(r vaultRequest) vaultValue {
	return vaultDict(vaultF("identity", vaultTestGet(r.body, "identity")), vaultF("session", vaultDict(vaultF("epoch", vaultString(strings.Repeat("e", 32))), vaultF("session_id", vaultString(strings.Repeat("5", 32))), vaultF("generation", vaultUint(1)))), vaultF("lifetime_ms", vaultUint(900000)))
}
func vaultTestGet(v vaultValue, k string) vaultValue {
	for _, f := range v.fields {
		if f.Key == k {
			return f.vaultValue
		}
	}
	return vaultValue{}
}
func vaultTestWith(v vaultValue, k string, n vaultValue) vaultValue {
	o := v.clone()
	for i := range o.fields {
		if o.fields[i].Key == k {
			o.fields[i].vaultValue = n.clone()
		}
	}
	return o
}
func vaultTestPlus(v vaultValue, k string, n vaultValue) vaultValue {
	o := v.clone()
	o.fields = append(o.fields, vaultF(k, n.clone()))
	return o
}
func vaultTestWithout(v vaultValue, k string) vaultValue {
	o := vaultValue{kind: v.kind}
	for _, f := range v.fields {
		if f.Key != k {
			o.fields = append(o.fields, vaultField{Key: f.Key, vaultValue: f.vaultValue.clone()})
		}
	}
	return o
}
func vaultTestRun(t *testing.T, f *vaultFake, mode string, consume func([]byte) error) vaultAttemptReport {
	t.Helper()
	c, r := vaultNewClient(vaultFixtureAdmitted(t, vaultFixtureObserved(t, mode)), f.dep())
	if r != nil {
		t.Fatal(r)
	}
	return c.Release(context.Background(), vaultFixtureGuard(), consume)
}
