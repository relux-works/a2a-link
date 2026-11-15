package cli

import (
	"bytes"
	"context"
	"errors"
	"github.com/relux-works/a2a-swarm/internal/config"
	"strings"
	"testing"
)

// Claim: direct and registered logical successes use exact operation/session
// bodies, fresh IDs, all verification boundaries, one handoff and owned cleanup.
// This tests the real client with logical external dependencies, not native trust.
func TestReleaseCallOrderPositive(t *testing.T) {
	for _, mode := range []string{vaultSessionDirect, vaultSessionRegistered} {
		t.Run(mode, func(t *testing.T) {
			f := vaultNewFake(t)
			calls := 0
			var borrowed []byte
			r := vaultTestRun(t, f, mode, func(b []byte) error {
				calls++
				borrowed = b
				if !bytes.Equal(b, f.token) {
					t.Fatal("wrong selected bytes")
				}
				return nil
			})
			want := 1
			if mode == vaultSessionRegistered {
				want = 2
			}
			if !r.acquisitionOK() || r.Revision != 1 || calls != 1 || f.effects != want || f.preparations != want || f.invocations != want || f.verifyCount != want*3 || f.closes != 1 || f.discards != want {
				t.Fatalf("flow/counters: %+v events=%v", r, f.events)
			}
			for _, b := range append(f.buffers, borrowed) {
				if bytes.Count(b, []byte{0}) != len(b) {
					t.Fatal("owned bytes not cleared")
				}
			}
			seen := map[string]bool{}
			for _, req := range f.requests {
				if !vaultHex32RE.MatchString(req.id) || seen[req.id] {
					t.Fatal("request ID not fresh Hex32")
				}
				seen[req.id] = true
			}
			body := f.requests[len(f.requests)-1].body
			s := vaultTestGet(body, "session")
			if mode == vaultSessionDirect && s.kind != vaultKindNull {
				t.Fatal("direct session not null")
			}
			if mode == vaultSessionRegistered && vaultTestGet(s, "session_id").s != strings.Repeat("5", 32) {
				t.Fatal("registration session not carried")
			}
		})
	}
}

// Claim: missing/typed-nil dependencies and zero authority cannot use the driver;
// nil consumer or guard is rejected without an operation.
func TestReleaseMissingDependency(t *testing.T) {
	f := vaultNewFake(t)
	s := vaultFixtureAdmitted(t, vaultFixtureObserved(t, vaultSessionDirect))
	var typedNil *vaultFake
	for _, tc := range []struct {
		dep  *vaultDependency
		code vaultCode
	}{{nil, vaultEUnavailable}, {&vaultDependency{Verifier: f}, vaultEUnavailable}, {&vaultDependency{Driver: typedNil, Verifier: f}, vaultEUnavailable}, {&vaultDependency{Driver: f}, vaultEServerUntrusted}, {&vaultDependency{Driver: f, Verifier: typedNil}, vaultEServerUntrusted}} {
		_, r := vaultNewClient(s, tc.dep)
		if r == nil || r.Outcome != vaultNotSubmitted || r.Code != tc.code {
			t.Fatal("missing dependency gate")
		}
	}
	if _, r := vaultNewClient(vaultCredentialSelection{}, f.dep()); r == nil || r.Code != vaultEContext {
		t.Fatal("zero authority admitted")
	}
	c, _ := vaultNewClient(s, f.dep())
	r := c.Release(context.Background(), vaultFixtureGuard(), nil)
	if r.Failure == nil || r.Failure.Code != vaultEBackendConfig {
		t.Fatal("nil consumer admitted")
	}
	r = c.Release(context.Background(), nil, func([]byte) error { return nil })
	if r.Failure == nil || r.Failure.Code != vaultEBackendConfig || len(f.events) != 0 {
		t.Fatal("nil guard admitted or dependency touched")
	}
}

// Claim: missing, unissued, foreign, zero or rejected service attestations yield
// no preparation/invocation/consumer bytes; an unmodified neighbor succeeds.
// Regression: driver-side proof rejection must not mask a missing client gate.
func TestReleaseVerificationIsMandatory(t *testing.T) {
	for _, mode := range []string{"zero", "unissued", "foreign", "peer_missing", "policy_missing", "error", "panic"} {
		t.Run(mode, func(t *testing.T) {
			f := vaultNewFake(t)
			f.proofMode = mode
			if mode == "error" {
				f.verifyErr = errors.New(string(f.token))
			}
			if mode == "panic" {
				f.panicAt = "verify"
			}
			called := false
			r := vaultTestRun(t, f, vaultSessionRegistered, func([]byte) error { called = true; return nil })
			want := vaultEServerUntrusted
			if mode == "panic" {
				want = vaultEInternal
			}
			if r.Failure == nil || r.Failure.Outcome != vaultNotSubmitted || r.Failure.Code != want || called || f.preparations != 0 || f.invocations != 0 || f.effects != 0 || f.closes != 1 {
				t.Fatalf("mandatory verifier before prepare: report=%+v preparations=%d invocations=%d effects=%d", r, f.preparations, f.invocations, f.effects)
			}
			if bytes.Contains([]byte(r.diagnostic().Error()), f.token) {
				t.Fatal("raw error leaked")
			}
		})
	}
	f := vaultNewFake(t)
	if r := vaultTestRun(t, f, vaultSessionRegistered, func([]byte) error { return nil }); !r.acquisitionOK() {
		t.Fatal("positive verification neighbor")
	}
}

// Claim: every one of the frozen 26 codes is accepted only on a complete
// matching authenticated refusal, independently for register and release.
func TestReleaseAuthenticatedRefusals(t *testing.T) {
	if len(vaultAllCodes) != 26 {
		t.Fatal("wrong code set")
	}
	for _, op := range []vaultOp{vaultOpRegister, vaultOpRelease} {
		for _, code := range vaultAllCodes {
			f := vaultNewFake(t)
			f.reply = func(req vaultRequest, _ int) (vaultValue, error) {
				if req.op == op {
					return vaultTestRefusal(req, string(code)), nil
				}
				return vaultTestSuccess(req, vaultTestRegisterResult(req)), nil
			}
			r := vaultTestRun(t, f, vaultSessionRegistered, func([]byte) error { t.Fatal("consumer on refusal"); return nil })
			if r.Failure == nil || r.Failure.Outcome != vaultRefused || r.Failure.Code != code || r.Failure.Op != op || r.Handoff != vaultHandoffNotEntered {
				t.Fatalf("%s %s: %+v", op, code, r)
			}
			if op == vaultOpRegister && r.Release != nil {
				t.Fatal("release attempted after register refusal")
			}
		}
	}
	f := vaultNewFake(t)
	f.release = func(r vaultRequest) (vaultValue, error) { return vaultTestRefusal(r, "E_NOT_A_CODE"), nil }
	r := vaultTestRun(t, f, vaultSessionDirect, func([]byte) error { return nil })
	if r.Failure == nil || r.Failure.Outcome != vaultUnknown {
		t.Fatal("unknown code admitted")
	}
}
func vaultNest(depth int) vaultValue {
	v := vaultNull()
	for i := 0; i < depth; i++ {
		v = vaultDict(vaultF("x", v))
	}
	return v
}

// Claim: malformed, mismatched and over-limit invoked replies are UNKNOWN with
// zero consumer bytes; owned response buffers are wiped and diagnostics fixed.
func TestReleaseSubmittedRepliesAreUnknown(t *testing.T) {
	type mutate func(f *vaultFake, req vaultRequest) (vaultValue, error)
	rel := func(m func(f *vaultFake, req vaultRequest, ok vaultValue) vaultValue) mutate {
		return func(f *vaultFake, req vaultRequest) (vaultValue, error) {
			return m(f, req, vaultTestSuccess(req, f.releaseResult(req))), nil
		}
	}
	res := func(m func(r vaultValue) vaultValue) mutate {
		return rel(func(_ *vaultFake, _ vaultRequest, ok vaultValue) vaultValue {
			return vaultTestWith(ok, "result", m(vaultTestGet(ok, "result")))
		})
	}
	bind := func(key string, nv vaultValue) mutate {
		return res(func(r vaultValue) vaultValue {
			return vaultTestWith(r, "consumer_binding", vaultTestWith(vaultTestGet(r, "consumer_binding"), key, nv))
		})
	}
	ident := func(key string, nv vaultValue) mutate {
		return res(func(r vaultValue) vaultValue {
			return vaultTestWith(r, "identity", vaultTestWith(vaultTestGet(r, "identity"), key, nv))
		})
	}
	for _, tc := range []struct {
		label string
		m     mutate
		diag  vaultDiagnosis
	}{
		{"transport error", func(*vaultFake, vaultRequest) (vaultValue, error) { return vaultValue{}, errors.New("disconnect") }, vaultDiagTransport},
		{"v 1", rel(func(_ *vaultFake, _ vaultRequest, ok vaultValue) vaultValue {
			return vaultTestWith(ok, "v", vaultUint(1))
		}), vaultDiagMismatch},
		{"v 3", rel(func(_ *vaultFake, _ vaultRequest, ok vaultValue) vaultValue {
			return vaultTestWith(ok, "v", vaultUint(3))
		}), vaultDiagMismatch},
		{"v string", rel(func(_ *vaultFake, _ vaultRequest, ok vaultValue) vaultValue {
			return vaultTestWith(ok, "v", vaultString("2"))
		}), vaultDiagMalformed},
		{"missing v", rel(func(_ *vaultFake, _ vaultRequest, ok vaultValue) vaultValue { return vaultTestWithout(ok, "v") }), vaultDiagMalformed},
		{"other request_id", rel(func(_ *vaultFake, _ vaultRequest, ok vaultValue) vaultValue {
			return vaultTestWith(ok, "request_id", vaultString(strings.Repeat("0", 32)))
		}), vaultDiagMismatch},
		{"register op", rel(func(_ *vaultFake, _ vaultRequest, ok vaultValue) vaultValue {
			return vaultTestWith(ok, "op", vaultString("register"))
		}), vaultDiagMismatch},
		{"ok string", rel(func(_ *vaultFake, _ vaultRequest, ok vaultValue) vaultValue {
			return vaultTestWith(ok, "ok", vaultString("true"))
		}), vaultDiagMalformed},
		{"ok false with result", rel(func(_ *vaultFake, _ vaultRequest, ok vaultValue) vaultValue {
			return vaultTestWith(ok, "ok", vaultBool(false))
		}), vaultDiagMalformed},
		{"vaultUnknown top-level field", rel(func(_ *vaultFake, _ vaultRequest, ok vaultValue) vaultValue {
			return vaultTestPlus(ok, "detail", vaultString("x"))
		}), vaultDiagMalformed},
		{"duplicate key", rel(func(_ *vaultFake, _ vaultRequest, ok vaultValue) vaultValue {
			return vaultTestPlus(vaultTestWithout(ok, "v"), "op", vaultString("release"))
		}), vaultDiagMalformed},
		{"vaultUnknown result field", res(func(r vaultValue) vaultValue { return vaultTestPlus(r, "note", vaultString("x")) }), vaultDiagMalformed},
		{"extra session data on release", res(func(r vaultValue) vaultValue { return vaultTestPlus(r, "session", vaultNull()) }), vaultDiagMalformed},
		{"register-shaped result", func(_ *vaultFake, req vaultRequest) (vaultValue, error) {
			return vaultTestSuccess(req, vaultTestRegisterResult(req)), nil
		}, vaultDiagMalformed},
		{"close-shaped result", func(_ *vaultFake, req vaultRequest) (vaultValue, error) {
			return vaultTestSuccess(req, vaultDict(vaultF("state", vaultString("closed")))), nil
		}, vaultDiagMalformed},
		{"identity name changed", ident("name", vaultString("fixture-b")), vaultDiagMismatch},
		{"identity domain changed", ident("domain", vaultString("other-domain")), vaultDiagMismatch},
		{"identity kind changed", ident("kind", vaultString("synthetic")), vaultDiagMismatch},
		{"identity origin added", ident("origin", vaultDict(vaultF("host_id", vaultString("h")), vaultF("project_id", vaultString("p")), vaultF("profile_id", vaultString("r")))), vaultDiagMismatch},
		{"identity origin wrong type", ident("origin", vaultString("null")), vaultDiagMalformed},
		{"binding user changed", bind("user_id", vaultString("@fixture:b.example.invalid")), vaultDiagMismatch},
		{"binding server changed", bind("server_name", vaultString("b.example.invalid")), vaultDiagMismatch},
		{"binding URL trailing slash", bind("homeserver_url", vaultString("https://matrix-a.example.invalid/")), vaultDiagMismatch},
		{"binding selector changed", bind("a2a_selector", vaultString("fixture-b")), vaultDiagMismatch},
		{"binding_v 2", bind("binding_v", vaultUint(2)), vaultDiagMismatch},
		{"binding_v string", bind("binding_v", vaultString("1")), vaultDiagMalformed},
		{"revision 0", res(func(r vaultValue) vaultValue { return vaultTestWith(r, "record_revision", vaultUint(0)) }), vaultDiagMalformed},
		{"revision 2^63", res(func(r vaultValue) vaultValue { return vaultTestWith(r, "record_revision", vaultUint(1<<63)) }), vaultDiagMalformed},
		{"secret as string", res(func(r vaultValue) vaultValue { return vaultTestWith(r, "secret", vaultString("x")) }), vaultDiagMalformed},
		{"empty secret", res(func(r vaultValue) vaultValue { return vaultTestWith(r, "secret", vaultBytes([]byte{})) }), vaultDiagMalformed},
		{"secret 16385 bytes", func(f *vaultFake, req vaultRequest) (vaultValue, error) {
			ok := vaultTestSuccess(req, f.releaseResult(req))
			big := bytes.Repeat(f.token[:1], vaultMaxSecret+1)
			return vaultTestWith(ok, "result", vaultTestWith(vaultTestGet(ok, "result"), "secret", vaultBytes(big))), nil
		}, vaultDiagLimit},
		{"nesting depth 9", rel(func(_ *vaultFake, _ vaultRequest, ok vaultValue) vaultValue {
			return vaultTestPlus(vaultTestWithout(ok, "result"), "result", vaultNest(8))
		}), vaultDiagLimit},
		{"33 fields", rel(func(_ *vaultFake, _ vaultRequest, ok vaultValue) vaultValue {
			r := vaultTestGet(ok, "result")
			for i := 0; len(r.fields) < 33; i++ {
				r = vaultTestPlus(r, "pad"+string(rune('a'+i)), vaultNull())
			}
			return vaultTestWith(ok, "result", r)
		}), vaultDiagLimit},
		{"invalid UTF-8 string", ident("name", vaultString("fixture-\xff")), vaultDiagMalformed},
		{"NUL string", ident("name", vaultString("fixture-a\x00")), vaultDiagMalformed},
		{"vaultFailure with extra field", func(_ *vaultFake, req vaultRequest) (vaultValue, error) {
			return vaultTestPlus(vaultTestRefusal(req, "E_REVOKED"), "secret", vaultBytes([]byte("x"))), nil
		}, vaultDiagMalformed},
		{"vaultFailure vaultCode wrong type", func(_ *vaultFake, req vaultRequest) (vaultValue, error) {
			return vaultTestWith(vaultTestRefusal(req, "E_REVOKED"), "error", vaultDict(vaultF("code", vaultUint(1)))), nil
		}, vaultDiagMalformed},
		{"vaultFailure with detail", func(_ *vaultFake, req vaultRequest) (vaultValue, error) {
			return vaultTestWith(vaultTestRefusal(req, "E_REVOKED"), "error", vaultDict(vaultF("code", vaultString("E_REVOKED")), vaultF("detail", vaultString("x")))), nil
		}, vaultDiagMalformed},
		{"vaultFailure for other request", func(_ *vaultFake, req vaultRequest) (vaultValue, error) {
			return vaultTestWith(vaultTestRefusal(req, "E_REVOKED"), "request_id", vaultString(strings.Repeat("1", 32))), nil
		}, vaultDiagMismatch},
		{"submit panic", func(*vaultFake, vaultRequest) (vaultValue, error) { panic("injected") }, vaultDiagSubmission},
	} {
		f := vaultNewFake(t)
		tc := tc
		f.reply = func(req vaultRequest, n int) (vaultValue, error) {
			if req.op == vaultOpRelease {
				return tc.m(f, req)
			}
			return vaultTestSuccess(req, vaultTestRegisterResult(req)), nil
		}
		called := false
		report := vaultTestRun(t, f, vaultSessionRegistered, func([]byte) error { called = true; return nil })
		r := report.Failure
		if r == nil || r.Outcome != vaultUnknown || r.Diagnosis != tc.diag || r.Code != "" || called || report.Register.Outcome != vaultSucceeded || report.Release.Op != vaultOpRelease {
			t.Fatalf("%s: incorrect reply admission/report: %+v", tc.label, report)
		}
		err := report.diagnostic()

		for _, b := range f.buffers {
			if bytes.Count(b, []byte{0}) != len(b) {
				t.Fatalf("%s: reply secret buffer not cleared", tc.label)
			}
		}
		if bytes.Contains([]byte(err.Error()), f.token) {
			t.Fatalf("%s: secret in error", tc.label)
		}
		if f.effects != 2 || f.closes != 1 {
			t.Fatalf("%s: effects=%d closes=%d", tc.label, f.effects, f.closes)
		}
	}
}

// Claim: malformed register results stop before release; neighboring valid
// registration/release succeeds in TestReleaseCallOrderPositive.
func TestRegisterRepliesAreClosed(t *testing.T) {
	for _, mutate := range []func(vaultValue) vaultValue{
		func(v vaultValue) vaultValue { return vaultTestPlus(v, "secret", vaultBytes([]byte{1})) },
		func(v vaultValue) vaultValue { return vaultTestWith(v, "lifetime_ms", vaultUint(900001)) },
		func(v vaultValue) vaultValue {
			return vaultTestWith(v, "session", vaultTestWith(vaultTestGet(v, "session"), "generation", vaultUint(0)))
		},
		func(v vaultValue) vaultValue {
			return vaultTestWith(v, "session", vaultTestWith(vaultTestGet(v, "session"), "session_id", vaultString(strings.Repeat("A", 32))))
		},
		func(v vaultValue) vaultValue {
			return vaultTestWith(v, "identity", vaultTestWith(vaultTestGet(v, "identity"), "name", vaultString("other")))
		},
	} {
		f := vaultNewFake(t)
		f.reply = func(req vaultRequest, _ int) (vaultValue, error) {
			return vaultTestSuccess(req, mutate(vaultTestRegisterResult(req))), nil
		}
		r := vaultTestRun(t, f, vaultSessionRegistered, func([]byte) error { t.Fatal("consumer"); return nil })
		if r.Failure == nil || r.Register.Outcome != vaultUnknown || r.Release != nil || f.effects != 1 {
			t.Fatal("register reply not closed")
		}
	}
}

// Claim: UNKNOWN has no automatic retry; an explicitly invoked later attempt
// gets a fresh Conn, registration and IDs and may succeed under r4.
func TestNewAttemptAfterUnknown(t *testing.T) {
	f := vaultNewFake(t)
	f.receiptMode = "lost"
	f.failureOp = vaultOpRelease
	c, _ := vaultNewClient(vaultFixtureAdmitted(t, vaultFixtureObserved(t, vaultSessionRegistered)), f.dep())
	r := c.Release(context.Background(), vaultFixtureGuard(), func([]byte) error { return nil })
	if r.Release.Outcome != vaultUnknown || f.effects != 2 || len(f.conns) != 1 {
		t.Fatal("unknown/retry boundary")
	}
	f.receiptMode = ""
	r = c.Release(context.Background(), vaultFixtureGuard(), func([]byte) error { return nil })
	if !r.acquisitionOK() || len(f.conns) != 2 || f.effects != 4 {
		t.Fatal("new attempt failed")
	}
	ids := map[string]bool{}
	for _, r := range f.requests {
		if ids[r.id] {
			t.Fatal("ID reused")
		}
		ids[r.id] = true
	}
}

// Claim: exact per-op receipts distinguish no invocation, lost/invalid receipt,
// and register success followed by local release cancellation/preparation failure.
func TestVaultOperationPhase(t *testing.T) {
	for _, mode := range []string{"before", "lost", "zero", "wrong_id", "wrong_op", "wrong_conn", "invalid", "contradictory", "unsent_zero", ""} {
		t.Run(mode, func(t *testing.T) {
			f := vaultNewFake(t)
			f.receiptMode = mode
			f.failureOp = vaultOpRelease
			r := vaultTestRun(t, f, vaultSessionRegistered, func([]byte) error { return nil })
			if r.Register == nil || r.Register.Outcome != vaultSucceeded || r.Release == nil || r.Release.Op != vaultOpRelease || (mode != "" && r.Release.Stage != vaultStageInvoke) {
				t.Fatal("operation identity conflated")
			}
			switch mode {
			case "":
				if !r.acquisitionOK() {
					t.Fatal("phase positive")
				}
			case "before":
				if r.Release.Outcome != vaultNotSubmitted || r.Release.Invocation != vaultNoInvocation || r.Release.Code != vaultEUnavailable || f.effects != 1 {
					t.Fatalf("before invocation: %+v", r)
				}
			default:
				if r.Release.Outcome != vaultUnknown || r.Release.Code != "" || r.Handoff != vaultHandoffNotEntered || (mode != "unsent_zero" && f.effects != 2) || (mode == "unsent_zero" && f.effects != 1) {
					t.Fatalf("uncertain invocation: %+v", r)
				}
			}
		})
	}
	for _, reason := range []string{"cancel", "prepare", "rng"} {
		t.Run(reason, func(t *testing.T) {
			f := vaultNewFake(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c, _ := vaultNewClient(vaultFixtureAdmitted(t, vaultFixtureObserved(t, vaultSessionRegistered)), f.dep())
			f.afterReply = func(r vaultRequest) {
				if r.op == vaultOpRegister {
					switch reason {
					case "cancel":
						cancel()
					case "prepare":
						f.failureOp = vaultOpRelease
						f.prepareFailure = vaultLocalFailure(vaultELimit)
					case "rng":
						c.rand = strings.NewReader("")
					}
				}
			}
			r := c.Release(ctx, vaultFixtureGuard(), func([]byte) error { t.Fatal("handoff after local failure"); return nil })
			want := vaultEUnavailable
			if reason == "prepare" {
				want = vaultELimit
			}
			if reason == "rng" {
				want = vaultEInternal
			}
			if r.Register.Outcome != vaultSucceeded || r.Release.Outcome != vaultNotSubmitted || r.Release.Code != want || r.Release.Invocation != vaultNoInvocation || r.Release.Stage != vaultStagePrepare || f.effects != 1 || f.closes != 1 {
				t.Fatalf("independent release state: %+v", r)
			}
		})
	}
	// Cancellation before register must not invoke either operation.
	f := vaultNewFake(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c, _ := vaultNewClient(vaultFixtureAdmitted(t, vaultFixtureObserved(t, vaultSessionRegistered)), f.dep())
	r := c.Release(ctx, vaultFixtureGuard(), func([]byte) error { return nil })
	if r.Failure == nil || r.Failure.Code != vaultEUnavailable || len(f.events) != 0 {
		t.Fatal("early cancellation")
	}
}

// Claim: after entry, callback error/panic preserves known native success,
// revision and nonzero entry evidence; owned buffers are cleared on both exits.
func TestVaultHandoffBoundary(t *testing.T) {
	for _, mode := range []string{"return", "error", "panic"} {
		f := vaultNewFake(t)
		entered := 0
		var borrow []byte
		r := vaultTestRun(t, f, vaultSessionDirect, func(b []byte) error {
			entered++
			borrow = b
			switch mode {
			case "error":
				return errors.New(string(f.token))
			case "panic":
				panic(string(f.token))
			}
			return nil
		})
		want := vaultHandoffReturned
		if mode == "error" {
			want = vaultHandoffFailed
		}
		if mode == "panic" {
			want = vaultHandoffPanicked
		}
		if r.Release.Outcome != vaultSucceeded || r.Release.Invocation != vaultInvoked || r.Revision != 1 || r.Failure != nil || r.Handoff != want || entered != 1 || f.effects != 1 || f.closes != 1 {
			t.Fatalf("handoff reclassified: %+v", r)
		}
		if bytes.Count(borrow, []byte{0}) != len(borrow) {
			t.Fatal("borrow not wiped")
		}
		if e := r.diagnostic(); e != nil && bytes.Contains([]byte(e.Error()), f.token) {
			t.Fatal("callback payload leaked")
		}
	}
	// Cancellation after a validated reply must preserve native success but
	// suppress the consumer, rather than make a fabricated UNKNOWN/refusal.
	f := vaultNewFake(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.afterReply = func(vaultRequest) { cancel() }
	c, _ := vaultNewClient(vaultFixtureAdmitted(t, vaultFixtureObserved(t, vaultSessionDirect)), f.dep())
	r := c.Release(ctx, vaultFixtureGuard(), func([]byte) error { t.Fatal("cancelled handoff"); return nil })
	if r.Release.Outcome != vaultSucceeded || r.Handoff != vaultHandoffNotEntered || r.DeliveryDiagnosis != vaultDeliveryCancelled {
		t.Fatal("late cancellation reclassified")
	}
}

// Claim: cleanup error/panic is separate from known success; each owned
// connection is closed once and no implicit retry or effect rollback occurs.
func TestVaultCleanupOutcomes(t *testing.T) {
	for _, mode := range []string{"close_error", "discard_error", "close", "discard", ""} {
		f := vaultNewFake(t)
		switch mode {
		case "close_error":
			f.closeErr = errors.New("private")
		case "discard_error":
			f.discardErr = errors.New("private")
		default:
			f.panicAt = mode
		}
		r := vaultTestRun(t, f, vaultSessionDirect, func([]byte) error { return nil })
		want := vaultCleanupFailed
		if mode == "" {
			want = vaultCleanupClosed
		}
		if r.Release.Outcome != vaultSucceeded || r.Handoff != vaultHandoffReturned || r.Cleanup != want || f.closes != 1 || f.effects != 1 {
			t.Fatalf("cleanup outcome: %+v", r)
		}
	}
}

// Claim: proofs from a replaced peer or stale policy fail before invocation;
// changed post-reply evidence is UNKNOWN with zero handoff, not REFUSED.
func TestVaultPeerRechecks(t *testing.T) {
	for _, when := range []string{"before_peer", "before_policy", "after_peer", "after_policy", ""} {
		f := vaultNewFake(t)
		f.verifyHook = func(point vaultVerificationPoint, n int, c *vaultFakeConn, p *vaultServiceVerification) {
			if strings.HasPrefix(when, "before") && n == 2 {
				if strings.HasSuffix(when, "peer") {
					p.peer = &vaultPeerWitness{2}
				} else {
					p.policy = &vaultPolicyWitness{2}
				}
			}
			if strings.HasPrefix(when, "after") && point == vaultAfterReply {
				if strings.HasSuffix(when, "peer") {
					p.peer = &vaultPeerWitness{2}
				} else {
					p.policy = &vaultPolicyWitness{2}
				}
			}
		}
		entered := 0
		r := vaultTestRun(t, f, vaultSessionDirect, func([]byte) error { entered++; return nil })
		if when == "" {
			if !r.acquisitionOK() {
				t.Fatal("peer positive")
			}
			continue
		}
		if entered != 0 {
			t.Fatal("unverified handoff")
		}
		if strings.HasPrefix(when, "before") {
			if r.Release.Outcome != vaultNotSubmitted || r.Release.Code != vaultEServerUntrusted || r.Release.Stage != vaultStageVerification || f.effects != 0 {
				t.Fatal("pre-invoke peer phase")
			}
		} else if r.Release.Outcome != vaultUnknown || r.Release.Diagnosis != vaultDiagPeer || r.Release.Stage != vaultStageReply || f.effects != 1 {
			t.Fatal("post-reply peer phase")
		}
	}
}

// Claim: all nested public/value views are detached from retained request data.
func TestVaultSelectionOwnership(t *testing.T) {
	c := config.Connection{ID: "fixture-a", URL: "https://matrix-a.example.invalid", ServerName: "a.example.invalid", Store: config.CredentialStore{Backend: config.BackendVaultV1}}
	local, _ := c.Binding("fixture", false)
	origin := &config.VaultOrigin{HostID: "h", ProjectID: "p", ProfileID: "r"}
	name, _ := vaultSyntheticName(vaultSyntheticContext{HostID: "h", ProjectID: "p", ProfileID: "r"})
	input := config.VaultSelection{Identity: config.VaultIdentity{Domain: "fixture-domain", Kind: vaultKindSynthetic, Name: name, Origin: origin}, SessionMode: vaultSessionDirect}
	o, e := vaultObserve(input, "fixture", local)
	if e != nil {
		t.Fatal(e)
	}
	s := vaultFixtureAdmitted(t, o)
	origin.HostID = "changed"
	view := s.Public()
	view.identity.Origin.ProjectID = "changed"
	if s.Public().identity.Origin.HostID != "h" || s.Public().identity.Origin.ProjectID != "p" {
		t.Fatal("selection alias retarget")
	}
	f := vaultNewFake(t)
	client, r := vaultNewClient(s, f.dep())
	if r != nil {
		t.Fatal(r)
	}
	result := client.Release(context.Background(), vaultFixtureGuard(), func([]byte) error { return nil })
	if !result.acquisitionOK() {
		t.Fatal("immutable request positive")
	}
	id, ok := vaultParseIdentity(vaultTestGet(f.requests[0].body, "identity"))
	if !ok || id.Origin.HostID != "h" || id.Origin.ProjectID != "p" {
		t.Fatal("input/public mutation retargeted actual request")
	}
	b := []byte{1, 2}
	v := vaultDict(vaultF("nested", vaultArray(vaultBytes(b))))
	b[0] = 9
	fields := v.Fields()
	fields[0].vaultValue.items[0].bytes[0] = 8
	items := vaultTestGet(v, "nested").Items()
	items[0].bytes[0] = 7
	if vaultTestGet(v, "nested").items[0].bytes[0] != 1 {
		t.Fatal("nested view alias")
	}
}
func vaultLongURLBinding(t *testing.T) config.ConnectionBinding {
	t.Helper()
	host := strings.Repeat(strings.Repeat("h", 62)+".", 129) + strings.Repeat("z", 8193-len("https://")-129*63)
	c := config.Connection{ID: "fixture-a", URL: "https://" + host, ServerName: "a.example.invalid", Store: config.CredentialStore{Backend: config.BackendVaultV1}}
	if len(c.URL) != 8193 {
		t.Fatalf("fixture length %d", len(c.URL))
	}
	b, err := c.Binding("fixture", false)
	if err != nil {
		t.Fatalf("8193-byte URL is not source-valid: %v", err)
	}
	return b
}

// Claim: vaultObserve accepts an explicit or synthetic selection on a vault-v1
// agents binding and refuses a legacy backend, the humans class, an unknown
// or empty session mode and an invalid identity, with no default mode.
func TestLatchSelection(t *testing.T) {
	c := config.Connection{ID: "fixture-a", URL: "https://matrix-a.example.invalid", ServerName: "a.example.invalid", Store: config.CredentialStore{Backend: config.BackendVaultV1}}
	b, _ := c.Binding("fixture", false)
	v := vaultSyntheticVectors[0]
	good := config.VaultSelection{Identity: config.VaultIdentity{Domain: "example", Kind: vaultKindSynthetic, Name: v.name, Origin: &config.VaultOrigin{HostID: v.host, ProjectID: v.project, ProfileID: v.profile}}, SessionMode: vaultSessionRegistered}
	sel, err := vaultObserve(good, "fixture", b)
	if err != nil || !sel.Latched() || sel.SessionMode() != vaultSessionRegistered || sel.Binding().UserID != "@fixture:a.example.invalid" || sel.Identity().Name != v.name {
		t.Fatalf("valid synthetic selection: %v", err)
	}
	again, _ := vaultObserve(good, "fixture", b)
	if !sel.Equal(again) {
		t.Fatal("identical latch differs")
	}
	other := good
	other.SessionMode = vaultSessionDirect
	if o, _ := vaultObserve(other, "fixture", b); sel.Equal(o) {
		t.Fatal("changed session mode compares equal")
	}
	file := c
	file.Store.Backend = "file"
	fb, _ := file.Binding("fixture", false)
	hb, _ := c.Binding("fixture", true)
	for _, tc := range []struct {
		label string
		s     config.VaultSelection
		b     config.ConnectionBinding
		want  vaultCode
	}{
		{"legacy backend", good, fb, vaultEBackendConfig},
		{"humans class", good, hb, vaultEBackendConfig},
		{"empty session mode", func() config.VaultSelection { s := good; s.SessionMode = ""; return s }(), b, vaultEFormat},
		{"vaultUnknown session mode", func() config.VaultSelection { s := good; s.SessionMode = "Registered"; return s }(), b, vaultEFormat},
		{"invalid identity", func() config.VaultSelection { s := good; s.Identity.Name = "syn1:00"; return s }(), b, vaultEIdentity},
		// Combined faults: shape, then limits, then representation.
		{"bad mode beats bad identity", func() config.VaultSelection { s := good; s.SessionMode = "x"; s.Identity.Name = "syn1:00"; return s }(), b, vaultEFormat},
		{"binding limit beats bad identity", func() config.VaultSelection { s := good; s.Identity.Name = "syn1:00"; return s }(), vaultLongURLBinding(t), vaultELimit},
		{"identity limit beats bad domain", func() config.VaultSelection {
			s := good
			s.Identity.Domain = ""
			s.Identity.Origin = &config.VaultOrigin{HostID: strings.Repeat("h", 257), ProjectID: "p", ProfileID: "r"}
			return s
		}(), b, vaultELimit},
		{"bad identity beats nothing else", func() config.VaultSelection { s := good; s.Identity.Domain = "X"; return s }(), b, vaultEContext},
	} {
		if got := vaultTestCode(t, func() error { _, e := vaultObserve(tc.s, "fixture", tc.b); return e }()); got != tc.want {
			t.Fatalf("%s: %s", tc.label, got)
		}
	}
}

// Claim: secret and returned public-field byte bounds are checked before
// handoff; exact 1/16384-byte secrets are paired with 0/16385 rejections.
func TestVaultReplyBounds(t *testing.T) {
	for _, n := range []int{0, 1, 16384, 16385} {
		f := vaultNewFake(t)
		f.token = bytes.Repeat([]byte{1}, n)
		entered := 0
		r := vaultTestRun(t, f, vaultSessionDirect, func(b []byte) error {
			entered++
			if len(b) != n {
				t.Fatal("truncated secret")
			}
			return nil
		})
		if n == 1 || n == 16384 {
			if !r.acquisitionOK() || entered != 1 {
				t.Fatal("valid boundary refused")
			}
		} else {
			want := vaultDiagMalformed
			if n > 16384 {
				want = vaultDiagLimit
			}
			if r.Release.Outcome != vaultUnknown || r.Release.Diagnosis != want || entered != 0 {
				t.Fatal("invalid secret bound admitted")
			}
		}
	}
	for _, part := range []string{"identity", "binding"} {
		f := vaultNewFake(t)
		f.release = func(req vaultRequest) (vaultValue, error) {
			v := f.releaseResult(req)
			if part == "identity" {
				v = vaultTestWith(v, "identity", vaultTestWith(vaultTestGet(v, "identity"), "name", vaultString(strings.Repeat("a", 513))))
			} else {
				v = vaultTestWith(v, "consumer_binding", vaultTestWith(vaultTestGet(v, "consumer_binding"), "homeserver_url", vaultString("https://"+strings.Repeat("a", 8193))))
			}
			return vaultTestSuccess(req, v), nil
		}
		r := vaultTestRun(t, f, vaultSessionDirect, func([]byte) error { t.Fatal("oversize handoff"); return nil })
		if r.Release.Outcome != vaultUnknown || r.Release.Diagnosis != vaultDiagLimit {
			t.Fatal("returned public byte limit not checked")
		}
	}
}

// Claim: the dependency contract rechecks live peer/policy at invocation,
// after the client's last verification. Rejection is proven no-invocation;
// this is a logical driver contract control, not actual native verification.
func TestVaultInvocationRecheck(t *testing.T) {
	for _, part := range []string{"peer", "policy", ""} {
		f := vaultNewFake(t)
		f.beforeInvoke = func(vaultRequest) {
			if part == "peer" {
				f.conns[0].peer = &vaultPeerWitness{2}
			}
			if part == "policy" {
				f.conns[0].policy = &vaultPolicyWitness{2}
			}
		}
		r := vaultTestRun(t, f, vaultSessionDirect, func([]byte) error { return nil })
		if part == "" {
			if !r.acquisitionOK() {
				t.Fatal("invoke positive")
			}
		} else if r.Release.Outcome != vaultNotSubmitted || r.Release.Code != vaultEServerUntrusted || r.Release.Invocation != vaultNoInvocation || r.Release.Stage != vaultStageInvoke || r.Handoff != vaultHandoffNotEntered || f.effects != 0 {
			t.Fatal("invocation proof/policy changed without rejection")
		}
	}
}

// Claim: local setup/preparation faults have no invocation, an Open handle
// returned with an error is closed, and a post-invocation verifier panic is
// UNKNOWN. Native errors/panic payloads never become public diagnostics.
func TestVaultSetupFaults(t *testing.T) {
	for _, mode := range []string{"open", "open_handle_error", "prepare", "bad_prepare_failure", "post_verifier", ""} {
		f := vaultNewFake(t)
		switch mode {
		case "open", "prepare":
			f.panicAt = mode
		case "open_handle_error":
			f.openWithHandle = true
			f.openErr = errors.New(string(f.token))
		case "bad_prepare_failure":
			f.prepareFailure = &vaultFailure{Outcome: vaultRefused, Code: vaultERevoked}
		case "post_verifier":
			f.verifyHook = func(p vaultVerificationPoint, _ int, _ *vaultFakeConn, _ *vaultServiceVerification) {
				if p == vaultAfterReply {
					panic(string(f.token))
				}
			}
		}
		entered := 0
		r := vaultTestRun(t, f, vaultSessionDirect, func([]byte) error { entered++; return nil })
		if mode == "" {
			if !r.acquisitionOK() {
				t.Fatal("setup positive")
			}
			continue
		}
		if r.Failure == nil || entered != 0 {
			t.Fatal("setup fault admitted")
		}
		if bytes.Contains([]byte(r.diagnostic().Error()), f.token) {
			t.Fatal("private setup detail leaked")
		}
		if mode == "post_verifier" {
			if r.Release.Outcome != vaultUnknown || r.Release.Invocation != vaultInvoked || r.Release.Diagnosis != vaultDiagInternal || f.effects != 1 {
				t.Fatal("post-invoke panic phase")
			}
		} else if r.Failure.Outcome != vaultNotSubmitted || f.effects != 0 {
			t.Fatal("local setup misclassified")
		}
		if mode == "open_handle_error" && (f.closes != 1 || r.Failure.Code != vaultEUnavailable) {
			t.Fatal("Open error handle leaked")
		}
	}
}
