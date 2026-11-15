package vaultv1

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/relux-works/a2a-swarm/internal/config"
)

// fakeVault is a TEST-ONLY logical double of the internal dependency boundary.
// It records call order and answers from a script. It proves this package's
// call contract only; it is not native signature verification or transport.
type fakeVault struct {
	events    []string
	requests  []Request
	openErr   error
	verifyErr error
	proof     *ServiceProof
	reply     func(req Request, n int) (Value, error) // n counts submits on this connection
	secret    []byte
	buffers   [][]byte // every secret buffer handed out, for wipe checks
	panicAt   string
}

type fakeConn struct {
	v *fakeVault
	n int
}

func (f *fakeVault) Open(context.Context) (Conn, error) {
	f.events = append(f.events, "open")
	if f.panicAt == "open" {
		panic("injected")
	}
	if f.openErr != nil {
		return nil, f.openErr
	}
	return &fakeConn{v: f}, nil
}

func (f *fakeVault) VerifyService(_ context.Context, c Conn) (ServiceProof, error) {
	f.events = append(f.events, "verify")
	if f.panicAt == "verify" {
		panic("injected")
	}
	if _, ok := c.(*fakeConn); !ok {
		return ServiceProof{}, errors.New("foreign connection")
	}
	if f.verifyErr != nil {
		return ServiceProof{}, f.verifyErr
	}
	if f.proof != nil {
		return *f.proof, nil
	}
	return goodProof(), nil
}

func goodProof() ServiceProof {
	return ServiceProof{Role: RoleVaultServer, CodeID: "fixture.vault.server", LeafSHA256: strings.Repeat("ab", 32), PinsetVersion: 1}
}

func (c *fakeConn) Submit(_ context.Context, req Request) (Value, error) {
	c.v.events = append(c.v.events, "submit:"+string(req.Op))
	c.v.requests = append(c.v.requests, req)
	c.n++
	if c.v.panicAt == "submit" {
		panic("injected")
	}
	v, err := c.v.reply(req, c.n)
	c.v.track(v)
	return v, err
}

// track records every byte buffer actually handed out in a reply.
func (f *fakeVault) track(v Value) {
	if v.kind == KindBytes {
		f.buffers = append(f.buffers, v.bytes)
	}
	for _, it := range v.items {
		f.track(it)
	}
	for _, fl := range v.fields {
		f.track(fl.Value)
	}
}

func (c *fakeConn) Close() error {
	c.v.events = append(c.v.events, "close")
	return nil
}

func (f *fakeVault) dep() *Dependency { return &Dependency{Driver: f, Verifier: f} }

// session/identity/binding values the honest fake echoes back.
func echoIdentity(req Request) Value {
	m, _ := req.Body.closed(fieldKeys(req.Body)...)
	return m["identity"]
}

func fieldKeys(v Value) []string {
	var k []string
	for _, f := range v.fields {
		k = append(k, f.Key)
	}
	return k
}

func success(req Request, result Value) Value {
	return Dict(F("v", Uint(2)), F("request_id", String(req.ID)), F("op", String(string(req.Op))), F("ok", Bool(true)), F("result", result))
}

func refusal(req Request, c string) Value {
	return Dict(F("v", Uint(2)), F("request_id", String(req.ID)), F("op", String(string(req.Op))), F("ok", Bool(false)), F("error", Dict(F("code", String(c)))))
}

func registerResult(req Request) Value {
	return Dict(F("identity", echoIdentity(req)), F("session", Dict(F("epoch", String(strings.Repeat("e", 32))), F("session_id", String(strings.Repeat("5", 32))), F("generation", Uint(1)))), F("lifetime_ms", Uint(900000)))
}

func (f *fakeVault) releaseResult(req Request) Value {
	m, _ := req.Body.closed("identity", "session", "expected_binding")
	buf := append([]byte(nil), f.secret...)
	return Dict(F("identity", m["identity"]), F("consumer_binding", m["expected_binding"]), F("record_revision", Uint(1)), F("secret", Bytes(buf)))
}

// honest answers register and release correctly.
func (f *fakeVault) honest(req Request, _ int) (Value, error) {
	if req.Op == OpRegister {
		return success(req, registerResult(req)), nil
	}
	return success(req, f.releaseResult(req)), nil
}

func newFake(t *testing.T) *fakeVault {
	t.Helper()
	secret := make([]byte, 24)
	if _, err := rand.Read(secret); err != nil { // runner-generated, never printed
		t.Fatal(err)
	}
	f := &fakeVault{secret: secret}
	f.reply = f.honest
	return f
}

func latched(t *testing.T, mode string) Selection {
	t.Helper()
	c := config.Connection{ID: "fixture-a", URL: "https://matrix-a.example.invalid", ServerName: "a.example.invalid", Store: config.CredentialStore{Backend: config.BackendVaultV1}}
	b, err := c.Binding("fixture", false)
	if err != nil {
		t.Fatal(err)
	}
	sel, err := Latch(config.VaultSelection{Identity: config.VaultIdentity{Domain: "fixture-domain", Kind: KindExplicit, Name: "fixture-a"}, SessionMode: mode}, "fixture", b)
	if err != nil {
		t.Fatal(err)
	}
	return sel
}

func outcome(t *testing.T, err error) *Refusal {
	t.Helper()
	var r *Refusal
	if !errors.As(err, &r) {
		t.Fatalf("not a vault refusal: %v", err)
	}
	return r
}

func join(s []string) string { return strings.Join(s, ",") }

// Claim: a registered release verifies the service before anything is
// submitted, registers then releases with fresh distinct request IDs and the
// returned session, hands exactly the vault bytes to the consumer once, and
// clears the reply buffer afterwards. Direct mode submits only a release with
// a null session. Limit: logical double only; no native verification.
func TestReleaseCallOrderPositive(t *testing.T) {
	for _, tc := range []struct {
		mode, events string
	}{
		{SessionRegistered, "open,verify,submit:register,submit:release,close"},
		{SessionDirect, "open,verify,submit:release,close"},
	} {
		f := newFake(t)
		c, err := NewClient(f.dep())
		if err != nil {
			t.Fatal(err)
		}
		var got [][]byte
		res, err := c.Release(context.Background(), latched(t, tc.mode), func(s []byte) { got = append(got, append([]byte(nil), s...)) })
		if err != nil || res.Outcome != Succeeded || res.Revision != 1 {
			t.Fatalf("%s: %v %+v", tc.mode, err, res)
		}
		if join(f.events) != tc.events {
			t.Fatalf("%s order: %s", tc.mode, join(f.events))
		}
		if len(got) != 1 || !bytes.Equal(got[0], f.secret) {
			t.Fatalf("%s: consumer did not receive exactly the selected bytes", tc.mode)
		}
		if len(f.buffers) != 1 || bytes.Count(f.buffers[0], []byte{0}) != len(f.buffers[0]) {
			t.Fatalf("%s: owned reply buffer not cleared", tc.mode)
		}
		rel := f.requests[len(f.requests)-1]
		m, _ := rel.Body.closed("identity", "session", "expected_binding")
		if tc.mode == SessionDirect && m["session"].kind != KindNull {
			t.Fatal("direct release carried a session")
		}
		if tc.mode == SessionRegistered {
			if f.requests[0].ID == rel.ID || !hex32RE.MatchString(rel.ID) || !hex32RE.MatchString(f.requests[0].ID) {
				t.Fatal("request IDs are not fresh distinct Hex32")
			}
			s, _ := m["session"].closed("epoch", "session_id", "generation")
			if s["session_id"].s != strings.Repeat("5", 32) || s["generation"].u != 1 {
				t.Fatal("release did not carry the registered session")
			}
		}
	}
}

// Claim: an absent production dependency, a nil/typed-nil driver or verifier,
// an unlatched selection and a nil consumer refuse before any open, verify or
// submit, with the r4 pre-submission codes.
func TestReleaseMissingDependency(t *testing.T) {
	var typedNil *fakeVault
	f := newFake(t)
	for _, tc := range []struct {
		label string
		dep   *Dependency
		want  Code
	}{
		{"nil dependency (production default)", nil, EUnavailable},
		{"nil driver", &Dependency{Verifier: f}, EUnavailable},
		{"typed-nil driver", &Dependency{Driver: typedNil, Verifier: f}, EUnavailable},
		{"nil verifier", &Dependency{Driver: f}, EServerUntrusted},
		{"typed-nil verifier", &Dependency{Driver: f, Verifier: typedNil}, EServerUntrusted},
	} {
		_, err := NewClient(tc.dep)
		if r := outcome(t, err); r.Outcome != NotSubmitted || r.Code != tc.want {
			t.Fatalf("%s: %v", tc.label, err)
		}
	}
	c, _ := NewClient(f.dep())
	called := false
	if _, err := c.Release(context.Background(), Selection{}, func([]byte) { called = true }); outcome(t, err).Code != EBackendConfig {
		t.Fatal("zero selection admitted")
	}
	if _, err := c.Release(context.Background(), latched(t, SessionDirect), nil); outcome(t, err).Code != EBackendConfig {
		t.Fatal("nil consumer admitted")
	}
	if len(f.events) != 0 || called {
		t.Fatalf("dependency used before refusal: %s", join(f.events))
	}
}

// Claim: open failure, verifier error, every invalid or zero proof, panics
// before submission and pre-submit cancellation stop before any submit and
// before consumer handoff; raw dependency errors never reach the error text.
func TestReleaseVerificationIsMandatory(t *testing.T) {
	sentinel := "raw-dependency-detail-7f3a"
	for _, tc := range []struct {
		label  string
		setup  func(*fakeVault)
		ctx    func() context.Context
		want   Code
		events string
	}{
		{"open error", func(f *fakeVault) { f.openErr = errors.New(sentinel) }, nil, EUnavailable, "open"},
		{"verifier error", func(f *fakeVault) { f.verifyErr = errors.New(sentinel) }, nil, EServerUntrusted, "open,verify,close"},
		{"zero proof", func(f *fakeVault) { f.proof = &ServiceProof{} }, nil, EServerUntrusted, "open,verify,close"},
		{"client role", func(f *fakeVault) { p := goodProof(); p.Role = "a2a-release-client"; f.proof = &p }, nil, EServerUntrusted, "open,verify,close"},
		{"team-id-like code only", func(f *fakeVault) { p := goodProof(); p.LeafSHA256 = ""; f.proof = &p }, nil, EServerUntrusted, "open,verify,close"},
		{"uppercase leaf", func(f *fakeVault) { p := goodProof(); p.LeafSHA256 = strings.Repeat("AB", 32); f.proof = &p }, nil, EServerUntrusted, "open,verify,close"},
		{"empty code id", func(f *fakeVault) { p := goodProof(); p.CodeID = ""; f.proof = &p }, nil, EServerUntrusted, "open,verify,close"},
		{"256-byte code id", func(f *fakeVault) { p := goodProof(); p.CodeID = strings.Repeat("c", 256); f.proof = &p }, nil, EServerUntrusted, "open,verify,close"},
		{"pinset zero", func(f *fakeVault) { p := goodProof(); p.PinsetVersion = 0; f.proof = &p }, nil, EServerUntrusted, "open,verify,close"},
		{"verifier panic", func(f *fakeVault) { f.panicAt = "verify" }, nil, EInternal, "open,verify,close"},
		{"open panic", func(f *fakeVault) { f.panicAt = "open" }, nil, EInternal, "open"},
		{"cancelled before open", nil, func() context.Context { c, cancel := context.WithCancel(context.Background()); cancel(); return c }, EUnavailable, ""},
	} {
		f := newFake(t)
		if tc.setup != nil {
			tc.setup(f)
		}
		ctx := context.Background()
		if tc.ctx != nil {
			ctx = tc.ctx()
		}
		c, _ := NewClient(f.dep())
		called := false
		_, err := c.Release(ctx, latched(t, SessionRegistered), func([]byte) { called = true })
		r := outcome(t, err)
		if r.Outcome != NotSubmitted || r.Code != tc.want || called || join(f.events) != tc.events || len(f.requests) != 0 {
			t.Fatalf("%s: %v events=%s called=%v", tc.label, err, join(f.events), called)
		}
		if strings.Contains(err.Error(), sentinel) {
			t.Fatalf("%s: raw dependency error leaked", tc.label)
		}
	}
	// Positive neighbour with the same fixture: a valid proof proceeds.
	f := newFake(t)
	c, _ := NewClient(f.dep())
	if _, err := c.Release(context.Background(), latched(t, SessionRegistered), func([]byte) {}); err != nil {
		t.Fatalf("valid proof refused: %v", err)
	}
}

// Claim: only a well-formed, matching RefusalV2 carrying one of the 26 closed
// codes is REFUSED, for register and for release; the consumer is never
// called. An unknown code is UNKNOWN, not a refusal.
func TestReleaseAuthenticatedRefusals(t *testing.T) {
	for _, op := range []Op{OpRegister, OpRelease} {
		for _, want := range AllCodes {
			f := newFake(t)
			f.reply = func(req Request, n int) (Value, error) {
				if req.Op == op {
					return refusal(req, string(want)), nil
				}
				return f.honest(req, n)
			}
			c, _ := NewClient(f.dep())
			called := false
			_, err := c.Release(context.Background(), latched(t, SessionRegistered), func([]byte) { called = true })
			if r := outcome(t, err); r.Outcome != Refused || r.Code != want || called {
				t.Fatalf("%s %s: %v", op, want, err)
			}
		}
	}
	if len(AllCodes) != 26 {
		t.Fatal("closed vocabulary is not exactly 26 codes")
	}
	f := newFake(t)
	f.reply = func(req Request, _ int) (Value, error) { return refusal(req, "E_NOT_A_CODE"), nil }
	c, _ := NewClient(f.dep())
	if _, err := c.Release(context.Background(), latched(t, SessionDirect), func([]byte) {}); outcome(t, err).Outcome != Unknown {
		t.Fatal("unknown refusal code became REFUSED")
	}
}

func withField(v Value, key string, nv Value) Value {
	out := Value{kind: v.kind}
	for _, f := range v.fields {
		if f.Key == key {
			f.Value = nv
		}
		out.fields = append(out.fields, f)
	}
	return out
}

func without(v Value, key string) Value {
	out := Value{kind: v.kind}
	for _, f := range v.fields {
		if f.Key != key {
			out.fields = append(out.fields, f)
		}
	}
	return out
}

func plus(v Value, key string, nv Value) Value {
	out := Value{kind: v.kind, fields: append([]Field(nil), v.fields...)}
	out.fields = append(out.fields, F(key, nv))
	return out
}

func get(v Value, key string) Value {
	for _, f := range v.fields {
		if f.Key == key {
			return f.Value
		}
	}
	return Value{}
}

func nest(depth int) Value {
	v := Null()
	for i := 0; i < depth; i++ {
		v = Dict(F("x", v))
	}
	return v
}

// Claim: every submitted reply that is not exactly the matching closed
// success (changed v/request/op/identity/binding/revision, unknown or missing
// fields, wrong types, duplicate keys, over-limit secret/depth/fields, invalid
// strings, cross-operation results) or a transport error/panic after
// submission is UNKNOWN with zero consumer bytes, every handed-out secret
// buffer cleared, and no secret or raw error in the error text. A clean
// release with the same fixture succeeds.
func TestReleaseSubmittedRepliesAreUnknown(t *testing.T) {
	type mutate func(f *fakeVault, req Request) (Value, error)
	rel := func(m func(f *fakeVault, req Request, ok Value) Value) mutate {
		return func(f *fakeVault, req Request) (Value, error) {
			return m(f, req, success(req, f.releaseResult(req))), nil
		}
	}
	res := func(m func(r Value) Value) mutate {
		return rel(func(_ *fakeVault, _ Request, ok Value) Value { return withField(ok, "result", m(get(ok, "result"))) })
	}
	bind := func(key string, nv Value) mutate {
		return res(func(r Value) Value {
			return withField(r, "consumer_binding", withField(get(r, "consumer_binding"), key, nv))
		})
	}
	ident := func(key string, nv Value) mutate {
		return res(func(r Value) Value { return withField(r, "identity", withField(get(r, "identity"), key, nv)) })
	}
	for _, tc := range []struct {
		label string
		m     mutate
		diag  Diagnosis
	}{
		{"transport error", func(*fakeVault, Request) (Value, error) { return Value{}, errors.New("disconnect") }, DiagTransport},
		{"v 1", rel(func(_ *fakeVault, _ Request, ok Value) Value { return withField(ok, "v", Uint(1)) }), DiagMismatch},
		{"v 3", rel(func(_ *fakeVault, _ Request, ok Value) Value { return withField(ok, "v", Uint(3)) }), DiagMismatch},
		{"v string", rel(func(_ *fakeVault, _ Request, ok Value) Value { return withField(ok, "v", String("2")) }), DiagMalformed},
		{"missing v", rel(func(_ *fakeVault, _ Request, ok Value) Value { return without(ok, "v") }), DiagMalformed},
		{"other request_id", rel(func(_ *fakeVault, _ Request, ok Value) Value {
			return withField(ok, "request_id", String(strings.Repeat("0", 32)))
		}), DiagMismatch},
		{"register op", rel(func(_ *fakeVault, _ Request, ok Value) Value { return withField(ok, "op", String("register")) }), DiagMismatch},
		{"ok string", rel(func(_ *fakeVault, _ Request, ok Value) Value { return withField(ok, "ok", String("true")) }), DiagMalformed},
		{"ok false with result", rel(func(_ *fakeVault, _ Request, ok Value) Value { return withField(ok, "ok", Bool(false)) }), DiagMalformed},
		{"unknown top-level field", rel(func(_ *fakeVault, _ Request, ok Value) Value { return plus(ok, "detail", String("x")) }), DiagMalformed},
		{"duplicate key", rel(func(_ *fakeVault, _ Request, ok Value) Value { return plus(without(ok, "v"), "op", String("release")) }), DiagMalformed},
		{"unknown result field", res(func(r Value) Value { return plus(r, "note", String("x")) }), DiagMalformed},
		{"extra session data on release", res(func(r Value) Value { return plus(r, "session", Null()) }), DiagMalformed},
		{"register-shaped result", func(_ *fakeVault, req Request) (Value, error) { return success(req, registerResult(req)), nil }, DiagMalformed},
		{"close-shaped result", func(_ *fakeVault, req Request) (Value, error) {
			return success(req, Dict(F("state", String("closed")))), nil
		}, DiagMalformed},
		{"identity name changed", ident("name", String("fixture-b")), DiagMismatch},
		{"identity domain changed", ident("domain", String("other-domain")), DiagMismatch},
		{"identity kind changed", ident("kind", String("synthetic")), DiagMismatch},
		{"identity origin added", ident("origin", Dict(F("host_id", String("h")), F("project_id", String("p")), F("profile_id", String("r")))), DiagMismatch},
		{"identity origin wrong type", ident("origin", String("null")), DiagMalformed},
		{"binding user changed", bind("user_id", String("@fixture:b.example.invalid")), DiagMismatch},
		{"binding server changed", bind("server_name", String("b.example.invalid")), DiagMismatch},
		{"binding URL trailing slash", bind("homeserver_url", String("https://matrix-a.example.invalid/")), DiagMismatch},
		{"binding selector changed", bind("a2a_selector", String("fixture-b")), DiagMismatch},
		{"binding_v 2", bind("binding_v", Uint(2)), DiagMismatch},
		{"binding_v string", bind("binding_v", String("1")), DiagMalformed},
		{"revision 0", res(func(r Value) Value { return withField(r, "record_revision", Uint(0)) }), DiagMalformed},
		{"revision 2^63", res(func(r Value) Value { return withField(r, "record_revision", Uint(1<<63)) }), DiagMalformed},
		{"secret as string", res(func(r Value) Value { return withField(r, "secret", String("x")) }), DiagMalformed},
		{"empty secret", res(func(r Value) Value { return withField(r, "secret", Bytes([]byte{})) }), DiagMalformed},
		{"secret 16385 bytes", func(f *fakeVault, req Request) (Value, error) {
			ok := success(req, f.releaseResult(req))
			big := bytes.Repeat(f.secret[:1], MaxSecret+1)
			return withField(ok, "result", withField(get(ok, "result"), "secret", Bytes(big))), nil
		}, DiagLimit},
		{"nesting depth 9", rel(func(_ *fakeVault, _ Request, ok Value) Value { return plus(without(ok, "result"), "result", nest(8)) }), DiagLimit},
		{"33 fields", rel(func(_ *fakeVault, _ Request, ok Value) Value {
			r := get(ok, "result")
			for i := 0; len(r.fields) < 33; i++ {
				r = plus(r, "pad"+string(rune('a'+i)), Null())
			}
			return withField(ok, "result", r)
		}), DiagLimit},
		{"invalid UTF-8 string", ident("name", String("fixture-\xff")), DiagMalformed},
		{"NUL string", ident("name", String("fixture-a\x00")), DiagMalformed},
		{"refusal with extra field", func(_ *fakeVault, req Request) (Value, error) {
			return plus(refusal(req, "E_REVOKED"), "secret", Bytes([]byte("x"))), nil
		}, DiagMalformed},
		{"refusal code wrong type", func(_ *fakeVault, req Request) (Value, error) {
			return withField(refusal(req, "E_REVOKED"), "error", Dict(F("code", Uint(1)))), nil
		}, DiagMalformed},
		{"refusal with detail", func(_ *fakeVault, req Request) (Value, error) {
			return withField(refusal(req, "E_REVOKED"), "error", Dict(F("code", String("E_REVOKED")), F("detail", String("x")))), nil
		}, DiagMalformed},
		{"refusal for other request", func(_ *fakeVault, req Request) (Value, error) {
			return withField(refusal(req, "E_REVOKED"), "request_id", String(strings.Repeat("1", 32))), nil
		}, DiagMismatch},
		{"submit panic", func(*fakeVault, Request) (Value, error) { panic("injected") }, DiagInternal},
	} {
		f := newFake(t)
		tc := tc
		f.reply = func(req Request, n int) (Value, error) {
			if req.Op == OpRelease {
				return tc.m(f, req)
			}
			return f.honest(req, n)
		}
		c, _ := NewClient(f.dep())
		called := false
		_, err := c.Release(context.Background(), latched(t, SessionRegistered), func([]byte) { called = true })
		r := outcome(t, err)
		if r.Outcome != Unknown || r.Diagnosis != tc.diag || r.Code != "" || called {
			t.Fatalf("%s: %v (called=%v)", tc.label, err, called)
		}
		for _, b := range f.buffers {
			if bytes.Count(b, []byte{0}) != len(b) {
				t.Fatalf("%s: reply secret buffer not cleared", tc.label)
			}
		}
		if bytes.Contains([]byte(err.Error()), f.secret) {
			t.Fatalf("%s: secret in error", tc.label)
		}
		if join(f.events) != "open,verify,submit:register,submit:release,close" {
			t.Fatalf("%s: events %s", tc.label, join(f.events))
		}
	}
}

// Claim: a register reply carrying release data (an extra secret), a wrong
// lifetime, a non-Hex32 session or a changed identity is UNKNOWN and stops
// before any release is submitted.
func TestRegisterRepliesAreClosed(t *testing.T) {
	for _, tc := range []struct {
		label string
		m     func(req Request) Value
	}{
		{"extra secret", func(req Request) Value {
			return withField(success(req, plus(registerResult(req), "secret", Bytes([]byte("x")))), "op", String("register"))
		}},
		{"release-shaped", func(req Request) Value {
			return success(req, Dict(F("identity", echoIdentity(req)), F("consumer_binding", Null()), F("record_revision", Uint(1)), F("secret", Bytes([]byte("x")))))
		}},
		{"lifetime changed", func(req Request) Value {
			return success(req, withField(registerResult(req), "lifetime_ms", Uint(900001)))
		}},
		{"generation 0", func(req Request) Value {
			r := registerResult(req)
			return success(req, withField(r, "session", withField(get(r, "session"), "generation", Uint(0))))
		}},
		{"uppercase session id", func(req Request) Value {
			r := registerResult(req)
			return success(req, withField(r, "session", withField(get(r, "session"), "session_id", String(strings.Repeat("A", 32)))))
		}},
		{"identity changed", func(req Request) Value {
			r := registerResult(req)
			return success(req, withField(r, "identity", withField(get(r, "identity"), "name", String("fixture-b"))))
		}},
	} {
		f := newFake(t)
		f.reply = func(req Request, n int) (Value, error) {
			if req.Op == OpRegister {
				return tc.m(req), nil
			}
			return f.honest(req, n)
		}
		c, _ := NewClient(f.dep())
		_, err := c.Release(context.Background(), latched(t, SessionRegistered), func([]byte) { t.Fatal("consumer called") })
		if outcome(t, err).Outcome != Unknown || join(f.events) != "open,verify,submit:register,close" {
			t.Fatalf("%s: %v %s", tc.label, err, join(f.events))
		}
	}
}

// Claim: after an UNKNOWN outcome a later call is a NEW attempt on a new
// connection with new request IDs and a new registration; nothing is reused
// and there is no terminal no-resend latch. No automatic retry happens.
func TestNewAttemptAfterUnknown(t *testing.T) {
	f := newFake(t)
	first := true
	f.reply = func(req Request, n int) (Value, error) {
		if req.Op == OpRelease && first {
			first = false
			return Value{}, errors.New("lost")
		}
		return f.honest(req, n)
	}
	c, _ := NewClient(f.dep())
	sel := latched(t, SessionRegistered)
	if _, err := c.Release(context.Background(), sel, func([]byte) {}); outcome(t, err).Outcome != Unknown {
		t.Fatal("lost reply was not UNKNOWN")
	}
	if join(f.events) != "open,verify,submit:register,submit:release,close" {
		t.Fatalf("automatic retry or extra effect: %s", join(f.events))
	}
	var got []byte
	if _, err := c.Release(context.Background(), sel, func(s []byte) { got = append([]byte(nil), s...) }); err != nil || !bytes.Equal(got, f.secret) {
		t.Fatalf("fresh attempt failed: %v", err)
	}
	if join(f.events) != "open,verify,submit:register,submit:release,close,open,verify,submit:register,submit:release,close" {
		t.Fatalf("second attempt order: %s", join(f.events))
	}
	seen := map[string]bool{}
	for _, r := range f.requests {
		if seen[r.ID] {
			t.Fatal("request ID reused across attempts")
		}
		seen[r.ID] = true
	}
}

// longURLBinding is a source-valid vault-v1 binding whose 8193-byte endpoint
// exceeds only the new native envelope.
func longURLBinding(t *testing.T) config.ConnectionBinding {
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

// Claim: Latch accepts an explicit or synthetic selection on a vault-v1
// agents binding and refuses a legacy backend, the humans class, an unknown
// or empty session mode and an invalid identity, with no default mode.
func TestLatchSelection(t *testing.T) {
	c := config.Connection{ID: "fixture-a", URL: "https://matrix-a.example.invalid", ServerName: "a.example.invalid", Store: config.CredentialStore{Backend: config.BackendVaultV1}}
	b, _ := c.Binding("fixture", false)
	v := syntheticVectors[0]
	good := config.VaultSelection{Identity: config.VaultIdentity{Domain: "example", Kind: KindSynthetic, Name: v.name, Origin: &config.VaultOrigin{HostID: v.host, ProjectID: v.project, ProfileID: v.profile}}, SessionMode: SessionRegistered}
	sel, err := Latch(good, "fixture", b)
	if err != nil || !sel.Latched() || sel.SessionMode() != SessionRegistered || sel.Binding().UserID != "@fixture:a.example.invalid" || sel.Identity().Name != v.name {
		t.Fatalf("valid synthetic selection: %v", err)
	}
	again, _ := Latch(good, "fixture", b)
	if !sel.Equal(again) {
		t.Fatal("identical latch differs")
	}
	other := good
	other.SessionMode = SessionDirect
	if o, _ := Latch(other, "fixture", b); sel.Equal(o) {
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
		want  Code
	}{
		{"legacy backend", good, fb, EBackendConfig},
		{"humans class", good, hb, EBackendConfig},
		{"empty session mode", func() config.VaultSelection { s := good; s.SessionMode = ""; return s }(), b, EFormat},
		{"unknown session mode", func() config.VaultSelection { s := good; s.SessionMode = "Registered"; return s }(), b, EFormat},
		{"invalid identity", func() config.VaultSelection { s := good; s.Identity.Name = "syn1:00"; return s }(), b, EIdentity},
		// Combined faults: shape, then limits, then representation.
		{"bad mode beats bad identity", func() config.VaultSelection { s := good; s.SessionMode = "x"; s.Identity.Name = "syn1:00"; return s }(), b, EFormat},
		{"binding limit beats bad identity", func() config.VaultSelection { s := good; s.Identity.Name = "syn1:00"; return s }(), longURLBinding(t), ELimit},
		{"identity limit beats bad domain", func() config.VaultSelection {
			s := good
			s.Identity.Domain = ""
			s.Identity.Origin = &config.VaultOrigin{HostID: strings.Repeat("h", 257), ProjectID: "p", ProfileID: "r"}
			return s
		}(), b, ELimit},
		{"bad identity beats nothing else", func() config.VaultSelection { s := good; s.Identity.Domain = "X"; return s }(), b, EContext},
	} {
		if got := code(t, func() error { _, e := Latch(tc.s, "fixture", tc.b); return e }()); got != tc.want {
			t.Fatalf("%s: %s", tc.label, got)
		}
	}
}
