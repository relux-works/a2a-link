package vaultv1

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"reflect"
	"regexp"
)

// Driver is the reviewed INTERNAL dependency boundary for the future qualified
// native driver (Darwin Mach/XPC per CONTRACT-r4 T1). Bootstrap, endpoint
// selection, byte encoding, size accounting, kernel peer evidence and process
// incarnation live behind it. No implementation exists in this unit, and none
// is selectable through an environment variable, flag, file or argument.
type Driver interface {
	// Open establishes one connection before anything is submitted. Any error
	// is a pre-submission E_UNAVAILABLE.
	Open(ctx context.Context) (Conn, error)
}

// Conn is one live native connection. Sessions and replay sets are scoped to
// it; closing it invalidates them.
type Conn interface {
	// Submit sends one logical RequestV2 and returns the logical reply. Once
	// Submit is called the request counts as submitted: an error, panic or
	// cancellation is UNKNOWN, never a refusal.
	Submit(ctx context.Context, req Request) (Value, error)
	Close() error
}

// ServiceVerifier is the MANDATORY service code-signature verification
// dependency. It must derive its result from the live connection's
// kernel-reported peer and the signed-release pinset (CONTRACT-r4 section 6),
// never from payload bytes, a supplied path, PID or certificate. A logical
// test double proves only this package's call contract, not that the
// platform verified a running signature.
type ServiceVerifier interface {
	VerifyService(ctx context.Context, conn Conn) (ServiceProof, error)
}

// RoleVaultServer is the only admitted service role. The a2a release-client
// role is distinct and never accepted here.
const RoleVaultServer = "vault-server"

// ServiceProof is the verifier's positive claim about the connected service.
// The zero value is not a proof. A proof is consumed only for the connection
// it was produced for, inside one Release call.
type ServiceProof struct {
	Role          string
	CodeID        string // exact code identifier, 1..255 bytes
	LeafSHA256    string // SHA-256 of the complete leaf certificate DER, 64 lowercase hex
	PinsetVersion uint64 // >= 1
}

var digestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (p ServiceProof) valid() bool {
	return p.Role == RoleVaultServer && publicText(p.CodeID) && len(p.CodeID) <= 255 && digestRE.MatchString(p.LeafSHA256) && p.PinsetVersion >= 1
}

// Dependency bundles the two mandatory parts. There is no skip flag, trust
// field or default verifier.
type Dependency struct {
	Driver   Driver
	Verifier ServiceVerifier
}

// Client performs vault-v1 release operations against one Dependency.
type Client struct {
	dep  Dependency
	rand io.Reader
}

// NewClient refuses before any call when the dependency is absent: a nil or
// incomplete driver is E_UNAVAILABLE, a nil verifier E_SERVER_UNTRUSTED.
func NewClient(dep *Dependency) (*Client, error) {
	if dep == nil || isNil(dep.Driver) {
		return nil, notSubmitted(EUnavailable)
	}
	if isNil(dep.Verifier) {
		return nil, notSubmitted(EServerUntrusted)
	}
	return &Client{dep: *dep, rand: rand.Reader}, nil
}

func isNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Func, reflect.Interface, reflect.Chan, reflect.Slice:
		return rv.IsNil()
	}
	return false
}

// Result describes a SUCCEEDED release. Failures are returned as *Refusal.
type Result struct {
	Outcome  Outcome
	Revision uint64
}

// Release runs one complete audited release attempt for a latched selection:
//
//  1. refuse an unlatched selection (E_BACKEND_CONFIG);
//  2. Driver.Open (E_UNAVAILABLE on failure);
//  3. Verifier.VerifyService on that connection (E_SERVER_UNTRUSTED unless a
//     valid proof is returned) -- nothing is submitted before this succeeds;
//  4. registered mode: submit register, accept only a matching register result;
//  5. submit release with the latched identity, session (or null for direct)
//     and expected binding; accept only a fully matching release result;
//  6. hand the secret to consume, then clear the reply buffers and close.
//
// Every request uses a fresh random request ID. A failure after step 4 or 5 has
// been submitted is UNKNOWN unless a matching authenticated RefusalV2 arrived.
// A later call is a new attempt on a new connection with new IDs; there is no
// automatic retry, no cached session and no terminal no-resend latch.
func (c *Client) Release(ctx context.Context, sel Selection, consume func(secret []byte)) (res Result, err error) {
	if !sel.latched || consume == nil {
		return Result{}, notSubmitted(EBackendConfig)
	}
	submitted := false
	var conn Conn
	defer func() {
		if p := recover(); p != nil {
			res = Result{}
			if submitted {
				err = unknown(DiagInternal)
			} else {
				err = notSubmitted(EInternal)
			}
		}
		if !isNil(conn) {
			func() {
				defer func() { _ = recover() }()
				_ = conn.Close()
			}()
		}
	}()
	if ctx.Err() != nil {
		return Result{}, notSubmitted(EUnavailable)
	}
	opened, e := c.dep.Driver.Open(ctx)
	if e != nil || isNil(opened) {
		return Result{}, notSubmitted(EUnavailable)
	}
	conn = opened
	proof, e := c.dep.Verifier.VerifyService(ctx, conn)
	if e != nil || !proof.valid() {
		return Result{}, notSubmitted(EServerUntrusted)
	}
	if ctx.Err() != nil {
		return Result{}, notSubmitted(EUnavailable)
	}
	var session *Session
	if sel.mode == SessionRegistered {
		id, r := c.requestID()
		if r != nil {
			return Result{}, r
		}
		req := registerRequest(id, sel.identity)
		submitted = true
		reply, e := conn.Submit(ctx, req)
		if e != nil {
			reply.wipe()
			return Result{}, unknown(DiagTransport)
		}
		result, r := classify(req, reply)
		if r == nil {
			var s Session
			if s, r = parseRegister(result, sel.identity); r == nil {
				session = &s
			}
		}
		reply.wipe()
		if r != nil {
			return Result{}, r
		}
	}
	id, r := c.requestID()
	if r != nil {
		if submitted {
			return Result{}, unknown(DiagInternal)
		}
		return Result{}, r
	}
	req := releaseRequest(id, sel.identity, session, sel.binding)
	submitted = true
	reply, e := conn.Submit(ctx, req)
	defer reply.wipe()
	if e != nil {
		return Result{}, unknown(DiagTransport)
	}
	result, r := classify(req, reply)
	if r != nil {
		return Result{}, r
	}
	secret, rev, r := parseRelease(result, sel.identity, sel.binding)
	if r != nil {
		return Result{}, r
	}
	consume(secret)
	return Result{Outcome: Succeeded, Revision: rev}, nil
}

// requestID draws 128 random bits as Hex32. Failure before submission is
// E_INTERNAL; IDs are never derived, counted or reused.
func (c *Client) requestID() (string, *Refusal) {
	var b [16]byte
	if _, e := io.ReadFull(c.rand, b[:]); e != nil {
		return "", notSubmitted(EInternal)
	}
	return hex.EncodeToString(b[:]), nil
}
