package vaultv1

// Code is the closed r4 vault/integration refusal vocabulary (CONTRACT-r4
// section 9.2). No other code is ever produced or accepted from a reply.
type Code string

const (
	EVersion              Code = "E_VERSION"
	EFormat               Code = "E_FORMAT"
	ELimit                Code = "E_LIMIT"
	EIdentity             Code = "E_IDENTITY"
	EContext              Code = "E_CONTEXT"
	EIdentityConflict     Code = "E_IDENTITY_CONFLICT"
	EHome                 Code = "E_HOME"
	EBackendConfig        Code = "E_BACKEND_CONFIG"
	EUnavailable          Code = "E_UNAVAILABLE"
	EServerUntrusted      Code = "E_SERVER_UNTRUSTED"
	ECallerUntrusted      Code = "E_CALLER_UNTRUSTED"
	EOperationDenied      Code = "E_OPERATION_DENIED"
	EReplay               Code = "E_REPLAY"
	EUnknownIdentity      Code = "E_UNKNOWN_IDENTITY"
	ERevoked              Code = "E_REVOKED"
	EDeleted              Code = "E_DELETED"
	EConflict             Code = "E_CONFLICT"
	ESessionRequired      Code = "E_SESSION_REQUIRED"
	ESessionStale         Code = "E_SESSION_STALE"
	ESessionBinding       Code = "E_SESSION_BINDING"
	ECustody              Code = "E_CUSTODY"
	EIntegrity            Code = "E_INTEGRITY"
	EAudit                Code = "E_AUDIT"
	EMigrationUnqualified Code = "E_MIGRATION_UNQUALIFIED"
	EMigrationConflict    Code = "E_MIGRATION_CONFLICT"
	EInternal             Code = "E_INTERNAL"
)

// AllCodes is the complete closed set, in contract order (26 codes).
var AllCodes = [...]Code{
	EVersion, EFormat, ELimit, EIdentity, EContext, EIdentityConflict, EHome,
	EBackendConfig, EUnavailable, EServerUntrusted, ECallerUntrusted,
	EOperationDenied, EReplay, EUnknownIdentity, ERevoked, EDeleted, EConflict,
	ESessionRequired, ESessionStale, ESessionBinding, ECustody, EIntegrity,
	EAudit, EMigrationUnqualified, EMigrationConflict, EInternal,
}

// Known reports membership in the closed vocabulary.
func (c Code) Known() bool {
	for _, k := range AllCodes {
		if c == k {
			return true
		}
	}
	return false
}

// Outcome is the client-observed operation state (CONTRACT-r4 section 5).
type Outcome string

const (
	// NotSubmitted: nothing reached the service; a local refusal code applies.
	NotSubmitted Outcome = "NOT_SUBMITTED"
	// Refused: an authenticated, well-formed, matching RefusalV2 was received.
	Refused Outcome = "REFUSED"
	// Succeeded: a fully validated release reached the consumer.
	Succeeded Outcome = "SUCCEEDED"
	// Unknown: submitted, but the effect cannot be known. Never a refusal and
	// never no-effect evidence. A later call is a NEW audited attempt.
	Unknown Outcome = "UNKNOWN"
)

// Diagnosis is the fixed local diagnosis of an UNKNOWN outcome. Response
// bytes and raw errors are never converted into diagnostics.
type Diagnosis string

const (
	DiagTransport Diagnosis = "transport_lost"   // submit error, timeout, cancellation or disconnect after submission
	DiagMalformed Diagnosis = "reply_malformed"  // not the closed operation shape or not admitted native types
	DiagMismatch  Diagnosis = "reply_mismatch"   // version/request/op/identity/binding differs from the request
	DiagLimit     Diagnosis = "reply_over_limit" // depth/field/byte bound exceeded in a submitted reply
	DiagInternal  Diagnosis = "internal_after_submit"
)

// Refusal is the only error type this package returns. Its text is built
// from closed values only; it never wraps or reproduces a dependency error.
type Refusal struct {
	Outcome   Outcome
	Code      Code      // empty only for Unknown
	Diagnosis Diagnosis // set only for Unknown
}

func (r *Refusal) Error() string {
	if r.Outcome == Unknown {
		return "vault-v1 " + string(Unknown) + " " + string(r.Diagnosis)
	}
	return "vault-v1 " + string(r.Outcome) + " " + string(r.Code)
}

func notSubmitted(c Code) *Refusal { return &Refusal{Outcome: NotSubmitted, Code: c} }
func refused(c Code) *Refusal      { return &Refusal{Outcome: Refused, Code: c} }
func unknown(d Diagnosis) *Refusal { return &Refusal{Outcome: Unknown, Diagnosis: d} }

// NotSubmittedRefusal builds a pre-submission local refusal for an integration
// layer (for example the CLI backend selection). It cannot express REFUSED or
// UNKNOWN, which only a submitted operation in this package can produce.
func NotSubmittedRefusal(c Code) *Refusal {
	if !c.Known() {
		c = EInternal
	}
	return notSubmitted(c)
}
