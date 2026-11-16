package originproducer

import (
	"errors"

	"github.com/relux-works/a2a-swarm/internal/cg1"
	"github.com/relux-works/a2a-swarm/runorigin"
)

// Reason is a closed vocabulary. It never contains a path, an identity, a
// registration value, a key or any text taken from an input.
type Reason string

const (
	// The protected mapping file is absent, unprotected or malformed.
	ReasonMappingInvalid Reason = "mapping_invalid"
	// The protected mapping is pinned to another launcher UID or generation.
	ReasonMappingLauncher Reason = "mapping_launcher"
	// The protected mapping has no entry for the input principal.
	ReasonMappingMissing Reason = "mapping_missing"
	// The mapping names a contract profile this build does not implement, or
	// the protected terms are not valid under the named profile.
	ReasonProfile Reason = "profile_unsupported"
	// The retained event is not in the agent's own store.
	ReasonEventAbsent Reason = "event_absent"
	// A private state scope or an owned checker could not be created.
	ReasonScope              Reason = "scope_unavailable"
	ReasonPolicyInvalid      Reason = "policy_invalid"
	ReasonInnerInvalid       Reason = "inner_request_invalid"
	ReasonInnerRecipient     Reason = "inner_request_recipient"
	ReasonGrantAbsent        Reason = "grant_absent"
	ReasonGrantExpired       Reason = "grant_expired"
	ReasonSealSpent          Reason = "seal_spent"
	ReasonLandlordChanged    Reason = "landlord_changed"
	ReasonGrantRefused       Reason = "grant_refused"
	ReasonTermsInvalid       Reason = "terms_invalid"
	ReasonBindingMismatch    Reason = "binding_mismatch"
	ReasonTipStale           Reason = "tip_stale"
	ReasonTipMoved           Reason = "tip_moved"
	ReasonUnavailable        Reason = "unavailable"
	ReasonCancelled          Reason = "cancelled"
	ReasonClosed             Reason = "closed"
	ReasonChanged            Reason = "changed_since_prepare"
	ReasonSessionState       Reason = "session_state"
	ReasonAlreadyConstructed Reason = "already_constructed"
)

// Refusal is the only error type this package returns. It unwraps to
// runorigin.ErrUnavailable for a retryable dependency state and to
// runorigin.ErrRefused otherwise, so the endpoint emits only named codes.
type Refusal struct {
	Reason    Reason
	retryable bool
}

func (r *Refusal) Error() string { return "origin producer: " + string(r.Reason) }
func (r *Refusal) Unwrap() error {
	if r.retryable {
		return runorigin.ErrUnavailable
	}
	return runorigin.ErrRefused
}

func refuse(reason Reason) error      { return &Refusal{Reason: reason} }
func unavailable(reason Reason) error { return &Refusal{Reason: reason, retryable: true} }

// ReasonOf returns the typed reason of an error from this package, or "".
func ReasonOf(err error) Reason {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Reason
	}
	return ""
}

// refusalFor maps a non-Live checker outcome to its typed refusal. An unknown
// outcome refuses; nothing here can turn an outcome into permission.
func refusalFor(code cg1.OriginCode) error {
	switch code {
	case cg1.OriginTermsInvalid:
		return refuse(ReasonTermsInvalid)
	case cg1.OriginBindingMismatch:
		return refuse(ReasonBindingMismatch)
	case cg1.OriginPolicyInvalid:
		return refuse(ReasonPolicyInvalid)
	case cg1.OriginInnerInvalid:
		return refuse(ReasonInnerInvalid)
	case cg1.OriginRecipientMismatch:
		return refuse(ReasonInnerRecipient)
	case cg1.OriginGrantAbsent:
		return refuse(ReasonGrantAbsent)
	case cg1.OriginGrantExpired:
		return refuse(ReasonGrantExpired)
	case cg1.OriginSealSpent:
		return refuse(ReasonSealSpent)
	case cg1.OriginLandlordChanged:
		return refuse(ReasonLandlordChanged)
	case cg1.OriginTipStale:
		return unavailable(ReasonTipStale)
	case cg1.OriginTipMoved:
		return unavailable(ReasonTipMoved)
	case cg1.OriginUnavailable:
		return unavailable(ReasonUnavailable)
	case cg1.OriginClosed:
		return refuse(ReasonClosed)
	}
	return refuse(ReasonGrantRefused)
}
