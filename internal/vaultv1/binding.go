package vaultv1

import (
	"github.com/relux-works/a2a-swarm/internal/config"
)

const (
	BindingKind    = "a2a-matrix"
	BindingPurpose = "matrix-access-token"

	// New native envelope bounds (B1). Source predicates stay stricter where
	// they are: a source-valid user_id is at most 321 bytes, server 255 bytes.
	MaxSelector      = 64
	MaxUserID        = 4096
	MaxHomeserverURL = 8192
	MaxServerName    = 4096
)

// ConsumerBinding is ConsumerBindingV1, the only admitted consumer binding.
type ConsumerBinding struct {
	BindingV      uint64
	Kind          string
	Purpose       string
	A2ASelector   string
	UserID        string
	HomeserverURL string
	ServerName    string
}

// DeriveBinding derives B1 once from the explicitly selected named connection
// binding (agents class only). It performs no normalization, discovery or
// account inference; the result is validated before it is returned.
func DeriveBinding(selector string, b config.ConnectionBinding) (ConsumerBinding, error) {
	out, r := deriveBinding(selector, b)
	if r == nil {
		r = validateBinding(out)
	}
	if r != nil {
		return ConsumerBinding{}, r
	}
	return out, nil
}

func deriveBinding(selector string, b config.ConnectionBinding) (ConsumerBinding, *Refusal) {
	if b.Class != "agents" {
		return ConsumerBinding{}, notSubmitted(EBackendConfig)
	}
	return ConsumerBinding{
		BindingV: 1, Kind: BindingKind, Purpose: BindingPurpose,
		A2ASelector: selector, UserID: b.UserID,
		HomeserverURL: b.Connection.URL, ServerName: b.Connection.ServerName,
	}, nil
}

// ValidateBinding applies B1 precedence: native byte limits (E_LIMIT), then
// typed version (E_VERSION), then fixed kind/purpose, representation and the
// pinned source predicates (E_FORMAT). Only a binding that passes can reach
// an equality comparison.
func ValidateBinding(b ConsumerBinding) error {
	if r := validateBinding(b); r != nil {
		return r
	}
	return nil
}

func validateBinding(b ConsumerBinding) *Refusal {
	if r := bindingLimits(b); r != nil {
		return r
	}
	return bindingSemantics(b)
}

func bindingLimits(b ConsumerBinding) *Refusal {
	if len(b.A2ASelector) > MaxSelector || len(b.UserID) > MaxUserID || len(b.HomeserverURL) > MaxHomeserverURL || len(b.ServerName) > MaxServerName {
		return notSubmitted(ELimit)
	}
	return nil
}

func bindingSemantics(b ConsumerBinding) *Refusal {
	if b.BindingV != 1 {
		return notSubmitted(EVersion)
	}
	if b.Kind != BindingKind || b.Purpose != BindingPurpose {
		return notSubmitted(EFormat)
	}
	for _, s := range []string{b.A2ASelector, b.UserID, b.HomeserverURL, b.ServerName} {
		if !publicText(s) {
			return notSubmitted(EFormat)
		}
	}
	if config.ValidateName(b.A2ASelector) != nil || config.ValidateMatrixRouting(b.HomeserverURL, b.ServerName) != nil || b.UserID != "@"+b.A2ASelector+":"+b.ServerName {
		return notSubmitted(EFormat)
	}
	return nil
}
