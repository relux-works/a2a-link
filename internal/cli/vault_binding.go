package cli

import (
	"github.com/relux-works/a2a-swarm/internal/config"
)

const (
	vaultBindingKind    = "a2a-matrix"
	vaultBindingPurpose = "matrix-access-token"

	// New native envelope bounds (B1). Source predicates stay stricter where
	// they are: a source-valid user_id is at most 321 bytes, server 255 bytes.
	vaultMaxSelector      = 64
	vaultMaxUserID        = 4096
	vaultMaxHomeserverURL = 8192
	vaultMaxServerName    = 4096
)

// vaultConsumerBinding is ConsumerBindingV1, the only admitted consumer binding.
type vaultConsumerBinding struct {
	BindingV      uint64
	Kind          string
	Purpose       string
	A2ASelector   string
	UserID        string
	HomeserverURL string
	ServerName    string
}

// vaultDeriveBinding derives B1 once from the explicitly selected named connection
// binding (agents class only). It performs no normalization, discovery or
// account inference; the result is validated before it is returned.
func vaultDeriveBinding(selector string, b config.ConnectionBinding) (vaultConsumerBinding, error) {
	out, r := vaultDeriveBindingRaw(selector, b)
	if r == nil {
		r = vaultValidateBindingRaw(out)
	}
	if r != nil {
		return vaultConsumerBinding{}, r
	}
	return out, nil
}

func vaultDeriveBindingRaw(selector string, b config.ConnectionBinding) (vaultConsumerBinding, *vaultFailure) {
	if b.Class != "agents" {
		return vaultConsumerBinding{}, vaultLocalFailure(vaultEBackendConfig)
	}
	return vaultConsumerBinding{
		BindingV: 1, Kind: vaultBindingKind, Purpose: vaultBindingPurpose,
		A2ASelector: selector, UserID: b.UserID,
		HomeserverURL: b.Connection.URL, ServerName: b.Connection.ServerName,
	}, nil
}

// vaultValidateBinding applies B1 precedence: native byte limits (E_LIMIT), then
// typed version (E_VERSION), then fixed kind/purpose, representation and the
// pinned source predicates (E_FORMAT). Only a binding that passes can reach
// an equality comparison.
func vaultValidateBinding(b vaultConsumerBinding) error {
	if r := vaultValidateBindingRaw(b); r != nil {
		return r
	}
	return nil
}

func vaultValidateBindingRaw(b vaultConsumerBinding) *vaultFailure {
	if r := vaultBindingLimits(b); r != nil {
		return r
	}
	return vaultBindingSemantics(b)
}

func vaultBindingLimits(b vaultConsumerBinding) *vaultFailure {
	if len(b.A2ASelector) > vaultMaxSelector || len(b.UserID) > vaultMaxUserID || len(b.HomeserverURL) > vaultMaxHomeserverURL || len(b.ServerName) > vaultMaxServerName {
		return vaultLocalFailure(vaultELimit)
	}
	return nil
}

func vaultBindingSemantics(b vaultConsumerBinding) *vaultFailure {
	if b.BindingV != 1 {
		return vaultLocalFailure(vaultEVersion)
	}
	if b.Kind != vaultBindingKind || b.Purpose != vaultBindingPurpose {
		return vaultLocalFailure(vaultEFormat)
	}
	for _, s := range []string{b.A2ASelector, b.UserID, b.HomeserverURL, b.ServerName} {
		if !vaultPublicText(s) {
			return vaultLocalFailure(vaultEFormat)
		}
	}
	if config.ValidateName(b.A2ASelector) != nil || config.ValidateMatrixRouting(b.HomeserverURL, b.ServerName) != nil || b.UserID != "@"+b.A2ASelector+":"+b.ServerName {
		return vaultLocalFailure(vaultEFormat)
	}
	return nil
}
