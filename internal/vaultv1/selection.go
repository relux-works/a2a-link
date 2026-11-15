package vaultv1

import (
	"github.com/relux-works/a2a-swarm/internal/config"
)

const (
	SessionRegistered = "registered"
	SessionDirect     = "direct"
)

// Selection is the latched local input of one credential operation: the
// validated identity, the explicit session mode, the derived B1 binding and
// the selected ConnectionBinding fingerprint. It has no exported fields; the
// zero value is not latched and every operation refuses it before any call.
type Selection struct {
	latched     bool
	identity    Identity
	mode        string
	binding     ConsumerBinding
	fingerprint string
}

// Latch validates the per-agent vault_selection against the explicitly
// selected a2a name and its named connection binding. It is pure: no vault,
// secret-store, filesystem or network call. There is no default session mode,
// no generated identity and no mapping inferred from the name.
func Latch(sel config.VaultSelection, selector string, b config.ConnectionBinding) (Selection, error) {
	if b.Connection.Store.Backend != config.BackendVaultV1 || b.Class != "agents" {
		return Selection{}, notSubmitted(EBackendConfig)
	}
	id := Identity{Domain: sel.Identity.Domain, Kind: sel.Identity.Kind, Name: sel.Identity.Name}
	if o := sel.Identity.Origin; o != nil {
		id.Origin = &SyntheticContext{HostID: o.HostID, ProjectID: o.ProjectID, ProfileID: o.ProfileID}
	}
	binding, r := deriveBinding(selector, b)
	if r != nil {
		return Selection{}, r
	}
	// Local precedence: closed shape, then every byte limit, then identity
	// representation/context, then binding version/format/source predicates.
	if sel.SessionMode != SessionRegistered && sel.SessionMode != SessionDirect {
		return Selection{}, notSubmitted(EFormat)
	}
	for _, check := range []func() *Refusal{
		func() *Refusal { return identityShapeLimits(id) },
		func() *Refusal { return bindingLimits(binding) },
		func() *Refusal { return identityRepresentation(id) },
		func() *Refusal { return bindingSemantics(binding) },
	} {
		if r := check(); r != nil {
			return Selection{}, r
		}
	}
	return Selection{latched: true, identity: id, mode: sel.SessionMode, binding: binding, fingerprint: b.Fingerprint()}, nil
}

func (s Selection) Latched() bool            { return s.latched }
func (s Selection) Identity() Identity       { return s.identity.clone() }
func (s Selection) SessionMode() string      { return s.mode }
func (s Selection) Binding() ConsumerBinding { return s.binding }

// Fingerprint is the selected ConnectionBinding fingerprint. It is local
// evidence only; it is not part of the native wire.
func (s Selection) Fingerprint() string { return s.fingerprint }

// Equal compares two latched selections exactly. A changed selection needs a
// fresh qualified selection/registration, never live retargeting.
func (s Selection) Equal(o Selection) bool {
	return s.latched && o.latched && s.identity.Equal(o.identity) && s.mode == o.mode && s.binding == o.binding && s.fingerprint == o.fingerprint
}

func (id Identity) clone() Identity {
	if id.Origin != nil {
		o := *id.Origin
		id.Origin = &o
	}
	return id
}
