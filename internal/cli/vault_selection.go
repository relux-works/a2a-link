package cli

import (
	"context"

	"github.com/relux-works/a2a-swarm/internal/config"
)

const vaultSessionRegistered = "registered"
const vaultSessionDirect = "direct"

// vaultObservedSelection owns public data only. Observation grants no authority.
type vaultObservedSelection struct {
	latched     bool
	identity    vaultIdentity
	mode        string
	binding     vaultConsumerBinding
	local       config.ConnectionBinding
	fingerprint string
}

func vaultObserve(sel config.VaultSelection, selector string, b config.ConnectionBinding) (vaultObservedSelection, *vaultFailure) {
	if b.Connection.Store.Backend != config.BackendVaultV1 || b.Class != "agents" || b.Connection.Store.AccessTokenService != "" || b.Connection.Store.PasswordService != "" || b.Connection.RegistrationTokenRef != nil || b.Connection.AdminRegistration != nil {
		return vaultObservedSelection{}, vaultLocalFailure(vaultEBackendConfig)
	}
	id := vaultIdentity{Domain: sel.Identity.Domain, Kind: sel.Identity.Kind, Name: sel.Identity.Name}
	if o := sel.Identity.Origin; o != nil {
		id.Origin = &vaultSyntheticContext{HostID: o.HostID, ProjectID: o.ProjectID, ProfileID: o.ProfileID}
	}
	binding, r := vaultDeriveBindingRaw(selector, b)
	if r != nil {
		return vaultObservedSelection{}, r
	}
	if sel.SessionMode != vaultSessionRegistered && sel.SessionMode != vaultSessionDirect {
		return vaultObservedSelection{}, vaultLocalFailure(vaultEFormat)
	}
	for _, check := range []func() *vaultFailure{
		func() *vaultFailure { return vaultIdentityShapeLimits(id) },
		func() *vaultFailure { return vaultBindingLimits(binding) },
		func() *vaultFailure { return vaultIdentityRepresentation(id) },
		func() *vaultFailure { return vaultBindingSemantics(binding) },
	} {
		if r := check(); r != nil {
			return vaultObservedSelection{}, r
		}
	}
	return vaultObservedSelection{true, id, sel.SessionMode, binding, vaultCloneLocalBinding(b), b.Fingerprint()}, nil
}
func (s vaultObservedSelection) Latched() bool                 { return s.latched }
func (s vaultObservedSelection) Identity() vaultIdentity       { return s.identity.clone() }
func (s vaultObservedSelection) SessionMode() string           { return s.mode }
func (s vaultObservedSelection) Binding() vaultConsumerBinding { return s.binding }
func (s vaultObservedSelection) Fingerprint() string           { return s.fingerprint }
func (s vaultObservedSelection) Equal(o vaultObservedSelection) bool {
	return s.latched && o.latched && s.identity.Equal(o.identity) && s.mode == o.mode && s.binding == o.binding && s.fingerprint == o.fingerprint
}
func (s vaultObservedSelection) clone() vaultObservedSelection {
	s.identity = s.identity.clone()
	s.local = vaultCloneLocalBinding(s.local)
	return s
}
func (id vaultIdentity) clone() vaultIdentity {
	if id.Origin != nil {
		o := *id.Origin
		id.Origin = &o
	}
	return id
}

// No production issuer exists. Only same-package _test.go fixtures currently
// instantiate these authority witnesses. They are not serializable trust flags.
type vaultContextIssuer struct{ marker byte }
type vaultAdmittedContext struct {
	issuer         *vaultContextIssuer
	declared       vaultIdentity
	installDomain  string
	mappedIdentity vaultIdentity
	binding        vaultConsumerBinding
	local          config.ConnectionBinding
}
type vaultContextProvider interface {
	Current(context.Context) (vaultAdmittedContext, error)
}
type vaultCredentialSelection struct {
	observed vaultObservedSelection
	issuer   *vaultContextIssuer
}

func (s vaultCredentialSelection) Public() vaultObservedSelection { return s.observed.clone() }
func vaultAdmit(o vaultObservedSelection, c vaultAdmittedContext) (vaultCredentialSelection, *vaultFailure) {
	if !o.latched || c.issuer == nil {
		return vaultCredentialSelection{}, vaultLocalFailure(vaultEContext)
	}
	if c.installDomain == "" || c.declared.Name == "" || c.mappedIdentity.Name == "" {
		return vaultCredentialSelection{}, vaultLocalFailure(vaultEContext)
	}
	for _, id := range []vaultIdentity{c.declared, c.mappedIdentity} {
		if r := vaultValidateIdentityRaw(id); r != nil {
			return vaultCredentialSelection{}, r
		}
	}
	if !vaultDomainRE.MatchString(c.installDomain) {
		return vaultCredentialSelection{}, vaultLocalFailure(vaultEContext)
	}
	if r := vaultValidateBindingRaw(c.binding); r != nil {
		return vaultCredentialSelection{}, r
	}
	if !o.identity.Equal(c.declared) || !o.identity.Equal(c.mappedIdentity) || o.identity.Domain != c.installDomain || o.binding != c.binding || o.fingerprint != c.local.Fingerprint() {
		return vaultCredentialSelection{}, vaultLocalFailure(vaultEIdentityConflict)
	}
	return vaultCredentialSelection{o.clone(), c.issuer}, nil
}

type vaultSelectionGuard interface {
	Check(context.Context, vaultCredentialSelection) *vaultFailure
}
type vaultSelectionGuardFunc func(context.Context, vaultCredentialSelection) *vaultFailure

func (f vaultSelectionGuardFunc) Check(ctx context.Context, s vaultCredentialSelection) *vaultFailure {
	return f(ctx, s)
}

func vaultCloneLocalBinding(b config.ConnectionBinding) config.ConnectionBinding {
	if b.Connection.RegistrationTokenRef != nil {
		r := *b.Connection.RegistrationTokenRef
		b.Connection.RegistrationTokenRef = &r
	}
	if b.Connection.AdminRegistration != nil {
		r := *b.Connection.AdminRegistration
		r.ExpectedMembers = append([]string(nil), r.ExpectedMembers...)
		b.Connection.AdminRegistration = &r
	}
	return b
}
