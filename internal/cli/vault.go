package cli

import (
	"context"
	"errors"

	"github.com/relux-works/a2a-swarm/internal/config"
)

func vaultRefusal(c vaultCode) error { return vaultLocalFailure(c) }
func (a *App) observeVaultSelection(c *config.Connection, name string, creds config.Credentials) (vaultObservedSelection, error) {
	if a.human {
		return vaultObservedSelection{}, vaultRefusal(vaultEBackendConfig)
	}
	if !creds.VaultSelection.Present() {
		return vaultObservedSelection{}, vaultRefusal(vaultEBackendConfig)
	}
	sel, e := creds.VaultSelection.Selection()
	if e != nil {
		return vaultObservedSelection{}, vaultRefusal(vaultEFormat)
	}
	b, e := c.Binding(name, false)
	if e != nil {
		return vaultObservedSelection{}, e
	}
	o, r := vaultObserve(sel, name, b)
	if r != nil {
		return o, r
	}
	return o, nil
}
func (a *App) releaseVaultToken(ctx context.Context, observed vaultObservedSelection) (token string, report vaultAttemptReport) {
	report.Handoff = vaultHandoffNotEntered
	report.Cleanup = vaultCleanupNotNeeded
	defer func() {
		if recover() != nil {
			token = ""
			if report.Release != nil && report.Release.Outcome == vaultSucceeded {
				report.DeliveryDiagnosis = vaultDeliveryFailed
			} else {
				report.Failure = vaultLocalFailure(vaultEInternal)
			}
		}
	}()
	if vaultIsNil(a.vaultContext) {
		report.Failure = vaultLocalFailure(vaultEContext)
		report.Failure.Stage = vaultStageAdmission
		return
	}
	current, err := a.vaultContext.Current(ctx)
	if err != nil {
		report.Failure = vaultLocalFailure(vaultEContext)
		report.Failure.Stage = vaultStageAdmission
		return
	}
	admitted, r := vaultAdmit(observed, current)
	if r != nil {
		r.Stage = vaultStageAdmission
		report.Failure = r
		return
	}
	guard := vaultSelectionGuardFunc(func(ctx context.Context, latched vaultCredentialSelection) *vaultFailure {
		name, e := a.identity()
		if e != nil {
			return vaultLocalFailure(vaultEIdentityConflict)
		}
		// A new resolver sees changes to the named profile rather than trusting the
		// invocation's cached connection. Metadata is public; no token lookup occurs.
		check := &App{Getenv: a.Getenv, lookupEnv: a.lookupEnv, profile: a.profile, human: a.human, connectionSecretStore: a.connectionSecretStore, keychain: a.keychain}
		c, e := check.selectedConnection()
		if e != nil || c == nil {
			return vaultLocalFailure(vaultEIdentityConflict)
		}
		p, e := check.pathsFor(name)
		if e != nil {
			return vaultLocalFailure(vaultEIdentityConflict)
		}
		creds, e := check.namedMetadata(p, name)
		if e != nil {
			return vaultLocalFailure(vaultEIdentityConflict)
		}
		now, e := check.observeVaultSelection(c, name, creds)
		if e != nil || !now.Equal(latched.observed) {
			return vaultLocalFailure(vaultEIdentityConflict)
		}
		cc, e := a.vaultContext.Current(ctx)
		if e != nil {
			return vaultLocalFailure(vaultEContext)
		}
		again, r := vaultAdmit(now, cc)
		if r != nil {
			return r
		}
		if again.issuer != latched.issuer {
			return vaultLocalFailure(vaultEContext)
		}
		return nil
	})
	if r := vaultGuardCheck(ctx, guard, admitted); r != nil {
		report.Failure = r
		report.Failure.Stage = vaultStageAdmission
		return
	}
	if a.vaultDependency == nil {
		report.Failure = vaultLocalFailure(vaultEUnavailable)
		report.Failure.Stage = vaultStageDependency
		return
	}
	dep, e := a.vaultDependency(admitted)
	if e != nil {
		report.Failure = vaultLocalFailure(vaultEUnavailable)
		report.Failure.Stage = vaultStageDependency
		return
	}
	client, r := vaultNewClient(admitted, dep)
	if r != nil {
		report.Failure = r
		report.Failure.Stage = vaultStageDependency
		return
	}
	report = client.Release(ctx, guard, func(secret []byte) error { token = string(secret); a.secrets.Add(token); return nil })
	if !report.acquisitionOK() {
		token = ""
	}
	return
}
func sameVaultSelection(a, b config.VaultSelectionField) bool {
	if a.Present() != b.Present() {
		return false
	}
	if !a.Present() {
		return true
	}
	av, ae := a.Selection()
	bv, be := b.Selection()
	if ae != nil || be != nil {
		return false
	}
	if av.SessionMode != bv.SessionMode || av.Identity.Domain != bv.Identity.Domain || av.Identity.Kind != bv.Identity.Kind || av.Identity.Name != bv.Identity.Name || (av.Identity.Origin == nil) != (bv.Identity.Origin == nil) {
		return false
	}
	return av.Identity.Origin == nil || *av.Identity.Origin == *bv.Identity.Origin
}
func vaultMetadataError(e error) error {
	if errors.Is(e, config.ErrVaultSelectionShape) {
		return vaultRefusal(vaultEFormat)
	}
	return e
}
