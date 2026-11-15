package cli

import (
	"context"

	"github.com/relux-works/a2a-swarm/internal/config"
	"github.com/relux-works/a2a-swarm/internal/vaultv1"
)

// vaultRefusal is a pre-submission vault-v1 refusal with a closed r4 code.
func vaultRefusal(c vaultv1.Code) error { return vaultv1.NotSubmittedRefusal(c) }

// latchVaultSelection validates the strictly decoded per-agent vault_selection
// against the explicitly selected name and named connection. It is pure:
// metadata-only sessions call it too, so it must never reach a dependency.
func (a *App) latchVaultSelection(c *config.Connection, name string, creds config.Credentials) (vaultv1.Selection, error) {
	if a.human {
		return vaultv1.Selection{}, vaultRefusal(vaultv1.EBackendConfig)
	}
	if creds.VaultSelection == nil {
		return vaultv1.Selection{}, vaultRefusal(vaultv1.EBackendConfig)
	}
	b, e := c.Binding(name, false)
	if e != nil {
		return vaultv1.Selection{}, e
	}
	return vaultv1.Latch(*creds.VaultSelection, name, b)
}

// releaseVaultToken is the only vault-v1 credential path. The dependency
// factory is consulted only here, after local selection, metadata and binding
// validation have latched. Production has no qualified native driver, so the
// factory is nil and the result is NOT_SUBMITTED E_UNAVAILABLE with no vault,
// network, IPC or legacy secret-store call. Every failure returns without
// consulting another backend or identity.
func (a *App) releaseVaultToken(ctx context.Context, sel vaultv1.Selection) (string, error) {
	if a.vaultDependency == nil {
		return "", vaultRefusal(vaultv1.EUnavailable)
	}
	client, e := vaultv1.NewClient(a.vaultDependency())
	if e != nil {
		return "", e
	}
	var token string
	if _, e = client.Release(ctx, sel, func(secret []byte) { token = string(secret) }); e != nil {
		return "", e
	}
	return token, nil
}

// sameVaultSelection is exact equality of two decoded selections, including
// absence and origin bytes.
func sameVaultSelection(a, b *config.VaultSelection) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.SessionMode != b.SessionMode || a.Identity.Domain != b.Identity.Domain || a.Identity.Kind != b.Identity.Kind || a.Identity.Name != b.Identity.Name || (a.Identity.Origin == nil) != (b.Identity.Origin == nil) {
		return false
	}
	return a.Identity.Origin == nil || *a.Identity.Origin == *b.Identity.Origin
}
