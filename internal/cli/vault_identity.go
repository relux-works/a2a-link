package cli

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"regexp"
	"unicode"
	"unicode/utf8"

	"github.com/relux-works/a2a-swarm/internal/config"
)

const (
	vaultKindExplicit  = "explicit"
	vaultKindSynthetic = "synthetic"

	// vaultMaxExplicitName is the proposed common I1-r4 envelope. The a2a MVP is
	// narrower: explicit names must also pass config.ValidateName.
	vaultMaxExplicitName = 512
	// vaultMaxOriginID bounds each opaque synthetic origin component.
	vaultMaxOriginID = 256

	vaultSyntheticDomainSeparator = "swarma.synthetic-identity/v1"
)

var (
	vaultDomainRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	vaultSyntheticRE = regexp.MustCompile(`^syn1:[0-9a-f]{64}$`)
)

// vaultSyntheticContext is SyntheticContextV2: opaque IDs from the launching
// integration's reviewed mapping. Nothing here discovers or invents them.
type vaultSyntheticContext struct {
	HostID, ProjectID, ProfileID string
}

// vaultIdentity is IdentityV2. Its logical key is (Domain, Kind, Name); Origin is
// retained and checked, never a fourth lookup component. Byte equality is
// exact: nothing is trimmed, case-folded or normalized.
type vaultIdentity struct {
	Domain string
	Kind   string
	Name   string
	Origin *vaultSyntheticContext // nil for explicit, the exact triple for synthetic
}

// Equal is exact typed equality including origin bytes.
func (id vaultIdentity) Equal(o vaultIdentity) bool {
	if id.Domain != o.Domain || id.Kind != o.Kind || id.Name != o.Name || (id.Origin == nil) != (o.Origin == nil) {
		return false
	}
	return id.Origin == nil || *id.Origin == *o.Origin
}

// vaultSyntheticPreimage is the exact agreed digest input:
// ASCII("swarma.synthetic-identity/v1") || 0x00 || LP(host) || LP(project) || LP(profile).
// It performs no validation; use vaultSyntheticName for a validated derivation.
func vaultSyntheticPreimage(o vaultSyntheticContext) []byte {
	out := append([]byte(vaultSyntheticDomainSeparator), 0)
	for _, s := range []string{o.HostID, o.ProjectID, o.ProfileID} {
		out = binary.BigEndian.AppendUint32(out, uint32(len(s)))
		out = append(out, s...)
	}
	return out
}

// vaultSyntheticName validates the origin and returns "syn1:" vaultPlus the lowercase
// SHA-256 hex digest (69 bytes). It is a pure value operation: it enrolls,
// maps or creates nothing, and the domain is deliberately not an input.
func vaultSyntheticName(o vaultSyntheticContext) (string, error) {
	if r := vaultValidateOrigin(o); r != nil {
		return "", r
	}
	sum := sha256.Sum256(vaultSyntheticPreimage(o))
	return "syn1:" + hex.EncodeToString(sum[:]), nil
}

func vaultValidateOrigin(o vaultSyntheticContext) *vaultFailure {
	parts := []string{o.HostID, o.ProjectID, o.ProfileID}
	for _, s := range parts { // limits win over representation
		if len(s) > vaultMaxOriginID {
			return vaultLocalFailure(vaultELimit)
		}
	}
	for _, s := range parts {
		if !vaultPublicText(s) {
			return vaultLocalFailure(vaultEContext)
		}
	}
	return nil
}

// vaultPublicText is nonempty valid UTF-8 without Unicode control characters.
func vaultPublicText(s string) bool {
	if s == "" || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// vaultValidateIdentity applies the r4 precedence for a locally selected identity:
// shape (E_FORMAT), byte limits (E_LIMIT), name representation (E_IDENTITY),
// domain/origin context (E_CONTEXT), then synthetic recomputation
// (E_IDENTITY_CONFLICT). The a2a MVP additionally restricts explicit names to
// the existing source selector grammar config.ValidateName.
func vaultValidateIdentity(id vaultIdentity) error {
	if r := vaultValidateIdentityRaw(id); r != nil {
		return r
	}
	return nil
}

func vaultValidateIdentityRaw(id vaultIdentity) *vaultFailure {
	if r := vaultIdentityShapeLimits(id); r != nil {
		return r
	}
	return vaultIdentityRepresentation(id)
}

// vaultIdentityShapeLimits is the closed-shape (E_FORMAT) and byte-limit (E_LIMIT)
// stage; it runs before any representation check of the same selection.
func vaultIdentityShapeLimits(id vaultIdentity) *vaultFailure {
	switch id.Kind {
	case vaultKindExplicit:
		if id.Origin != nil {
			return vaultLocalFailure(vaultEFormat)
		}
		if len(id.Name) > vaultMaxExplicitName {
			return vaultLocalFailure(vaultELimit)
		}
	case vaultKindSynthetic:
		if id.Origin != nil {
			for _, s := range []string{id.Origin.HostID, id.Origin.ProjectID, id.Origin.ProfileID} {
				if len(s) > vaultMaxOriginID {
					return vaultLocalFailure(vaultELimit)
				}
			}
		}
	default:
		return vaultLocalFailure(vaultEFormat)
	}
	return nil
}

// vaultIdentityRepresentation is the name (E_IDENTITY), context (E_CONTEXT) and
// synthetic recomputation (E_IDENTITY_CONFLICT) stage.
func vaultIdentityRepresentation(id vaultIdentity) *vaultFailure {
	if id.Kind == vaultKindExplicit && (!vaultPublicText(id.Name) || config.ValidateName(id.Name) != nil) {
		return vaultLocalFailure(vaultEIdentity)
	}
	if id.Kind == vaultKindSynthetic && !vaultSyntheticRE.MatchString(id.Name) {
		return vaultLocalFailure(vaultEIdentity)
	}
	if !vaultDomainRE.MatchString(id.Domain) {
		return vaultLocalFailure(vaultEContext)
	}
	if id.Kind == vaultKindSynthetic {
		if id.Origin == nil {
			return vaultLocalFailure(vaultEContext)
		}
		name, err := vaultSyntheticName(*id.Origin)
		if err != nil {
			return err.(*vaultFailure)
		}
		if name != id.Name {
			return vaultLocalFailure(vaultEIdentityConflict)
		}
	}
	return nil
}
