package vaultv1

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
	KindExplicit  = "explicit"
	KindSynthetic = "synthetic"

	// MaxExplicitName is the proposed common I1-r4 envelope. The a2a MVP is
	// narrower: explicit names must also pass config.ValidateName.
	MaxExplicitName = 512
	// MaxOriginID bounds each opaque synthetic origin component.
	MaxOriginID = 256

	syntheticDomainSeparator = "swarma.synthetic-identity/v1"
)

var (
	domainRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	syntheticRE = regexp.MustCompile(`^syn1:[0-9a-f]{64}$`)
)

// SyntheticContext is SyntheticContextV2: opaque IDs from the launching
// integration's reviewed mapping. Nothing here discovers or invents them.
type SyntheticContext struct {
	HostID, ProjectID, ProfileID string
}

// Identity is IdentityV2. Its logical key is (Domain, Kind, Name); Origin is
// retained and checked, never a fourth lookup component. Byte equality is
// exact: nothing is trimmed, case-folded or normalized.
type Identity struct {
	Domain string
	Kind   string
	Name   string
	Origin *SyntheticContext // nil for explicit, the exact triple for synthetic
}

// Equal is exact typed equality including origin bytes.
func (id Identity) Equal(o Identity) bool {
	if id.Domain != o.Domain || id.Kind != o.Kind || id.Name != o.Name || (id.Origin == nil) != (o.Origin == nil) {
		return false
	}
	return id.Origin == nil || *id.Origin == *o.Origin
}

// SyntheticPreimage is the exact agreed digest input:
// ASCII("swarma.synthetic-identity/v1") || 0x00 || LP(host) || LP(project) || LP(profile).
// It performs no validation; use SyntheticName for a validated derivation.
func SyntheticPreimage(o SyntheticContext) []byte {
	out := append([]byte(syntheticDomainSeparator), 0)
	for _, s := range []string{o.HostID, o.ProjectID, o.ProfileID} {
		out = binary.BigEndian.AppendUint32(out, uint32(len(s)))
		out = append(out, s...)
	}
	return out
}

// SyntheticName validates the origin and returns "syn1:" plus the lowercase
// SHA-256 hex digest (69 bytes). It is a pure value operation: it enrolls,
// maps or creates nothing, and the domain is deliberately not an input.
func SyntheticName(o SyntheticContext) (string, error) {
	if r := validateOrigin(o); r != nil {
		return "", r
	}
	sum := sha256.Sum256(SyntheticPreimage(o))
	return "syn1:" + hex.EncodeToString(sum[:]), nil
}

func validateOrigin(o SyntheticContext) *Refusal {
	parts := []string{o.HostID, o.ProjectID, o.ProfileID}
	for _, s := range parts { // limits win over representation
		if len(s) > MaxOriginID {
			return notSubmitted(ELimit)
		}
	}
	for _, s := range parts {
		if !publicText(s) {
			return notSubmitted(EContext)
		}
	}
	return nil
}

// publicText is nonempty valid UTF-8 without Unicode control characters.
func publicText(s string) bool {
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

// ValidateIdentity applies the r4 precedence for a locally selected identity:
// shape (E_FORMAT), byte limits (E_LIMIT), name representation (E_IDENTITY),
// domain/origin context (E_CONTEXT), then synthetic recomputation
// (E_IDENTITY_CONFLICT). The a2a MVP additionally restricts explicit names to
// the existing source selector grammar config.ValidateName.
func ValidateIdentity(id Identity) error {
	if r := validateIdentity(id); r != nil {
		return r
	}
	return nil
}

func validateIdentity(id Identity) *Refusal {
	if r := identityShapeLimits(id); r != nil {
		return r
	}
	return identityRepresentation(id)
}

// identityShapeLimits is the closed-shape (E_FORMAT) and byte-limit (E_LIMIT)
// stage; it runs before any representation check of the same selection.
func identityShapeLimits(id Identity) *Refusal {
	switch id.Kind {
	case KindExplicit:
		if id.Origin != nil {
			return notSubmitted(EFormat)
		}
		if len(id.Name) > MaxExplicitName {
			return notSubmitted(ELimit)
		}
	case KindSynthetic:
		if id.Origin != nil {
			for _, s := range []string{id.Origin.HostID, id.Origin.ProjectID, id.Origin.ProfileID} {
				if len(s) > MaxOriginID {
					return notSubmitted(ELimit)
				}
			}
		}
	default:
		return notSubmitted(EFormat)
	}
	return nil
}

// identityRepresentation is the name (E_IDENTITY), context (E_CONTEXT) and
// synthetic recomputation (E_IDENTITY_CONFLICT) stage.
func identityRepresentation(id Identity) *Refusal {
	if id.Kind == KindExplicit && (!publicText(id.Name) || config.ValidateName(id.Name) != nil) {
		return notSubmitted(EIdentity)
	}
	if id.Kind == KindSynthetic && !syntheticRE.MatchString(id.Name) {
		return notSubmitted(EIdentity)
	}
	if !domainRE.MatchString(id.Domain) {
		return notSubmitted(EContext)
	}
	if id.Kind == KindSynthetic {
		if id.Origin == nil {
			return notSubmitted(EContext)
		}
		name, err := SyntheticName(*id.Origin)
		if err != nil {
			return err.(*Refusal)
		}
		if name != id.Name {
			return notSubmitted(EIdentityConflict)
		}
	}
	return nil
}
