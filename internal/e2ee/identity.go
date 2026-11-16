package e2ee

// Bootstrap states (docs/e2ee.md section 3). A state is derived evidence, not
// authority: owner-verified is accepted only with the owner signature it names.
const (
	StateAbsent        = "absent"
	StateLocalReady    = "local-ready"
	StateAwaitingUIA   = "awaiting-uia"
	StatePublished     = "published"
	StateAwaitingOwner = "awaiting-owner"
	StateOwnerVerified = "owner-verified"
	StateChanged       = "changed"
	StateUnavailable   = "unavailable"
)

var identityStates = map[string]bool{
	StateLocalReady: true, StateAwaitingUIA: true, StatePublished: true,
	StateAwaitingOwner: true, StateOwnerVerified: true, StateChanged: true, StateUnavailable: true,
}

// IdentityEvidence is the sealed public record of this identity's cross-signing
// bootstrap: the exact persisted public material, the accepted pin revision and
// digest, and the owner's USK signature over the agent master once verified.
// It contains no private key; it lives inside the sealed snapshot so a changed
// record cannot be planted without the per-generation wrapping key.
type IdentityEvidence struct {
	Version               int    `json:"v"`
	State                 string `json:"state"`
	MasterKeyID           string `json:"master_key_id"`
	MasterPublicKey       string `json:"master_public_key"`
	SelfSigningKeyID      string `json:"self_signing_key_id"`
	SelfSigningPublicKey  string `json:"self_signing_public_key"`
	UserSigningKeyID      string `json:"user_signing_key_id"`
	UserSigningPublicKey  string `json:"user_signing_public_key"`
	DeviceEd25519         string `json:"device_ed25519"`
	DeviceCurve25519      string `json:"device_curve25519"`
	PinRevision           uint64 `json:"pin_revision"`
	PinDigest             string `json:"pin_digest"`
	Owner                 string `json:"owner"`
	OwnerUserSigningKeyID string `json:"owner_user_signing_key_id,omitempty"`
	OwnerSignature        string `json:"owner_signature,omitempty"`
	ObservedMS            int64  `json:"observed_ms"`
}

// NewIdentityEvidence records freshly derived public material in local-ready
// against the pin it was bootstrapped under.
func NewIdentityEvidence(keys *CrossSigning, device DeviceKeys, pin HostPin, nowMS int64) (IdentityEvidence, error) {
	if keys == nil {
		return IdentityEvidence{}, ErrInvalid
	}
	m, s, u := keys.Master(), keys.SelfSigning(), keys.UserSigning()
	e := IdentityEvidence{
		Version: 1, State: StateLocalReady,
		MasterKeyID: m.ID, MasterPublicKey: m.Public,
		SelfSigningKeyID: s.ID, SelfSigningPublicKey: s.Public,
		UserSigningKeyID: u.ID, UserSigningPublicKey: u.Public,
		DeviceEd25519:    device.Keys["ed25519:"+device.DeviceID],
		DeviceCurve25519: device.Keys["curve25519:"+device.DeviceID],
		PinRevision:      pin.Revision, PinDigest: pin.Digest, Owner: pin.Owner,
		ObservedMS: nowMS,
	}
	if err := e.validate(); err != nil {
		return IdentityEvidence{}, err
	}
	return e, nil
}

func (e IdentityEvidence) validate() error {
	if e.Version != 1 || !identityStates[e.State] || e.ObservedMS < 0 {
		return ErrCodec
	}
	for _, key := range []struct{ id, public string }{
		{e.MasterKeyID, e.MasterPublicKey}, {e.SelfSigningKeyID, e.SelfSigningPublicKey}, {e.UserSigningKeyID, e.UserSigningPublicKey},
	} {
		if _, err := publicBase64(key.public, 32); err != nil || key.id != "ed25519:"+key.public {
			return ErrCodec
		}
	}
	if e.MasterPublicKey == e.SelfSigningPublicKey || e.MasterPublicKey == e.UserSigningPublicKey || e.SelfSigningPublicKey == e.UserSigningPublicKey {
		return ErrCodec
	}
	for _, public := range []string{e.DeviceEd25519, e.DeviceCurve25519} {
		if _, err := publicBase64(public, 32); err != nil {
			return ErrCodec
		}
	}
	if e.PinRevision == 0 || !hexSize(e.PinDigest, 32) || !fullMXID(e.Owner) {
		return ErrCodec
	}
	verified := e.State == StateOwnerVerified
	if verified {
		// A state label alone is never trust: the signature it names must be
		// present and well formed, and is re-verified against the pin on use.
		if _, err := publicBase64(e.OwnerSignature, 64); err != nil {
			return ErrIntegrity
		}
		if len(e.OwnerUserSigningKeyID) != len("ed25519:")+43 || e.OwnerUserSigningKeyID[:8] != "ed25519:" {
			return ErrIntegrity
		}
		if _, err := publicBase64(e.OwnerUserSigningKeyID[8:], 32); err != nil {
			return ErrIntegrity
		}
	} else if e.OwnerSignature != "" || e.OwnerUserSigningKeyID != "" {
		return ErrCodec
	}
	return nil
}

// MatchesKeys reports whether the derived keys and device are exactly the
// persisted public material. A mismatch is never repaired: it refuses.
func (e IdentityEvidence) MatchesKeys(keys *CrossSigning, device DeviceKeys) error {
	if keys == nil {
		return ErrInvalid
	}
	m, s, u := keys.Master(), keys.SelfSigning(), keys.UserSigning()
	if e.MasterKeyID != m.ID || e.MasterPublicKey != m.Public || e.SelfSigningKeyID != s.ID || e.SelfSigningPublicKey != s.Public || e.UserSigningKeyID != u.ID || e.UserSigningPublicKey != u.Public {
		return ErrIntegrity
	}
	if e.DeviceEd25519 != device.Keys["ed25519:"+device.DeviceID] || e.DeviceCurve25519 != device.Keys["curve25519:"+device.DeviceID] {
		return ErrIntegrity
	}
	return nil
}

// ComparePin applies the section 3 rule before each trusted operation: only the
// exact accepted revision with the exact accepted bytes is unchanged. The same
// revision with other bytes, a lower revision and a higher revision all enter
// changed here; revision + 1 adoption is U2b's host-authorized transition.
func (e IdentityEvidence) ComparePin(pin HostPin) error {
	if e.PinRevision == pin.Revision && e.PinDigest == pin.Digest && e.Owner == pin.Owner {
		return nil
	}
	return ErrTrustChanged
}

// MasterKeyObject is the agent's own unsigned master-key object as persisted.
func (e IdentityEvidence) MasterKeyObject(mxid string) (SignedKey, error) {
	return keyObject(mxid, UsageMaster, PublicKey{ID: e.MasterKeyID, Public: e.MasterPublicKey})
}

// PublicIdentity is the public evidence printed by the CLI and consumed by the
// later grant key-binding node. It never includes private material.
type PublicIdentity struct {
	Type        string    `json:"type"`
	MXID        string    `json:"mxid"`
	DeviceID    string    `json:"device_id"`
	State       string    `json:"state"`
	PinRevision uint64    `json:"pin_revision"`
	Owner       string    `json:"owner,omitempty"`
	Master      PublicKey `json:"master"`
	SelfSigning PublicKey `json:"self_signing"`
	UserSigning PublicKey `json:"user_signing"`
}

func (e IdentityEvidence) Public(mxid, device, state string) (PublicIdentity, error) {
	m, err := publicKeyOf(e.MasterPublicKey)
	if err != nil {
		return PublicIdentity{}, err
	}
	s, err := publicKeyOf(e.SelfSigningPublicKey)
	if err != nil {
		return PublicIdentity{}, err
	}
	u, err := publicKeyOf(e.UserSigningPublicKey)
	if err != nil {
		return PublicIdentity{}, err
	}
	if state == "" {
		state = e.State
	}
	return PublicIdentity{Type: "e2ee_identity", MXID: mxid, DeviceID: device, State: state, PinRevision: e.PinRevision, Owner: e.Owner, Master: m, SelfSigning: s, UserSigning: u}, nil
}
