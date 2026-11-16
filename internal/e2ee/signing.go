package e2ee

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"maunium.net/go/mautrix/crypto/canonicaljson"
	"maunium.net/go/mautrix/crypto/goolm/account"
	goolmcrypto "maunium.net/go/mautrix/crypto/goolm/crypto"
	"maunium.net/go/mautrix/crypto/goolm/pk"
)

// Standard cross-signing usages (Matrix client-server API, cross-signing).
const (
	UsageMaster      = "master"
	UsageSelfSigning = "self_signing"
	UsageUserSigning = "user_signing"
)

// deviceAlgorithms is the fixed algorithm list this adapter publishes with its
// device keys. U3 owns actual Olm/Megolm traffic; the list is public metadata.
var deviceAlgorithms = []string{"m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"}

// SignedKey is the standard cross-signing key object: user_id, usage, keys and
// signatures (user -> key ID -> unpadded standard base64 Ed25519 signature).
type SignedKey struct {
	UserID     string                       `json:"user_id"`
	Usage      []string                     `json:"usage"`
	Keys       map[string]string            `json:"keys"`
	Signatures map[string]map[string]string `json:"signatures,omitempty"`
}

// DeviceKeys is the standard device-key object published through /keys/upload.
type DeviceKeys struct {
	UserID     string                       `json:"user_id"`
	DeviceID   string                       `json:"device_id"`
	Algorithms []string                     `json:"algorithms"`
	Keys       map[string]string            `json:"keys"`
	Signatures map[string]map[string]string `json:"signatures,omitempty"`
}

// PublicKey is the public evidence for one Ed25519 key: its Matrix key ID,
// the unpadded standard base64 public key and the SHA256 hex of its 32 bytes.
type PublicKey struct {
	ID     string `json:"key_id"`
	Public string `json:"public_key"`
	SHA256 string `json:"sha256"`
}

// Fingerprint is the SHA256 hex digest of the decoded 32-byte public key, the
// same digest the host pin records for the owner's keys.
func Fingerprint(public string) (string, error) {
	decoded, err := publicBase64(public, 32)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(decoded)
	return hex.EncodeToString(sum[:]), nil
}

func publicKeyOf(public string) (PublicKey, error) {
	fingerprint, err := Fingerprint(public)
	if err != nil {
		return PublicKey{}, err
	}
	return PublicKey{ID: "ed25519:" + public, Public: public, SHA256: fingerprint}, nil
}

// signingInput is the canonical JSON of obj without its signatures and
// unsigned members: exactly the bytes a Matrix signature covers, and the same
// pipeline goolm's pk.Signing.SignJSON applies (marshal, drop "unsigned" and
// "signatures", canonicalize). It is the one helper behind signing, the account
// adapter and verification, so the paths cannot drift apart.
func signingInput(obj any) ([]byte, error) {
	raw, err := json.Marshal(obj)
	if err != nil {
		return nil, ErrCodec
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, ErrCodec
	}
	delete(fields, "signatures")
	delete(fields, "unsigned")
	raw, err = json.Marshal(fields)
	if err != nil {
		return nil, ErrCodec
	}
	canonical, err := canonicaljson.CanonicalJSON(raw)
	if err != nil {
		return nil, ErrCodec
	}
	return canonical, nil
}

// ed25519Verify is the single verification primitive behind every signature
// gate. It is a variable only so controls can plant a bypass and prove the
// negative tests detect it; production never reassigns it.
var ed25519Verify = func(public, message, signature []byte) bool {
	return goolmcrypto.Ed25519PublicKey(public).Verify(message, signature)
}

// verifySigned checks signature (unpadded standard base64, 64 bytes) by the
// public key (unpadded standard base64, 32 bytes) over obj's signing input.
func verifySigned(public string, obj any, signature string) (bool, error) {
	key, err := publicBase64(public, 32)
	if err != nil {
		return false, ErrCodec
	}
	sig, err := publicBase64(signature, 64)
	if err != nil {
		return false, ErrCodec
	}
	message, err := signingInput(obj)
	if err != nil {
		return false, err
	}
	return ed25519Verify(key, message, sig), nil
}

// jsonSigner is satisfied by goolm's pk.Signing and by accountSigner. Both
// canonicalize the marshaled object and return the standard base64 signature.
type jsonSigner interface {
	SignJSON(obj any) (string, error)
}

// accountSigner gives the goolm device account the pk.Signing.SignJSON
// contract: signingInput produces the canonical bytes, Account.Sign returns
// their unpadded standard base64 Ed25519 signature. goolm's Account has Sign
// only; this adapter never touches the private key itself.
type accountSigner struct{ account *account.Account }

func (s accountSigner) SignJSON(obj any) (string, error) {
	if s.account == nil {
		return "", ErrInvalid
	}
	message, err := signingInput(obj)
	if err != nil {
		return "", err
	}
	signature, err := s.account.Sign(message)
	if err != nil {
		return "", ErrUnavailable
	}
	return string(signature), nil
}

// signWith signs obj's signing input with s and verifies the result under
// public before returning it, so a library semantic drift fails closed here.
func signWith(s jsonSigner, public string, obj any) (string, error) {
	message, err := signingInput(obj)
	if err != nil {
		return "", err
	}
	// Canonical JSON is a fixed point of canonicalization: the library signs
	// exactly these bytes, which verifySigned reproduces independently.
	signature, err := s.SignJSON(json.RawMessage(message))
	if err != nil {
		return "", ErrUnavailable
	}
	ok, err := verifySigned(public, obj, signature)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", ErrIntegrity
	}
	return signature, nil
}

// CrossSigning holds the MSK, SSK and USK derived from the custody root seeds
// (seed 0, 1, 2). Private material never leaves the process; every fmt verb
// prints a fixed label. The keys are rebuilt from the same seeds on every run,
// so an interrupted upload resumes with exactly the persisted public material.
type CrossSigning struct {
	master, selfSigning, userSigning *pk.Signing
	secrets                          *Inventory
}

func DeriveCrossSigning(r Root, secrets *Inventory) (*CrossSigning, error) {
	if secrets == nil {
		return nil, ErrInvalid
	}
	keys := make([]*pk.Signing, len(r.Seeds))
	for i, encoded := range r.Seeds {
		seed, err := keyBytes(encoded)
		if err != nil {
			return nil, err
		}
		secrets.Register(seed)
		s, err := pk.NewSigningFromSeed(seed)
		if err != nil || s == nil {
			return nil, ErrUnavailable
		}
		keys[i] = s
	}
	c := &CrossSigning{keys[0], keys[1], keys[2], secrets}
	m, s, u := c.Master(), c.SelfSigning(), c.UserSigning()
	if m.Public == s.Public || m.Public == u.Public || s.Public == u.Public {
		return nil, ErrIntegrity
	}
	return c, nil
}

func publicOf(s *pk.Signing) PublicKey {
	p, err := publicKeyOf(string(s.PublicKey()))
	if err != nil {
		return PublicKey{}
	}
	return p
}

func (c *CrossSigning) Master() PublicKey      { return publicOf(c.master) }
func (c *CrossSigning) SelfSigning() PublicKey { return publicOf(c.selfSigning) }
func (c *CrossSigning) UserSigning() PublicKey { return publicOf(c.userSigning) }

func keyObject(mxid, usage string, key PublicKey) (SignedKey, error) {
	if !fullMXID(mxid) || key.ID == "" {
		return SignedKey{}, ErrInvalid
	}
	return SignedKey{UserID: mxid, Usage: []string{usage}, Keys: map[string]string{key.ID: key.Public}}, nil
}

// MasterKey is the unsigned standard master-key object for mxid.
func (c *CrossSigning) MasterKey(mxid string) (SignedKey, error) {
	return keyObject(mxid, UsageMaster, c.Master())
}

// SelfSigningKey is the SSK object signed by the master key.
func (c *CrossSigning) SelfSigningKey(mxid string) (SignedKey, error) {
	return c.subordinate(mxid, UsageSelfSigning, c.SelfSigning())
}

// UserSigningKey is the USK object signed by the master key.
func (c *CrossSigning) UserSigningKey(mxid string) (SignedKey, error) {
	return c.subordinate(mxid, UsageUserSigning, c.UserSigning())
}

func (c *CrossSigning) subordinate(mxid, usage string, key PublicKey) (SignedKey, error) {
	obj, err := keyObject(mxid, usage, key)
	if err != nil {
		return SignedKey{}, err
	}
	master := c.Master()
	signature, err := signWith(c.master, master.Public, obj)
	if err != nil {
		return SignedKey{}, err
	}
	obj.Signatures = map[string]map[string]string{mxid: {master.ID: signature}}
	return obj, nil
}

// SignDevice adds this identity's self-signing signature to its own device
// keys. Self-signing one's own device is not owner approval.
func (c *CrossSigning) SignDevice(d DeviceKeys) (DeviceKeys, error) {
	if !fullMXID(d.UserID) || !text(d.DeviceID, 255) {
		return DeviceKeys{}, ErrInvalid
	}
	key := c.SelfSigning()
	signature, err := signWith(c.selfSigning, key.Public, d)
	if err != nil {
		return DeviceKeys{}, err
	}
	out := d
	out.Signatures = map[string]map[string]string{}
	for user, keys := range d.Signatures {
		out.Signatures[user] = map[string]string{}
		for id, sig := range keys {
			out.Signatures[user][id] = sig
		}
	}
	if out.Signatures[d.UserID] == nil {
		out.Signatures[d.UserID] = map[string]string{}
	}
	out.Signatures[d.UserID][key.ID] = signature
	return out, nil
}

// SignAsUser signs obj with the user-signing key. The agent's own USK signs
// nothing in U2a; this exists so controls can model the owner side of the
// Element ceremony with generated material.
func (c *CrossSigning) SignAsUser(obj any) (string, error) {
	return signWith(c.userSigning, c.UserSigning().Public, obj)
}

// SignAsMaster signs obj with the master key, modeling the owner's MSK over
// their USK object when controls render a host pin from generated material.
func (c *CrossSigning) SignAsMaster(obj any) (string, error) {
	return signWith(c.master, c.Master().Public, obj)
}

// DeviceKeys builds this account's standard device-key object, self-signed by
// its Ed25519 device key. The cross-signing signature is added separately.
func (w *Working) DeviceKeys(mxid, device string) (DeviceKeys, error) {
	if !fullMXID(mxid) || !text(device, 255) {
		return DeviceKeys{}, ErrInvalid
	}
	ed, curve, err := w.IdentityKeys()
	if err != nil {
		return DeviceKeys{}, err
	}
	d := DeviceKeys{
		UserID:     mxid,
		DeviceID:   device,
		Algorithms: append([]string(nil), deviceAlgorithms...),
		Keys:       map[string]string{"curve25519:" + device: string(curve), "ed25519:" + device: string(ed)},
	}
	signature, err := signWith(accountSigner{w.account}, string(ed), d)
	if err != nil {
		return DeviceKeys{}, err
	}
	d.Signatures = map[string]map[string]string{mxid: {"ed25519:" + device: signature}}
	return d, nil
}

// VerifyDeviceSelfSignature checks the device's own Ed25519 signature on its
// device-key object; it says nothing about cross-signing or owner approval.
func VerifyDeviceSelfSignature(d DeviceKeys) error {
	ed := d.Keys["ed25519:"+d.DeviceID]
	signature := d.Signatures[d.UserID]["ed25519:"+d.DeviceID]
	if ed == "" || signature == "" {
		return ErrIntegrity
	}
	ok, err := verifySigned(ed, d, signature)
	if err != nil {
		return err
	}
	if !ok {
		return ErrIntegrity
	}
	return nil
}
