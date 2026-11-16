package e2ee

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"runtime"
	"strings"
)

// MaxPin bounds the host trust artifact (docs/e2ee.md section 3).
const MaxPin = 64 << 10

// PinPolicy names the host trust root and the UID that provisions it. The CLI
// never writes under Base. Production uses HostPinPolicy; controls point Base at
// a fixture directory owned by the test UID.
type PinPolicy struct {
	Base       string
	TrustedUID int
}

// HostPinPolicy is the platform host-managed trust root, provisioned by root.
func HostPinPolicy() PinPolicy {
	if runtime.GOOS == "darwin" {
		return PinPolicy{Base: "/Library/Application Support/a2a-swarm/e2ee-trust", TrustedUID: 0}
	}
	return PinPolicy{Base: "/etc/a2a-swarm/e2ee-trust", TrustedUID: 0}
}

// LegacyBinding is the section 3 legacy connection-binding digest: a versioned
// tuple of endpoint, server, backend, class and full MXID. Named connections use
// ConnectionBinding.Fingerprint instead. No token enters either digest.
func LegacyBinding(endpoint, server, backend, class, mxid string) string {
	return TupleHash("1", endpoint, server, backend, class, mxid)
}

// PinPath is Base/B/CLASS/H/NAME.pin.json with H = SHA256 hex of the exact MXID.
func PinPath(policy PinPolicy, binding, class, mxid, name string) (string, error) {
	if !filepath.IsAbs(policy.Base) || filepath.Clean(policy.Base) != policy.Base || policy.Base == "/" {
		return "", ErrInvalid
	}
	if !hexSize(binding, 32) || (class != "agents" && class != "humans") || !fullMXID(mxid) || !text(name, 64) || strings.ContainsAny(name, "/\\") || name == "." || name == ".." {
		return "", ErrInvalid
	}
	h := sha256.Sum256([]byte(mxid))
	return filepath.Join(policy.Base, binding, class, hex.EncodeToString(h[:]), name+".pin.json"), nil
}

type pinPrincipal struct {
	MXID                       string   `json:"mxid"`
	MasterKeyID                string   `json:"master_key_id"`
	MasterPublicKey            string   `json:"master_public_key"`
	MasterSHA256               string   `json:"master_sha256"`
	UserSigningKeyID           string   `json:"user_signing_key_id"`
	UserSigningPublicKey       string   `json:"user_signing_public_key"`
	UserSigningSHA256          string   `json:"user_signing_sha256"`
	UserSigningMasterSignature string   `json:"user_signing_master_signature"`
	ApprovedDevices            []string `json:"approved_devices"`
}

type pinFile struct {
	Version    int            `json:"v"`
	Binding    string         `json:"binding"`
	Identity   string         `json:"identity"`
	Device     string         `json:"device_id"`
	Revision   uint64         `json:"revision"`
	Owner      string         `json:"owner"`
	Principals []pinPrincipal `json:"principals"`
}

// HostPin is one validated host trust artifact. Record is the owner principal's
// public proof shape (U1 PinRecord) with Digest set to the SHA256 of the exact
// artifact bytes, so a later reopen can be compared byte-for-byte.
type HostPin struct {
	Revision                  uint64
	Digest                    string
	Binding, Identity, Device string
	Owner                     string
	Record                    PinRecord
	ApprovedDevices           []string
}

// parseHostPin decodes strict JSON (no duplicate or unknown member, bounded
// size and depth) and validates binding, identity, device, revision and the
// owner principal's public proof shape. Only the principal whose MXID is the
// pinned owner supplies the MSK/USK evidence; any other principal's USK is
// never consulted. Shape validity is not cryptographic verification.
func parseHostPin(raw []byte, binding, mxid, device string) (HostPin, error) {
	if len(raw) > MaxPin {
		return HostPin{}, ErrCapacity
	}
	var f pinFile
	if err := strictJSON(raw, &f, MaxPin); err != nil {
		return HostPin{}, ErrPinInvalid
	}
	if f.Version != 1 || f.Binding != binding || f.Identity != mxid || f.Revision == 0 || !fullMXID(f.Owner) || !text(f.Device, 255) {
		return HostPin{}, ErrPinInvalid
	}
	if device != "" && f.Device != device {
		return HostPin{}, ErrPinInvalid
	}
	if len(f.Principals) == 0 || len(f.Principals) > 64 {
		return HostPin{}, ErrPinInvalid
	}
	sum := sha256.Sum256(raw)
	pin := HostPin{Revision: f.Revision, Digest: hex.EncodeToString(sum[:]), Binding: f.Binding, Identity: f.Identity, Device: f.Device, Owner: f.Owner}
	seen := map[string]bool{}
	found := false
	for _, p := range f.Principals {
		if !fullMXID(p.MXID) || seen[p.MXID] {
			return HostPin{}, ErrPinInvalid
		}
		seen[p.MXID] = true
		if len(p.ApprovedDevices) > 64 {
			return HostPin{}, ErrPinInvalid
		}
		devices := map[string]bool{}
		for _, d := range p.ApprovedDevices {
			if !text(d, 255) || devices[d] {
				return HostPin{}, ErrPinInvalid
			}
			devices[d] = true
		}
		if p.MXID != f.Owner {
			continue
		}
		found = true
		pin.Record = PinRecord{
			Revision: f.Revision, Digest: pin.Digest, Owner: f.Owner,
			MasterKeyID: p.MasterKeyID, MasterPublicKey: p.MasterPublicKey, MasterSHA256: p.MasterSHA256,
			UserSigningKeyID: p.UserSigningKeyID, UserSigningPublicKey: p.UserSigningPublicKey, UserSigningSHA256: p.UserSigningSHA256,
			UserSigningMasterSignature: p.UserSigningMasterSignature,
		}
		pin.ApprovedDevices = append([]string(nil), p.ApprovedDevices...)
	}
	if !found {
		return HostPin{}, ErrPinInvalid
	}
	if err := pin.Record.Validate(); err != nil {
		return HostPin{}, ErrPinInvalid
	}
	return pin, nil
}
