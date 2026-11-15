package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

// BackendVaultV1 is the explicit, named-only vault release backend label
// (per-identity-vault/phase1-r4). It is independent of the proposed native
// protocol integer and is never selected by the legacy ambient selector.
const BackendVaultV1 = "vault-v1"

// VaultSelection is the source-owned per-agent named metadata field
// vault_selection. It is required for vault-v1 and absent for every legacy
// backend; profiles never carry it. Only the closed JSON shape is enforced
// here. Representation, bounds, grammar and synthetic recomputation are owned
// by internal/vaultv1, which reports the r4 refusal codes.
type VaultSelection struct {
	Identity    VaultIdentity `json:"identity"`
	SessionMode string        `json:"session_mode"`
}

// VaultIdentity is the public IdentityV2 notation. Origin is always present
// on disk: null for explicit identities, the exact triple for synthetic ones.
type VaultIdentity struct {
	Domain string       `json:"domain"`
	Kind   string       `json:"kind"`
	Name   string       `json:"name"`
	Origin *VaultOrigin `json:"origin"`
}

// VaultOrigin is the public SyntheticContextV2 notation.
type VaultOrigin struct {
	HostID    string `json:"host_id"`
	ProjectID string `json:"project_id"`
	ProfileID string `json:"profile_id"`
}

// ErrVaultSelectionShape is the fixed diagnostic for any non-closed
// vault_selection value. It never reproduces input.
var ErrVaultSelectionShape = errors.New("invalid vault_selection shape")

// UnmarshalJSON accepts exactly the closed shape: every key present once, no
// unknown keys, string-typed scalars and byte-exact UTF-8. encoding/json would
// otherwise replace invalid UTF-8 or lone surrogate escapes with U+FFFD, which
// silently changes identity bytes, so both are refused before decoding.
func (s *VaultSelection) UnmarshalJSON(data []byte) error {
	if !utf8.Valid(data) || hasSurrogateEscape(data) {
		return ErrVaultSelectionShape
	}
	top, err := closedObject(data, "identity", "session_mode")
	if err != nil {
		return err
	}
	id, err := closedObject(top["identity"], "domain", "kind", "name", "origin")
	if err != nil {
		return err
	}
	var next VaultSelection
	for _, f := range []struct {
		raw json.RawMessage
		dst *string
	}{{top["session_mode"], &next.SessionMode}, {id["domain"], &next.Identity.Domain}, {id["kind"], &next.Identity.Kind}, {id["name"], &next.Identity.Name}} {
		if err := jsonString(f.raw, f.dst); err != nil {
			return err
		}
	}
	if raw := bytes.TrimSpace(id["origin"]); !bytes.Equal(raw, []byte("null")) {
		o, err := closedObject(raw, "host_id", "project_id", "profile_id")
		if err != nil {
			return err
		}
		next.Identity.Origin = &VaultOrigin{}
		for _, f := range []struct {
			raw json.RawMessage
			dst *string
		}{{o["host_id"], &next.Identity.Origin.HostID}, {o["project_id"], &next.Identity.Origin.ProjectID}, {o["profile_id"], &next.Identity.Origin.ProfileID}} {
			if err := jsonString(f.raw, f.dst); err != nil {
				return err
			}
		}
	}
	*s = next
	return nil
}

// closedObject decodes one JSON object whose key set is exactly keys, each
// present once. Values are returned raw for typed decoding by the caller.
func closedObject(data []byte, keys ...string) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	if t, e := d.Token(); e != nil || t != json.Delim('{') {
		return nil, ErrVaultSelectionShape
	}
	allowed := map[string]bool{}
	for _, k := range keys {
		allowed[k] = true
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		t, e := d.Token()
		k, ok := t.(string)
		if e != nil || !ok || !allowed[k] {
			return nil, ErrVaultSelectionShape
		}
		if _, dup := out[k]; dup {
			return nil, ErrVaultSelectionShape
		}
		var raw json.RawMessage
		if e = d.Decode(&raw); e != nil {
			return nil, ErrVaultSelectionShape
		}
		out[k] = raw
	}
	if t, e := d.Token(); e != nil || t != json.Delim('}') {
		return nil, ErrVaultSelectionShape
	}
	if _, e := d.Token(); e != io.EOF || len(out) != len(keys) {
		return nil, ErrVaultSelectionShape
	}
	return out, nil
}

func jsonString(raw json.RawMessage, dst *string) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, dst) != nil {
		return ErrVaultSelectionShape
	}
	return nil
}

// hasSurrogateEscape reports a \uD800-\uDFFF escape. Astral characters must be
// written as raw UTF-8 bytes in vault_selection; this is a deliberate, narrow
// restriction so decoding can never substitute U+FFFD for a lone surrogate.
func hasSurrogateEscape(data []byte) bool {
	for i := 0; i+5 < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		if data[i+1] == 'u' && (data[i+2] == 'd' || data[i+2] == 'D') && bytes.IndexByte([]byte("89abAB"), data[i+3]) >= 0 {
			return true
		}
		i++ // skip the escaped character, including an escaped backslash
	}
	return false
}
