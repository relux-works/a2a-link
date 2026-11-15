package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
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
// by the private adapter in internal/cli, which reports the r4 refusal codes.
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
// otherwise replace malformed UTF-8/surrogates with U+FFFD. Validate lexical
// encoding first, including valid pairs, without changing decoded bytes.
func (s *VaultSelection) UnmarshalJSON(data []byte) error {
	if !strictJSONStringEncoding(data) {
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

// strictJSONStringEncoding rejects repair-prone JSON before encoding/json.
// Valid high/low surrogate pairs decode to the same UTF-8 scalar as raw input.
func strictJSONStringEncoding(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}
	quoted := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if !quoted {
			if c == '"' {
				quoted = true
			}
			continue
		}
		if c == '"' {
			quoted = false
			continue
		}
		if c < 0x20 {
			return false
		}
		if c != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		switch data[i] {
		case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
		case 'u':
			if i+4 >= len(data) {
				return false
			}
			n, ok := jsonHex4(data[i+1 : i+5])
			if !ok {
				return false
			}
			i += 4
			if n >= 0xdc00 && n <= 0xdfff {
				return false
			}
			if n >= 0xd800 && n <= 0xdbff {
				if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
					return false
				}
				low, ok := jsonHex4(data[i+3 : i+7])
				if !ok || low < 0xdc00 || low > 0xdfff {
					return false
				}
				i += 6
			}
		default:
			return false
		}
	}
	return !quoted
}
func jsonHex4(b []byte) (uint16, bool) {
	var n uint16
	for _, c := range b {
		n *= 16
		switch {
		case c >= '0' && c <= '9':
			n += uint16(c - '0')
		case c >= 'a' && c <= 'f':
			n += uint16(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			n += uint16(c - 'A' + 10)
		default:
			return 0, false
		}
	}
	return n, true
}

// VaultSelectionField preserves reserved presence separately from a value.
// Its zero value is absent; null is never an absent legacy spelling.
type VaultSelectionField struct {
	present bool
	value   VaultSelection
	invalid bool
}

func (f VaultSelectionField) Present() bool { return f.present }
func (f VaultSelectionField) IsZero() bool  { return !f.present }
func (f VaultSelectionField) Selection() (VaultSelection, error) {
	if !f.present || f.invalid {
		return VaultSelection{}, ErrVaultSelectionShape
	}
	return cloneVaultSelection(f.value), nil
}
func NewVaultSelectionField(s VaultSelection) VaultSelectionField {
	return VaultSelectionField{present: true, value: cloneVaultSelection(s)}
}
func cloneVaultSelection(s VaultSelection) VaultSelection {
	if s.Identity.Origin != nil {
		o := *s.Identity.Origin
		s.Identity.Origin = &o
	}
	return s
}
func (f VaultSelectionField) MarshalJSON() ([]byte, error) {
	if !f.present || f.invalid {
		return nil, ErrVaultSelectionShape
	}
	return json.Marshal(f.value)
}
func scanVaultSelection(data []byte) (VaultSelectionField, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return VaultSelectionField{}, e
	}
	var f VaultSelectionField
	for d.More() {
		t, e := d.Token()
		if e != nil {
			return f, e
		}
		key, ok := t.(string)
		if !ok {
			return f, ErrVaultSelectionShape
		}
		var raw json.RawMessage
		if e = d.Decode(&raw); e != nil {
			return f, e
		}
		if !strings.EqualFold(key, "vault_selection") {
			continue
		}
		if f.present || key != "vault_selection" {
			f.present = true
			f.invalid = true
			return f, ErrVaultSelectionShape
		}
		f.present = true
		if e = f.value.UnmarshalJSON(raw); e != nil {
			f.invalid = true
			return f, ErrVaultSelectionShape
		}
	}
	return f, nil
}
