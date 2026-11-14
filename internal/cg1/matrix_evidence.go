package cg1

import (
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/relux-works/swarma-envelope/record"
)

func exactEvidenceObject(value any, fields string) (map[string]any, bool) {
	m, ok := value.(map[string]any)
	names := strings.Fields(fields)
	if !ok || len(m) != len(names) {
		return nil, false
	}
	for _, name := range names {
		if _, ok := m[name]; !ok {
			return nil, false
		}
	}
	return m, true
}
func evidenceKey(value any) bool {
	key, ok := value.(string)
	return ok && record.ValidateKey(key) == nil
}
func evidenceText(value any) bool {
	s, ok := value.(string)
	return ok && len(s) > 0 && len(s) <= 255 && utf8.ValidString(s)
}
func evidenceStamp(value any) bool {
	s, ok := value.(string)
	if !ok || len(s) != 20 {
		return false
	}
	t, e := time.Parse("2006-01-02T15:04:05Z", s)
	return e == nil && t.Year() >= 1970 && t.Format("2006-01-02T15:04:05Z") == s
}
func evidenceBool(v any) bool { _, ok := v.(bool); return ok }
func evidenceInteger(v any, min, max int64) bool {
	n, ok := v.(int64)
	return ok && n >= min && n <= max
}

// Signed evidence retains opaque canonical base64url bytes; cryptographic authority and freshness are checked by VerifyMessage.
func evidenceRecord(value any, kind string) bool {
	s, ok := value.(string)
	if !ok {
		return false
	}
	raw, e := record.DecodeBase64(s, -1)
	if e != nil || len(raw) == 0 || len(raw) > 8192 {
		return false
	}
	parsed, e := record.Parse(raw, 8192, 16)
	if e != nil {
		return false
	}
	outer, ok := exactEvidenceObject(parsed, "version body id signatures")
	if !ok || outer["version"] != "swarm-envelope/2" {
		return false
	}
	id, ok := outer["id"].(string)
	if !ok || !record.IsContentID(id) {
		return false
	}
	body, ok := outer["body"].(map[string]any)
	if !ok || body["type"] != kind || !evidenceKey(body["issuer"]) {
		return false
	}
	sigs, ok := outer["signatures"].([]any)
	if !ok || len(sigs) != 1 {
		return false
	}
	sig, ok := exactEvidenceObject(sigs[0], "role key sig")
	if !ok || sig["role"] != "author" || !evidenceKey(sig["key"]) {
		return false
	}
	encoded, ok := sig["sig"].(string)
	if !ok {
		return false
	}
	_, e = record.DecodeBase64(encoded, 64)
	return e == nil
}

// Validate the entire closed host-evidence grammar before startup can create either durable binding.
func matrixEvidenceShape(raw map[string]json.RawMessage) bool {
	values := map[string]any{}
	for name, encoded := range raw {
		value, e := evidenceValue(encoded)
		if e != nil {
			return false
		}
		values[name] = value
		switch name {
		case "service_root":
			m, ok := exactEvidenceObject(value, "key purpose")
			if !ok || !evidenceKey(m["key"]) || m["purpose"] != int64(5) {
				return false
			}
		case "agent_revocation_root":
			m, ok := exactEvidenceObject(value, "key purpose attestation_root")
			if !ok || !evidenceKey(m["key"]) || !evidenceKey(m["attestation_root"]) || m["purpose"] != "registry-revocation" {
				return false
			}
		case "attestations", "operator_attestations":
			m, ok := value.(map[string]any)
			if !ok {
				return false
			}
			for key, recordBytes := range m {
				if name == "attestations" {
					if !record.IsContentID(key) {
						return false
					}
				} else if !evidenceKey(key) {
					return false
				}
				if !evidenceRecord(recordBytes, "attestation/1") {
					return false
				}
			}
		case "active_generations":
			m, ok := value.(map[string]any)
			if !ok {
				return false
			}
			for key, row := range m {
				p, ok := exactEvidenceObject(row, "active uid generation registration_number master_epoch owner path")
				if !evidenceKey(key) || !ok || !evidenceBool(p["active"]) || !evidenceInteger(p["uid"], 0, 4294967294) || !evidenceInteger(p["registration_number"], 1, 9007199254740991) {
					return false
				}
				for _, name := range []string{"generation", "master_epoch", "owner", "path"} {
					if !evidenceText(p[name]) {
						return false
					}
				}
			}
		case "revocations":
			m, ok := value.(map[string]any)
			if !ok {
				return false
			}
			for key, row := range m {
				p, ok := exactEvidenceObject(row, "availability max_age rollback_safe snapshot")
				if !evidenceKey(key) || !ok || (p["availability"] != "available" && p["availability"] != "unavailable") || !evidenceInteger(p["max_age"], 1, 60) || !evidenceBool(p["rollback_safe"]) || !evidenceRecord(p["snapshot"], "revocation/1") {
					return false
				}
			}
		case "time":
			m, ok := exactEvidenceObject(value, "trusted fresh authority_until")
			if !ok || !evidenceBool(m["trusted"]) || !evidenceBool(m["fresh"]) || !evidenceStamp(m["authority_until"]) {
				return false
			}
		case "operator_root":
			if !evidenceKey(value) {
				return false
			}
		case "operator_owner":
			if !evidenceText(value) {
				return false
			}
		case "signer_facts":
			m, ok := exactEvidenceObject(value, "current presence presence_current")
			if !ok || !evidenceBool(m["current"]) || !evidenceBool(m["presence"]) || !evidenceBool(m["presence_current"]) {
				return false
			}
		default:
			return false
		}
	}
	for _, name := range []string{"service_root", "agent_revocation_root", "attestations", "active_generations", "revocations", "time"} {
		if _, ok := values[name]; !ok {
			return false
		}
	}
	service := values["service_root"].(map[string]any)
	revoker := values["agent_revocation_root"].(map[string]any)
	if service["key"] == revoker["key"] || revoker["attestation_root"] != service["key"] {
		return false
	}
	if op, ok := values["operator_root"]; ok && (op == service["key"] || op == revoker["key"]) {
		return false
	}
	return true
}
