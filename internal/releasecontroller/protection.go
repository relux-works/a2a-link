package releasecontroller

import (
	"encoding/json"
	"errors"
	"time"
)

// ProtectionEvidence is a complete authority response, not a projection of
// current_user_can_bypass. An omitted bypass list cannot prove nobody bypasses.
type ProtectionEvidence struct {
	ID           int64           `json:"id"`
	Target       string          `json:"target"`
	Source       string          `json:"source"`
	SourceType   string          `json:"source_type"`
	Enforcement  string          `json:"enforcement"`
	BypassActors json.RawMessage `json:"bypass_actors"`
	Conditions   struct {
		RefName struct{ Include, Exclude []string } `json:"ref_name"`
	} `json:"conditions"`
	Rules []struct {
		Type       string                     `json:"type"`
		Parameters map[string]json.RawMessage `json:"parameters"`
	} `json:"rules"`
}
type RuleVersion struct {
	ID        int64     `json:"version_id"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CheckProtection interprets the GitHub consumer fields: active update/deletion
// rules, exact ref selection and no bypass actors. Names alone prove nothing.
func CheckProtection(raw, history []byte, target, ref string, id, version int64, taggedAt time.Time) error {
	var p ProtectionEvidence
	if json.Unmarshal(raw, &p) != nil || p.ID != id || id <= 0 || p.Target != target || p.Source != "relux-works/a2a-swarm" || p.SourceType != "Repository" || p.Enforcement != "active" {
		return errors.New("custody-protection-binding")
	}
	var bypass []json.RawMessage
	if len(p.BypassActors) == 0 || string(p.BypassActors) == "null" || json.Unmarshal(p.BypassActors, &bypass) != nil || bypass == nil || len(bypass) != 0 {
		return errors.New("custody-protection-bypass-proof")
	}
	if len(p.Conditions.RefName.Include) != 1 || p.Conditions.RefName.Include[0] != ref || len(p.Conditions.RefName.Exclude) != 0 {
		return errors.New("custody-protection-ref")
	}
	expected := map[string]bool{"update": true, "deletion": true}
	if target == "branch" {
		expected["non_fast_forward"] = true
	} else if target != "tag" {
		return errors.New("custody-protection-target")
	}
	seen := map[string]bool{}
	for _, r := range p.Rules {
		if !expected[r.Type] || seen[r.Type] {
			return errors.New("custody-protection-rules")
		}
		seen[r.Type] = true
		for k, v := range r.Parameters {
			if r.Type != "update" || k != "update_allows_fetch_and_merge" || string(v) != "false" {
				return errors.New("custody-protection-update-exception")
			}
		}
	}
	if len(seen) != len(expected) {
		return errors.New("custody-protection-rules")
	}
	var versions []RuleVersion
	if json.Unmarshal(history, &versions) != nil || len(versions) == 0 || len(versions) >= 100 || version <= 0 || taggedAt.IsZero() {
		return errors.New("custody-protection-history-required")
	}
	latest := RuleVersion{}
	seenVersions := map[int64]bool{}
	for _, v := range versions {
		if v.ID <= 0 || v.UpdatedAt.IsZero() || seenVersions[v.ID] {
			return errors.New("custody-protection-history-required")
		}
		seenVersions[v.ID] = true
		if v.ID > latest.ID {
			latest = v
		}
	}
	if latest.ID != version || latest.UpdatedAt.After(taggedAt) {
		return errors.New("custody-protection-changed")
	}
	return nil
}
