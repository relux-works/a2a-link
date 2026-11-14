package cg1

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/a2a-swarm/internal/admission"
)

func freshMatrixConfig(t *testing.T) (*matrixFixture, string, admission.Config) {
	t.Helper()
	f := newMatrixFixture(t)
	dir := stateDir(t)
	f.save(t, dir)
	return f, dir, admission.Config{Identity: "alice", StateDir: dir, MatrixUserID: matrixAlice}
}
func noMatrixBinding(t *testing.T, dir string) {
	t.Helper()
	for _, path := range []string{"matrix-cg1-state/" + matrixJournalName, "matrix-grantcheck-state/grantcheck.json"} {
		if _, e := os.Lstat(filepath.Join(dir, path)); !os.IsNotExist(e) {
			t.Fatalf("failed startup persisted binding: %s (%v)", path, e)
		}
	}
}

// Proves malformed/unknown evidence is refused before either binding exists, and a corrected configuration starts in that same namespace.
func TestMatrixStartupEvidenceShapes(t *testing.T) {
	cases := []struct {
		name, slot string
		value      any
	}{
		{"empty-service-root", "service_root", map[string]any{}},
		{"empty-revocation-root", "agent_revocation_root", map[string]any{}},
		{"attestations-string", "attestations", "bad"},
		{"generations-array", "active_generations", []any{}},
		{"revocations-string", "revocations", "bad"},
		{"time-boolean", "time", false},
		{"unknown-slot", "unknown", map[string]any{}},
		{"service-purpose", "service_root", map[string]any{"key": edID(testEd(20)), "purpose": "5"}},
		{"revocation-purpose", "agent_revocation_root", map[string]any{"key": edID(testEd(21)), "purpose": "wrong", "attestation_root": edID(testEd(20))}},
		{"attestation-bytes", "attestations", map[string]any{"sha256:bad": false}},
		{"generation-row", "active_generations", map[string]any{edID(testEd(10)): false}},
		{"revocation-row", "revocations", map[string]any{edID(testEd(21)): false}},
		{"time-fields", "time", map[string]any{"trusted": true, "fresh": true}},
		{"time-extra", "time", map[string]any{"trusted": true, "fresh": true, "authority_until": "2026-01-01T00:06:00Z", "extra": true}},
		{"operator-root", "operator_root", false},
		{"operator-owner", "operator_owner", map[string]any{}},
		{"operator-attestations", "operator_attestations", []any{}},
		{"signer-facts", "signer_facts", map[string]any{"current": "true", "presence": false, "presence_current": true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, dir, cfg := freshMatrixConfig(t)
			original, exists := f.cfg.Evidence[tc.slot]
			f.cfg.Evidence[tc.slot] = evidenceJSON(t, tc.value)
			f.save(t, dir)
			checker, e := admission.Open(MatrixPolicy, cfg)
			if checker != nil {
				checker.Close()
			}
			if e == nil || checker != nil {
				t.Fatal("invalid envelope evidence admitted at startup")
			}
			noMatrixBinding(t, dir)
			entries, re := os.ReadDir(dir)
			if re != nil || len(entries) != 1 || entries[0].Name() != matrixConfigName {
				t.Fatal("invalid evidence caused startup writes", re)
			}
			if exists {
				f.cfg.Evidence[tc.slot] = original
			} else {
				delete(f.cfg.Evidence, tc.slot)
			}
			f.save(t, dir)
			checker, e = admission.Open(MatrixPolicy, cfg)
			if e != nil || checker == nil {
				t.Fatal("corrected evidence cannot start", e)
			}
			checker.Close()
		})
	}
}

// Proves a rejected backend config leaves no binding and its corrected neighbor starts, while established pin changes still refuse.
func TestMatrixRejectedStartupCanRecover(t *testing.T) {
	for _, field := range []string{"agent", "issuer"} {
		t.Run(field, func(t *testing.T) {
			f, dir, cfg := freshMatrixConfig(t)
			agent, issuer := f.cfg.AgentName, f.cfg.IssuerPubkey
			if field == "agent" {
				f.cfg.AgentName = ""
			} else {
				f.cfg.IssuerPubkey = ""
			}
			f.save(t, dir)
			checker, e := admission.Open(MatrixPolicy, cfg)
			if checker != nil {
				checker.Close()
			}
			if e == nil || checker != nil {
				t.Fatal("invalid backend config admitted")
			}
			noMatrixBinding(t, dir)
			f.cfg.AgentName, f.cfg.IssuerPubkey = agent, issuer
			f.save(t, dir)
			checker, e = admission.Open(MatrixPolicy, cfg)
			if e != nil || checker == nil {
				t.Fatal("corrected backend configuration remains poisoned", e)
			}
			checker.Close()
			for _, path := range []string{"matrix-cg1-state", "matrix-grantcheck-state"} {
				st, e := os.Stat(filepath.Join(dir, path))
				if e != nil || st.Mode().Perm() != 0700 {
					t.Fatal("private state mode", path, e)
				}
			}
			f.cfg.Pins[matrixBob] = matrixPeer{Key: xonly(3), Author: edID(f.bob)}
			f.save(t, dir)
			checker, e = admission.Open(MatrixPolicy, cfg)
			if checker != nil {
				checker.Close()
			}
			if e == nil || checker != nil {
				t.Fatal("established namespace forgot immutable pins")
			}
		})
	}
}

// Proves valid optional evidence starts, while malformed fields inside otherwise valid nested rows refuse before state creation.
func TestMatrixStartupNestedEvidence(t *testing.T) {
	cases := []struct {
		slot, field string
		value       any
	}{
		{"service_root", "key", false}, {"service_root", "extra", true},
		{"agent_revocation_root", "attestation_root", edID(testEd(30))},
		{"active_generations", "uid", "1000"}, {"active_generations", "uid", -1},
		{"active_generations", "registration_number", 0}, {"active_generations", "active", "true"},
		{"active_generations", "generation", false}, {"active_generations", "master_epoch", ""},
		{"active_generations", "owner", false}, {"active_generations", "path", false},
		{"active_generations", "extra", true},
		{"revocations", "availability", false}, {"revocations", "max_age", 61},
		{"revocations", "rollback_safe", "true"}, {"revocations", "snapshot", "not-base64"},
		{"revocations", "extra", true},
		{"time", "trusted", "true"}, {"time", "fresh", 1}, {"time", "authority_until", "invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.slot+"/"+tc.field, func(t *testing.T) {
			f, dir, cfg := freshMatrixConfig(t)
			original := f.cfg.Evidence[tc.slot]
			var obj map[string]any
			if e := json.Unmarshal(original, &obj); e != nil {
				t.Fatal(e)
			}
			row := obj
			if tc.slot == "active_generations" || tc.slot == "revocations" {
				for _, value := range obj {
					row = value.(map[string]any)
					break
				}
			}
			row[tc.field] = tc.value
			f.cfg.Evidence[tc.slot] = evidenceJSON(t, obj)
			f.save(t, dir)
			c, e := admission.Open(MatrixPolicy, cfg)
			if c != nil {
				c.Close()
			}
			if e == nil || c != nil {
				t.Fatal("invalid nested evidence admitted at startup")
			}
			noMatrixBinding(t, dir)
			f.cfg.Evidence[tc.slot] = original
			f.cfg.Evidence["operator_root"] = evidenceJSON(t, edID(testEd(22)))
			f.cfg.Evidence["operator_owner"] = evidenceJSON(t, "fixture-owner")
			f.cfg.Evidence["operator_attestations"] = evidenceJSON(t, map[string]any{})
			f.cfg.Evidence["signer_facts"] = evidenceJSON(t, map[string]any{"current": true, "presence": false, "presence_current": true})
			f.save(t, dir)
			c, e = admission.Open(MatrixPolicy, cfg)
			if e != nil || c == nil {
				t.Fatal("valid optional/nested evidence cannot start", e)
			}
			c.Close()
		})
	}
}
