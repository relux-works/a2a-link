package cg1

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/relux-works/a2a-swarm/internal/admission"
)

func refuseNostrPolicyNames(t *testing.T, config admission.Config, raw []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(config.StateDir, "cg1.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	opened, err := open(config)
	if opened != nil {
		opened.Close()
		t.Fatal("invalid member constructed checker")
	}
	if !errors.Is(err, errConfig) {
		t.Fatalf("want configuration refusal, got %v", err)
	}
	if _, err := os.Lstat(filepath.Join(config.StateDir, "cg1-state")); !os.IsNotExist(err) {
		t.Fatal("invalid member created checker state")
	}
}

func openNostrPolicyNamesControl(t *testing.T, config admission.Config, raw []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(config.StateDir, "cg1.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	opened, err := open(config)
	if err != nil {
		t.Fatal("exact-name control", err)
	}
	opened.Close()
}

// Claim: every Nostr policy and RPC member rejects aliases and duplicates before state creation, beside exact v1/pay and v2/trust controls.
func TestNostrPolicyExactMemberNames(t *testing.T) {
	for _, version := range []int{1, 2} {
		fields := strings.Fields("version agent_name landlord_name issuer_pubkey timeout_ms rpc executor_key max_tip_age_seconds max_future_skew_seconds minimum_height terms rpc.host rpc.port rpc.username rpc.password")
		if version == 2 {
			fields = append(fields, "profile", "network", "genesis")
		}
		for _, field := range fields {
			for _, defect := range []string{"alias", "alias-extra", "duplicate"} {
				t.Run(strconv.Itoa(version)+"/"+field+"/"+defect, func(t *testing.T) {
					config, policy := configFixture(t)
					if version == 2 {
						policy.Version, policy.grantPolicy = 2, explicitPolicy(t, "trust", "regtest")
					}
					valid := jsonBytes(t, policy)
					var object map[string]json.RawMessage
					if err := json.Unmarshal(valid, &object); err != nil {
						t.Fatal(err)
					}
					target, name := object, field
					if strings.HasPrefix(field, "rpc.") {
						name = strings.TrimPrefix(field, "rpc.")
						target = make(map[string]json.RawMessage)
						if err := json.Unmarshal(object["rpc"], &target); err != nil {
							t.Fatal(err)
						}
					}
					value := target[name]
					if defect != "duplicate" {
						target[strings.ToUpper(name)] = value
						if defect == "alias" {
							delete(target, name)
						}
					}
					bad := jsonBytes(t, target)
					if defect == "duplicate" {
						bad = append([]byte(`{"`+name+`":`+string(value)+`,`), bad[1:]...)
					}
					if strings.HasPrefix(field, "rpc.") {
						object["rpc"] = bad
						bad = jsonBytes(t, object)
					}
					refuseNostrPolicyNames(t, config, bad)
					openNostrPolicyNamesControl(t, config, valid)
				})
			}
		}
	}
}

// Claim: a later VERSION alias cannot select trust over an exact version:1; the unambiguous version:2 trust control still opens.
func TestNostrPolicyVersionAliasCannotSelectTrust(t *testing.T) {
	config, policy := configFixture(t)
	policy.Version, policy.grantPolicy = 2, explicitPolicy(t, "trust", "regtest")
	valid := jsonBytes(t, policy)
	attack := bytes.Replace(valid, []byte(`"version":2`), []byte(`"version":1,"VERSION":2`), 1)
	var decoded settings
	if bytes.Equal(attack, valid) || json.Unmarshal(attack, &decoded) != nil || decoded.Version != 2 || decoded.Profile != "trust" {
		t.Fatal("fixture does not exercise last-wins version alias")
	}
	refuseNostrPolicyNames(t, config, attack)
	openNostrPolicyNamesControl(t, config, valid)
}

// Claim: duplicate detection independently rejects exact and Unicode case-folded names in each object, while distinct members remain valid.
func TestPolicyJSONFoldDuplicates(t *testing.T) {
	for _, test := range []struct{ name, raw string }{
		{"exact", `{"version":1,"version":2}`},
		{"version-alias", `{"version":1,"VERSION":2}`},
		{"reverse-version-alias", `{"VERSION":2,"version":1}`},
		{"unicode-version-alias", `{"version":1,"verſion":2}`},
		{"rpc-alias", `{"version":1,"rpc":{"host":"a","HOST":"b"}}`},
		{"unicode-rpc-alias", `{"version":1,"rpc":{"username":"a","uſername":"b"}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if !uniqueJSON([]byte(`{"version":1,"rpc":{"host":"a","username":"b"}}`)) {
				t.Fatal("distinct-member control")
			}
			if uniqueJSON([]byte(test.raw)) {
				t.Fatal("duplicate member passed")
			}
		})
	}
}
