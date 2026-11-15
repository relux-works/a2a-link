package cg1

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/a2a-swarm/internal/admission"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
)

// Claim: both factories refuse omitted/null mandatory pins before writing checker state, and accept corrected neighbors including explicit zero F/FLOOR.
func TestRequiredGrantPolicyStartup(t *testing.T) {
	for _, policy := range []string{Policy, MatrixPolicy} {
		for _, field := range []string{"executor_key", "max_tip_age_seconds", "max_future_skew_seconds", "minimum_height", "terms"} {
			for _, kind := range []string{"missing", "null", "alias", "alias-extra"} {
				t.Run(policy+"/"+field+"/"+kind, func(t *testing.T) {
					c, settings := configFixture(t)
					*settings.MaxFutureSkewSeconds = 0
					dir, filename, mode := c.StateDir, "cg1.json", os.FileMode(0600)
					raw := jsonBytes(t, settings)
					if policy == MatrixPolicy {
						f, d, cfg := freshMatrixConfig(t)
						*f.cfg.MaxFutureSkewSeconds = 0
						dir, c, filename, mode = d, cfg, matrixConfigName, 0700
						raw = jsonBytes(t, f.cfg)
					}
					var obj map[string]json.RawMessage
					if err := json.Unmarshal(raw, &obj); err != nil {
						t.Fatal(err)
					}
					if kind == "alias-extra" {
						obj[strings.ToUpper(field)] = obj[field]
					} else if kind == "alias" {
						obj[strings.ToUpper(field)] = obj[field]
						delete(obj, field)
					} else if kind == "missing" {
						delete(obj, field)
					} else {
						obj[field] = json.RawMessage("null")
					}
					if err := os.WriteFile(filepath.Join(dir, filename), jsonBytes(t, obj), mode); err != nil {
						t.Fatal(err)
					}
					checker, err := admission.Open(policy, c)
					if checker != nil {
						checker.Close()
					}
					if err == nil || checker != nil {
						t.Fatal("missing policy input admitted")
					}
					entries, err := os.ReadDir(dir)
					if err != nil || len(entries) != 1 {
						t.Fatal("invalid policy wrote state", err)
					}
					if err := os.WriteFile(filepath.Join(dir, filename), raw, mode); err != nil {
						t.Fatal(err)
					}
					checker, err = admission.Open(policy, c)
					if err != nil {
						t.Fatal("corrected policy refused", err)
					}
					checker.Close()
				})
			}
		}
	}
}

// Claim: zero/negative/overflow A, skew outside the bench ceiling, bad floor, noncanonical or hash-mismatched terms never resolve; valid boundaries resolve.
func TestGrantPolicyBounds(t *testing.T) {
	for _, mode := range []string{"valid", "zero-skew-floor", "ceiling", "zero-age", "negative-age", "overflow-age", "negative-skew", "large-skew", "negative-floor", "large-floor", "executor", "terms-hash", "terms-noncanonical", "terms-padding"} {
		t.Run(mode, func(t *testing.T) {
			p := testGrantPolicy(t)
			switch mode {
			case "zero-skew-floor":
				*p.MaxFutureSkewSeconds = 0
			case "ceiling":
				*p.MaxFutureSkewSeconds = 600
			case "zero-age":
				*p.MaxTipAgeSeconds = 0
			case "negative-age":
				*p.MaxTipAgeSeconds = -1
			case "overflow-age":
				*p.MaxTipAgeSeconds = 9223372037
			case "negative-skew":
				*p.MaxFutureSkewSeconds = -1
			case "large-skew":
				*p.MaxFutureSkewSeconds = 601
			case "negative-floor":
				*p.MinimumHeight = -1
			case "large-floor":
				*p.MinimumHeight = 2147483648
			case "executor":
				p.ExecutorKey = strings.Repeat("f", 64)
			case "terms-hash":
				p.Terms = map[string]string{strings.Repeat("a", 64): base64.RawURLEncoding.EncodeToString(unitTerms(t))}
			case "terms-noncanonical":
				raw := append(unitTerms(t), ' ')
				p.Terms = map[string]string{rental.Hash(raw): base64.RawURLEncoding.EncodeToString(raw)}
			case "terms-padding":
				for k, v := range p.Terms {
					p.Terms[k] = v + "="
				}
			}
			_, _, err := p.resolve()
			valid := mode == "valid" || mode == "zero-skew-floor" || mode == "ceiling"
			if (err == nil) != valid {
				t.Fatal("policy boundary", err)
			}
		})
	}
}

// Claim: an established namespace cannot reopen under changed executor/A/F/FLOOR pins, and refusal leaves its durable binding unchanged.
func TestGrantPolicyImmutableState(t *testing.T) {
	for _, policy := range []string{Policy, MatrixPolicy} {
		for _, field := range []string{"executor", "age", "skew", "floor"} {
			t.Run(policy+"/"+field, func(t *testing.T) {
				cfg, s := configFixture(t)
				p := &s.grantPolicy
				path := filepath.Join(cfg.StateDir, "cg1.json")
				mode := os.FileMode(0600)
				state := filepath.Join(cfg.StateDir, "cg1-state", "grantcheck.json")
				var f *matrixFixture
				if policy == MatrixPolicy {
					var dir string
					f, dir, cfg = freshMatrixConfig(t)
					p = &f.cfg.grantPolicy
					path = filepath.Join(dir, matrixConfigName)
					mode = 0700
					state = filepath.Join(dir, "matrix-grantcheck-state", "grantcheck.json")
				} else {
					provision(t, cfg, s)
				}
				checker, err := admission.Open(policy, cfg)
				if err != nil {
					t.Fatal(err)
				}
				checker.Close()
				before, err := os.ReadFile(state)
				if err != nil {
					t.Fatal(err)
				}
				switch field {
				case "executor":
					p.ExecutorKey = xonly(8)
				case "age":
					*p.MaxTipAgeSeconds++
				case "skew":
					*p.MaxFutureSkewSeconds++
				case "floor":
					*p.MinimumHeight++
				}
				raw := jsonBytes(t, s)
				if f != nil {
					raw = jsonBytes(t, f.cfg)
				}
				if err = os.WriteFile(path, raw, mode); err != nil {
					t.Fatal(err)
				}
				checker, err = admission.Open(policy, cfg)
				if checker != nil {
					checker.Close()
				}
				if err == nil || checker != nil {
					t.Fatal("changed trust pins adopted")
				}
				after, err := os.ReadFile(state)
				if err != nil || string(before) != string(after) {
					t.Fatal("rejected rebind changed durable state")
				}
			})
		}
	}
}
