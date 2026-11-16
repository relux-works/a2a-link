package cg1

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math"
	"strings"
	"time"

	"github.com/relux-works/a2a-swarm/internal/matrix"
	"github.com/relux-works/swarma-chain-lab/experiments/grantcheck"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Host inputs only. Pointers distinguish explicit zero F/FLOOR from omission.
// This interim bench rule is superseded by LIP-0022; hidden age is A + F.
type grantPolicy struct {
	// Omission preserves the version-1 serialization and durable Matrix binding.
	Profile              string `json:"profile,omitempty"`
	Network              string `json:"network,omitempty"`
	Genesis              string `json:"genesis,omitempty"`
	ExecutorKey          string `json:"executor_key"`
	MaxTipAgeSeconds     *int64 `json:"max_tip_age_seconds"`
	MaxFutureSkewSeconds *int64 `json:"max_future_skew_seconds"`
	MinimumHeight        *int64 `json:"minimum_height"`
	// Canonical unpadded base64url terms bytes indexed by their contract SHA256.
	Terms map[string]string `json:"terms"`
}

// binding is the only compatibility default. Version 2 is checked for all
// three exact members before this function can be used by a factory.
func (p grantPolicy) binding() (profile, network, genesis string, ok bool) {
	if p.Profile == "" && p.Network == "" && p.Genesis == "" {
		return grantcheck.ContractProfilePay, "regtest", su.RegtestGenesis, true
	}
	if p.Profile != grantcheck.ContractProfilePay && p.Profile != grantcheck.ContractProfileTrust {
		return "", "", "", false
	}
	ok = (p.Network == "regtest" && p.Genesis == su.RegtestGenesis) ||
		(p.Network == "main" && p.Genesis == grantcheck.MainGenesis)
	return p.Profile, p.Network, p.Genesis, ok
}

func (p grantPolicy) resolve() (*grantcheck.FreshnessPolicy, func(string) ([]byte, error), error) {
	profile, _, _, bound := p.binding()
	if !bound || (profile == grantcheck.ContractProfilePay && !validKey(p.ExecutorKey)) ||
		(profile == grantcheck.ContractProfileTrust && p.ExecutorKey != "") || p.MaxTipAgeSeconds == nil || *p.MaxTipAgeSeconds <= 0 || *p.MaxTipAgeSeconds > math.MaxInt64/int64(time.Second) ||
		p.MaxFutureSkewSeconds == nil || *p.MaxFutureSkewSeconds < 0 || *p.MaxFutureSkewSeconds > 600 ||
		p.MinimumHeight == nil || *p.MinimumHeight < 0 || *p.MinimumHeight > math.MaxInt32 || len(p.Terms) == 0 || len(p.Terms) > 64 {
		return nil, nil, errConfig
	}
	terms := make(map[string][]byte, len(p.Terms))
	for hash, encoded := range p.Terms {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err != nil || len(raw) == 0 || len(raw) > grantcheck.MaxPresentationBytes || base64.RawURLEncoding.EncodeToString(raw) != encoded || rental.Hash(raw) != hash {
			return nil, nil, errConfig
		}
		if profile == grantcheck.ContractProfilePay {
			var pay rental.PayTermsV2
			if json.Unmarshal(raw, &pay) != nil {
				return nil, nil, errConfig
			}
			canonical, err := rental.EncodePayTermsV2(pay)
			if err != nil || !bytes.Equal(canonical, raw) {
				return nil, nil, errConfig
			}
		}
		// Trust contracts are judged and bound to the presented grant by CG1,
		// not by a second consumer-side implementation of its internal parser.
		terms[hash] = bytes.Clone(raw)
	}
	skew, floor := time.Duration(*p.MaxFutureSkewSeconds)*time.Second, *p.MinimumHeight
	policy := &grantcheck.FreshnessPolicy{MaxTipAge: time.Duration(*p.MaxTipAgeSeconds) * time.Second, MaxFutureSkew: &skew, MinimumHeight: &floor}
	lookup := func(hash string) ([]byte, error) {
		raw, ok := terms[hash]
		if !ok {
			return nil, errConfig
		}
		return bytes.Clone(raw), nil
	}
	return policy, lookup, nil
}

// encoding/json aliases cannot supply a missing protected policy field.
func grantPolicyNames(raw []byte, version int) bool {
	if version == 2 {
		if _, err := matrix.ParseStrictJSON(raw); err != nil {
			return false
		}
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return false
	}
	fields := []string{"executor_key", "max_tip_age_seconds", "max_future_skew_seconds", "minimum_height", "terms"}
	switch version {
	case 1:
		for name := range obj {
			for _, field := range []string{"profile", "network", "genesis"} {
				if strings.EqualFold(name, field) {
					return false
				}
			}
		}
	case 2:
		fields = append(fields, "profile", "network", "genesis")
	default:
		return false
	}
	for _, field := range fields {
		for name := range obj {
			if name != field && strings.EqualFold(name, field) {
				return false
			}
		}
		if len(obj[field]) == 0 || bytes.Equal(bytes.TrimSpace(obj[field]), []byte("null")) ||
			((field == "profile" || field == "network" || field == "genesis") && bytes.Equal(bytes.TrimSpace(obj[field]), []byte(`""`))) {
			return false
		}
	}
	return true
}
