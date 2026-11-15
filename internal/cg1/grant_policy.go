package cg1

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math"
	"strings"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/grantcheck"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
)

// Host inputs only. Pointers distinguish explicit zero F/FLOOR from omission.
// This interim bench rule is superseded by LIP-0022; hidden age is A + F.
type grantPolicy struct {
	ExecutorKey          string `json:"executor_key"`
	MaxTipAgeSeconds     *int64 `json:"max_tip_age_seconds"`
	MaxFutureSkewSeconds *int64 `json:"max_future_skew_seconds"`
	MinimumHeight        *int64 `json:"minimum_height"`
	// Canonical unpadded base64url terms bytes indexed by their contract SHA256.
	Terms map[string]string `json:"terms"`
}

func (p grantPolicy) resolve() (*grantcheck.FreshnessPolicy, func(string) ([]byte, error), error) {
	if !validKey(p.ExecutorKey) || p.MaxTipAgeSeconds == nil || *p.MaxTipAgeSeconds <= 0 || *p.MaxTipAgeSeconds > math.MaxInt64/int64(time.Second) ||
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
		var pay rental.PayTermsV2
		if json.Unmarshal(raw, &pay) != nil {
			return nil, nil, errConfig
		}
		canonical, err := rental.EncodePayTermsV2(pay)
		if err != nil || !bytes.Equal(canonical, raw) {
			return nil, nil, errConfig
		}
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
func grantPolicyNames(raw []byte) bool {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return false
	}
	for _, field := range []string{"executor_key", "max_tip_age_seconds", "max_future_skew_seconds", "minimum_height", "terms"} {
		for name := range obj {
			if name != field && strings.EqualFold(name, field) {
				return false
			}
		}
		if len(obj[field]) == 0 || bytes.Equal(bytes.TrimSpace(obj[field]), []byte("null")) {
			return false
		}
	}
	return true
}
