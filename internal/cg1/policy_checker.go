package cg1

import (
	"context"
	"encoding/json"

	"github.com/relux-works/swarma-chain-lab/experiments/grantcheck"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// policyChecker is constructed identically for Matrix, origin and Nostr. Only
// the protected policy selects the contract profile and the chain binding.
// Version 1 retains its existing backend-only node checks and durable pins.
type policyChecker struct {
	core             *grantcheck.Checker
	node             su.Node
	network, genesis string
	explicit         bool
}

func newPolicyChecker(p grantPolicy, cfg grantcheck.Config, transport grantcheck.Transport) (*policyChecker, error) {
	profile, network, genesis, ok := p.binding()
	if !ok {
		return nil, errConfig
	}
	freshness, terms, err := p.resolve()
	if err != nil {
		return nil, err
	}
	cfg.ContractProfile, cfg.Network, cfg.Genesis = profile, network, genesis
	cfg.ExecutorKey, cfg.Freshness, cfg.Terms = p.ExecutorKey, freshness, terms
	core, err := grantcheck.NewForTransport(cfg, transport)
	if err != nil {
		return nil, errConfig
	}
	return &policyChecker{core: core, node: cfg.Node, network: network, genesis: genesis, explicit: p.Profile != ""}, nil
}

// preflight compares both independently observed node pins before any grant
// check, on every new-version call. It never substitutes one pin for the other.
// As in CG1's chain observation and GENESIS mapping, a wrong node is unavailable,
// not a grant binding mismatch.
func (c *policyChecker) preflight(ctx context.Context) *grantcheck.Verdict {
	code := grantcheck.CodeLive
	if ctx == nil || ctx.Err() != nil {
		code = grantcheck.CodeCancelled
	} else if c.explicit {
		raw, err := c.node.Call(ctx, "getblockchaininfo")
		var info struct {
			Chain string `json:"chain"`
		}
		if err != nil || json.Unmarshal(raw, &info) != nil || info.Chain == "" {
			code = grantcheck.CodeVerifierUnavailable
		} else if info.Chain != c.network {
			code = grantcheck.CodeVerifierUnavailable
		} else {
			raw, err = c.node.Call(ctx, "getblockhash", 0)
			var genesis string
			if err != nil || json.Unmarshal(raw, &genesis) != nil || !validID(genesis) {
				code = grantcheck.CodeVerifierUnavailable
			} else if genesis != c.genesis {
				code = grantcheck.CodeVerifierUnavailable
			}
		}
	}
	if ctx != nil && ctx.Err() != nil {
		code = grantcheck.CodeCancelled
	}
	if code == grantcheck.CodeLive {
		return nil
	}
	return &grantcheck.Verdict{Decision: grantcheck.Refused, Code: code, Retryable: code == grantcheck.CodeVerifierUnavailable || code == grantcheck.CodeCancelled}
}

func (c *policyChecker) Inbound(ctx context.Context, sender string, p *grantcheck.Presentation) grantcheck.Verdict {
	if v := c.preflight(ctx); v != nil {
		return *v
	}
	return c.core.Inbound(ctx, sender, p)
}
func (c *policyChecker) Outbound(ctx context.Context, recipient string) grantcheck.Verdict {
	if v := c.preflight(ctx); v != nil {
		return *v
	}
	return c.core.Outbound(ctx, recipient)
}
func (c *policyChecker) InboundFrom(ctx context.Context, sender grantcheck.SenderProof, p *grantcheck.Presentation) grantcheck.Verdict {
	if v := c.preflight(ctx); v != nil {
		return *v
	}
	return c.core.InboundFrom(ctx, sender, p)
}
func (c *policyChecker) OutboundFrom(ctx context.Context, recipient grantcheck.RecipientProof) grantcheck.Verdict {
	if v := c.preflight(ctx); v != nil {
		return *v
	}
	return c.core.OutboundFrom(ctx, recipient)
}
func (c *policyChecker) Provision(ctx context.Context, p grantcheck.Presentation) grantcheck.Verdict {
	if v := c.preflight(ctx); v != nil {
		return *v
	}
	return c.core.Provision(ctx, p)
}
