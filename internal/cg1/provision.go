package cg1

import (
	"context"

	"github.com/relux-works/a2a-swarm/internal/admission"
	"github.com/relux-works/swarma-chain-lab/experiments/grantcheck"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

// Provision is local protected operator retrieval, never a message admission
// bypass. Grantcheck verifies the issuance commitment and all admission rules,
// atomically caches only Live proofs, and records a bounded durable audit.
func (c *matrixChecker) Provision(parent context.Context, p grantcheck.Presentation) admission.Decision {
	if c.closed.Load() {
		return deny("check_failed")
	}
	if parent == nil || parent.Err() != nil {
		return cancelled()
	}
	ctx, cancel := context.WithTimeout(parent, c.timeout)
	defer cancel()
	if c.life != nil {
		stop := context.AfterFunc(c.life, cancel)
		defer stop()
	}
	s, err := durable.Open(c.state, "matrix.lock")
	if err != nil {
		return matrixStorage()
	}
	defer s.Close()
	cfg, err := loadMatrixSettings(c.dir)
	if err != nil || matrixBinding(cfg) != c.binding {
		return deny("policy_invalid")
	}
	// Only the concrete production backend exposes this route; no test verdict
	// source or transport assertion substitutes for the protected constructor.
	core, ok := c.core.(*policyChecker)
	if !ok {
		return deny("check_failed")
	}
	ctx, answer := withNodeAnswer(ctx)
	return decision(answer.verdict(core.Provision(ctx, p)), false)
}
