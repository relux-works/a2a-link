package cli

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"syscall"

	"github.com/relux-works/a2a-swarm/internal/admission"
	"github.com/relux-works/swarma-chain-lab/experiments/grantcheck"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
)

// The local protected identity configuration supplies authority. Proofs supply
// only public bytes; neither flags nor messages can change pins or policy.
func cmdCG1(ctx context.Context, a *App, args []string) error {
	if len(args) != 3 || args[0] != "provision" || args[1] != "--proof" || args[2] == "" {
		return usagef("usage: a2a cg1 provision --proof FILE")
	}
	if a.daemonEngine {
		return &admissionRefusal{reason: "denied"}
	}
	s, err := a.sessionMetadata()
	if err != nil {
		return err
	}
	if s.creds.AdmissionPolicy != "cg1-matrix" {
		return &admissionRefusal{reason: "policy_invalid"}
	}
	entry, err := os.Lstat(args[2])
	if err != nil || !entry.Mode().IsRegular() {
		return &admissionRefusal{reason: "invalid_presentation"}
	}
	f, err := os.OpenFile(args[2], os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return &admissionRefusal{reason: "invalid_presentation"}
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || !os.SameFile(entry, st) {
		return &admissionRefusal{reason: "invalid_presentation"}
	}
	raw, err := io.ReadAll(io.LimitReader(f, grantcheck.MaxPresentationBytes+1))
	if err != nil {
		return &admissionRefusal{reason: "invalid_presentation"}
	}
	// Even malformed/oversize bytes go through Provision for its refusal audit.
	id, _ := kernel.PresentationID(raw)
	p, ok := s.admission.checker.(interface {
		Provision(context.Context, grantcheck.Presentation) admission.Decision
	})
	if !ok {
		return &admissionRefusal{reason: "policy_invalid"}
	}
	s.admission.mu.Lock()
	d := admission.Normalize(p.Provision(ctx, grantcheck.Presentation{GrantID: id, Bytes: raw}), nil)
	s.admission.mu.Unlock()
	if err := json.NewEncoder(a.Stdout).Encode(struct {
		GrantID   string `json:"grant_id"`
		Result    string `json:"result"`
		Retryable bool   `json:"retryable"`
	}{id, d.Reason, d.Retryable}); err != nil {
		return err
	}
	if d.Verdict != admission.Live {
		return &admissionRefusal{reason: d.Reason}
	}
	return nil
}
