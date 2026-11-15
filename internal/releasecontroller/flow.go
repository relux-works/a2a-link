// Package releasecontroller orders the complete shared release. Fixture ports
// exercise control flow; only the concrete production adapter owns live effects.
package releasecontroller

import (
	"context"
	"errors"
	"fmt"

	"github.com/relux-works/a2a-swarm/internal/sharedrelease"
)

const Hold = "combined-release-controller-not-integrated"

// ProductionReady stays false until a reviewed, machine-verifiable custody
// lease can fence main continuously with the selected CI authority.
const ProductionReady = false

type Request struct {
	Root          string
	Binding       sharedrelease.Binding
	SourceArchive string
	Epoch         int64
	Inputs        sharedrelease.AssemblyInputs
	Out           string
	BrewPrefix    string
}

type Receipt struct {
	Binding        sharedrelease.Binding `json:"binding"`
	ReleaseID      int64                 `json:"release_id"`
	Candidate      string                `json:"candidate"`
	ManifestSHA256 string                `json:"manifest_sha256"`
	CaskSHA256     string                `json:"cask_sha256"`
	Stages         []string              `json:"stages"`
}

// Operations are trusted code, never caller-controlled CLI flags. Every stage
// has one owner and every error prevents all later effects.
type operations interface {
	Admit(context.Context) error
	Lease(context.Context) error
	Assemble(context.Context) error
	SignManifest(context.Context) error
	DeriveCask(context.Context) error
	Consumer(context.Context) error
	CaptureCandidate(context.Context) error
	Publish(context.Context) (int64, error)
	Readback(context.Context, int64) error
}

// Run is the live boundary. A dry fixture cannot be promoted by setting an
// environment variable or injecting ports through this exported entry point.
func Run(ctx context.Context, r Request) (Receipt, error) {
	receipt := Receipt{Binding: r.Binding}
	if e := r.Binding.Validate(); e != nil {
		return receipt, e
	}
	if e := EventGate(); e != nil {
		return receipt, e
	}
	if !ProductionReady {
		return receipt, errors.New(Hold)
	}
	p := newProduction(r)
	defer p.Close()
	result, e := run(ctx, r.Binding, p)
	if p.candidate == r.Out && len(p.fingerprints) == 26 {
		result.Candidate = p.candidate
		result.ManifestSHA256 = p.fingerprints["release-assets.json"]
		result.CaskSHA256 = p.fingerprints["a2a.rb"]
	}
	return result, e
}

func run(ctx context.Context, b sharedrelease.Binding, ops operations) (Receipt, error) {
	receipt := Receipt{Binding: b, Stages: []string{}}
	if ops == nil {
		return receipt, errors.New("controller-operations-required")
	}
	stages := []struct {
		name string
		f    func(context.Context) error
	}{
		{"admission", ops.Admit}, {"lease-before-inputs", ops.Lease},
		{"producers-native-and-crossbuild", ops.Assemble}, {"signed-manifest", ops.SignManifest},
		{"cask-from-signed-manifest", ops.DeriveCask}, {"brew-consumer", ops.Consumer},
		{"captured-candidate", ops.CaptureCandidate}, {"readmission-before-draft", ops.Admit},
		{"lease-before-draft", ops.Lease},
	}
	for _, s := range stages {
		if e := ctx.Err(); e != nil {
			return receipt, e
		}
		if e := s.f(ctx); e != nil {
			return receipt, fmt.Errorf("%s: %w", s.name, e)
		}
		receipt.Stages = append(receipt.Stages, s.name)
	}
	if e := ctx.Err(); e != nil {
		return receipt, e
	}
	id, e := ops.Publish(ctx)
	receipt.ReleaseID = id
	if e != nil {
		return receipt, fmt.Errorf("publication: %w", e)
	}
	if id <= 0 {
		return receipt, errors.New("publication-id-required")
	}
	receipt.ReleaseID = id
	receipt.Stages = append(receipt.Stages, "single-publication")
	if e = ctx.Err(); e != nil {
		return receipt, e
	}
	if e = ops.Readback(ctx, id); e != nil {
		return receipt, fmt.Errorf("public-readback: %w", e)
	}
	receipt.Stages = append(receipt.Stages, "public-readback")
	if e = ctx.Err(); e != nil {
		return receipt, e
	}
	if e = ops.Admit(ctx); e != nil {
		return receipt, fmt.Errorf("readmission-after-readback: %w", e)
	}
	receipt.Stages = append(receipt.Stages, "readmission-after-readback")
	if e = ctx.Err(); e != nil {
		return receipt, e
	}
	if e = ops.Lease(ctx); e != nil {
		return receipt, fmt.Errorf("lease-through-readback: %w", e)
	}
	receipt.Stages = append(receipt.Stages, "lease-through-readback")
	return receipt, nil
}
