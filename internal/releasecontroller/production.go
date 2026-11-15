package releasecontroller

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/relux-works/a2a-swarm/internal/cask"
	"github.com/relux-works/a2a-swarm/internal/caskbrew"
	"github.com/relux-works/a2a-swarm/internal/darwinrelease"
	"github.com/relux-works/a2a-swarm/internal/sharedrelease"
)

type production struct {
	request                   Request
	work, platform, candidate string
	manifest                  sharedrelease.Manifest
	fingerprints              map[string]string
}

func newProduction(r Request) *production { return &production{request: r} }
func (p *production) Close() {
	if p.work != "" {
		_ = os.RemoveAll(p.work)
	}
}
func (p *production) Admit(ctx context.Context) error {
	a, e := darwinrelease.Admit(ctx, p.request.Root, p.request.Binding.Tag, p.request.Binding.TagObject)
	if e != nil {
		return e
	}
	if a.Commit != p.request.Binding.Commit {
		return errors.New("controller-source-admission")
	}
	return nil
}
func (p *production) Lease(context.Context) error {
	// A current-main comparison cannot establish an uninterrupted lease. Do not
	// substitute a polling loop or an unsigned operator flag for missing authority.
	return errors.New("custody-main-lease-contract-unavailable")
}
func (p *production) Assemble(ctx context.Context) error {
	r := p.request
	if r.Out == "" || r.SourceArchive == "" || r.Epoch <= 0 {
		return errors.New("controller-input-contract")
	}
	if _, e := os.Lstat(r.Out); !os.IsNotExist(e) {
		return errors.New("controller-output-exists")
	}
	var e error
	p.work, e = os.MkdirTemp(filepath.Dir(r.Out), ".a2a-combined-")
	if e != nil {
		return e
	}
	p.platform = filepath.Join(p.work, "platform")
	_, e = sharedrelease.AssembleInputs(ctx, r.Root, p.platform, r.SourceArchive, r.Binding, r.Epoch, r.Inputs)
	return e
}
func (p *production) SignManifest(ctx context.Context) error {
	r := p.request
	sealed := filepath.Join(p.work, "sealed")
	if e := sharedrelease.SealManifest(ctx, r.Binding, p.platform, sealed); e != nil {
		return e
	}
	p.candidate = filepath.Join(p.work, "candidate")
	if e := os.Mkdir(p.candidate, 0700); e != nil {
		return e
	}
	for _, n := range sharedrelease.FinalMembers(r.Binding.Version()) {
		if n == "a2a.rb" {
			continue
		}
		source := p.platform
		if n == "release-assets.json" || n == "release-assets.json.sig" || n == "release-assets.json.pem" {
			source = sealed
		}
		raw, e := os.ReadFile(filepath.Join(source, n))
		if e != nil {
			return e
		}
		if e = os.WriteFile(filepath.Join(p.candidate, n), raw, 0600); e != nil {
			return e
		}
	}
	return nil
}
func (p *production) DeriveCask(ctx context.Context) error {
	b := p.request.Binding
	raw, e := os.ReadFile(filepath.Join(p.candidate, "release-assets.json"))
	if e != nil {
		return e
	}
	p.manifest, e = sharedrelease.VerifyProduction(ctx, raw, filepath.Join(p.candidate, "release-assets.json.sig"), filepath.Join(p.candidate, "release-assets.json.pem"), p.candidate, b, nil)
	if e != nil {
		return e
	}
	ruby, e := cask.Render(p.manifest.Cask())
	if e != nil {
		return e
	}
	return os.WriteFile(filepath.Join(p.candidate, "a2a.rb"), ruby, 0600)
}
func (p *production) Consumer(ctx context.Context) error {
	ruby, e := os.ReadFile(filepath.Join(p.candidate, "a2a.rb"))
	if e != nil {
		return e
	}
	return caskbrew.Evaluate(ctx, p.request.BrewPrefix, ruby, p.manifest.Cask())
}
func (p *production) CaptureCandidate(ctx context.Context) error {
	if e := sharedrelease.VerifyCandidate(ctx, p.request.Binding, p.candidate, nil); e != nil {
		return e
	}
	p.fingerprints = map[string]string{}
	for _, n := range sharedrelease.FinalMembers(p.request.Binding.Version()) {
		raw, e := os.ReadFile(filepath.Join(p.candidate, n))
		if e != nil {
			return e
		}
		p.fingerprints[n] = sharedrelease.Hash(raw)
	}
	// Preserve the complete authenticated candidate before any draft mutation,
	// including an ambiguous result. Private failed preparation remains temporary.
	if e := os.Rename(p.candidate, p.request.Out); e != nil {
		return e
	}
	p.candidate = p.request.Out
	return nil
}
func (p *production) gate(ctx context.Context, captured string) error {
	if e := p.Admit(ctx); e != nil {
		return e
	}
	if e := p.Lease(ctx); e != nil {
		return e
	}
	if e := sharedrelease.VerifyCandidate(ctx, p.request.Binding, captured, nil); e != nil {
		return e
	}
	for _, n := range sharedrelease.FinalMembers(p.request.Binding.Version()) {
		raw, e := os.ReadFile(filepath.Join(captured, n))
		if e != nil || p.fingerprints[n] != sharedrelease.Hash(raw) {
			return errors.New("controller-candidate-changed")
		}
	}
	return nil
}
func (p *production) Publish(ctx context.Context) (int64, error) {
	r := p.request
	return darwinrelease.PublishPreparedAssetsWithID(ctx, r.Root, r.Binding.Tag, r.Binding.TagObject, p.candidate, sharedrelease.FinalMembers(r.Binding.Version()),
		"Combined Darwin arm64 and Linux amd64/arm64 release. checksums.txt covers the original Darwin archive and evidence; linux-checksums.txt covers Linux packages, archives, SBOMs and evidence. release-assets.json is the signed platform-only aggregate; a2a.rb is derived from it. Installation/adoption and manual tap delivery remain separate.", p.gate)
}
func (p *production) Readback(ctx context.Context, id int64) error {
	if e := sharedrelease.PublicReadback(ctx, p.request.Binding, p.candidate); e != nil {
		return e
	}
	state, e := sharedrelease.ReconcileCandidate(ctx, p.request.Binding, id, p.candidate)
	if e != nil {
		return e
	}
	if state != "public" {
		return errors.New("controller-public-readback-state")
	}
	return nil
}
