//go:build linux

package originproducer

import (
	"context"
	"os"
	"testing"

	"github.com/relux-works/a2a-swarm/runorigin"
)

type fixedGeneration uint64

func (g fixedGeneration) CurrentGeneration(context.Context, uint32) (uint64, error) {
	return uint64(g), nil
}

func (f *fixture) serviceConfig() ServiceConfig {
	return ServiceConfig{ControlDir: f.root, Launcher: fixtureLauncher, Generations: fixedGeneration(fixtureLauncher.Generation), MappingPath: f.mappingPath}
}

// Claim: the construction point links a producer only for a complete protected
// configuration. With no mapping path, a missing or malformed mapping, a
// mapping owned by another account or a mapping pinned to another launcher,
// the endpoint configuration carries the nil Producer interface, which is the
// stock upstream state that advertises no operation and answers
// origin_not_supported. The complete configuration beside them links one.
func TestServiceRefusingDefault(t *testing.T) {
	owner := uint32(os.Getuid())
	f := newFixture(t)
	cfg, enabled := originConfig(f.serviceConfig(), owner)
	if !enabled || cfg.Producer == nil || cfg.ControlDir != f.root || cfg.Launcher != fixtureLauncher || cfg.Generations == nil {
		t.Fatal("valid control: complete protected configuration linked no producer")
	}
	if _, ok := cfg.Producer.(*Producer); !ok {
		t.Fatal("valid control: linked producer is not the qualified producer")
	}
	cases := []struct {
		name   string
		change func(f *fixture, c *ServiceConfig, owner *uint32)
	}{
		{"no-mapping-path", func(_ *fixture, c *ServiceConfig, _ *uint32) { c.MappingPath = "" }},
		{"mapping-absent", func(f *fixture, _ *ServiceConfig, _ *uint32) {
			if err := os.Remove(f.mappingPath); err != nil {
				f.t.Fatal(err)
			}
		}},
		{"mapping-malformed", func(f *fixture, _ *ServiceConfig, _ *uint32) { f.writeMapping([]byte(`{"version":1}`)) }},
		{"mapping-owned-by-another-account", func(_ *fixture, _ *ServiceConfig, owner *uint32) { *owner++ }},
		{"mapping-for-another-launcher-uid", func(_ *fixture, c *ServiceConfig, _ *uint32) { c.Launcher.UID++ }},
		{"mapping-for-another-launcher-generation", func(_ *fixture, c *ServiceConfig, _ *uint32) { c.Launcher.Generation++ }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			c, trusted := f.serviceConfig(), owner
			if control, ok := originConfig(c, trusted); !ok || control.Producer == nil {
				t.Fatal("valid control: complete protected configuration linked no producer")
			}
			tc.change(f, &c, &trusted)
			cfg, enabled := originConfig(c, trusted)
			if enabled || cfg.Producer != nil {
				t.Fatal("an incomplete protected configuration linked a producer")
			}
			if cfg.ControlDir != c.ControlDir || cfg.Launcher != c.Launcher {
				t.Fatal("the refusing default changed the endpoint configuration")
			}
		})
	}
}

// Claim: the process builds one origin service. The first construction, here
// the refusing default without a mapping, succeeds; a second construction in
// the same process is refused; a failed construction does not consume the slot.
func TestServiceSingleConstruction(t *testing.T) {
	constructed.Store(false)
	t.Cleanup(func() { constructed.Store(false) })
	launcher := runorigin.Principal{UID: uint32(os.Geteuid()) + 1, Generation: 1}
	f := newFixture(t)
	if service, enabled, err := NewOriginService(ServiceConfig{ControlDir: f.root, Launcher: launcher}); err == nil || service != nil || enabled {
		t.Fatal("a configuration without generation authority was constructed")
	}
	service, enabled, err := NewOriginService(ServiceConfig{ControlDir: f.root, Launcher: launcher, Generations: fixedGeneration(1)})
	if err != nil || service == nil || enabled {
		t.Fatal("valid control: refusing default was not constructed", err)
	}
	again, enabled, err := NewOriginService(ServiceConfig{ControlDir: f.root, Launcher: launcher, Generations: fixedGeneration(1)})
	if err == nil || again != nil || enabled || ReasonOf(err) != ReasonAlreadyConstructed {
		t.Fatal("a second origin service was constructed in one process")
	}
}
