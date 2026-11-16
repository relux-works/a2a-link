//go:build linux

package originproducer

import (
	"sync/atomic"

	"github.com/relux-works/a2a-swarm/internal/daemon"
	"github.com/relux-works/a2a-swarm/runorigin"
)

// ServiceConfig is protected service configuration. It is not read from
// station flags, credentials, the environment or any caller of the endpoint.
type ServiceConfig struct {
	ControlDir  string
	Launcher    runorigin.Principal
	Generations runorigin.GenerationAuthority
	// MappingPath names the protected host mapping. Empty means no producer.
	MappingPath string
}

var constructed atomic.Bool

// originConfig links a producer only for a complete protected configuration:
// a mapping that passes every protection check and is pinned to the same
// launcher. Anything less leaves Producer as the nil interface, so the
// endpoint advertises no operation and answers origin_not_supported, exactly
// as a stock upstream endpoint does.
func originConfig(c ServiceConfig, owner uint32) (daemon.OriginConfig, bool) {
	cfg := daemon.OriginConfig{ControlDir: c.ControlDir, Launcher: c.Launcher, Generations: c.Generations}
	if c.MappingPath == "" {
		return cfg, false
	}
	p, err := newProducer(c.MappingPath, owner)
	if err != nil {
		return cfg, false
	}
	m, err := loadMapping(c.MappingPath, owner)
	if err != nil || m.Launcher != c.Launcher {
		return cfg, false
	}
	cfg.Producer = p
	return cfg, true
}

// NewOriginService is the single construction point of the origin endpoint.
// It builds one service per process, at process start. The second result
// reports whether a producer is linked; false is the refusing default. The
// caller decides whether and when to call Serve; nothing here starts it.
func NewOriginService(c ServiceConfig) (*daemon.OriginService, bool, error) {
	if !constructed.CompareAndSwap(false, true) {
		return nil, false, refuse(ReasonAlreadyConstructed)
	}
	cfg, enabled := originConfig(c, protectedOwner)
	service, err := daemon.NewOriginService(cfg)
	if err != nil {
		constructed.Store(false)
		return nil, false, err
	}
	return service, enabled, nil
}
