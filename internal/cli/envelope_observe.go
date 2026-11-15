package cli

import (
	"github.com/relux-works/a2a-swarm/internal/config"
	"github.com/relux-works/a2a-swarm/internal/envelopeobserve"
)

// Load once per explicit read/inbox. Errors mean unknown authors, not failed mail.
// This is separate from delivery matching, mailbox persistence and wake admission.
func (a *App) envelopeObserver(s *session) *envelopeobserve.Observer {
	path := config.EnvelopeRosterPath(s.paths)
	load := envelopeobserve.Load
	if a.loadEnvelopeRoster != nil {
		load = a.loadEnvelopeRoster
	}
	observer, err := load(path)
	if err != nil {
		return nil
	}
	return observer
}
