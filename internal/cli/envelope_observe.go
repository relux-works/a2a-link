package cli

import (
	"fmt"
	"strings"

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

// verificationField is generated metadata; peer body indentation is reserved for peer text.
// Callers place it before every peer-controlled header field, so the first
// verification token on a generated header line is always the observed one.
func verificationField(label string) string {
	if label == "" {
		return ""
	}
	return fmt.Sprintf(" verification=%q", sanitizeLine(label))
}

// verificationLead is verificationField for a position right after a generated
// prefix that already ends in a space.
func verificationLead(label string) string {
	if label == "" {
		return ""
	}
	return strings.TrimPrefix(verificationField(label), " ") + " "
}
