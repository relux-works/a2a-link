package admission

import "time"

// TrustedNostrInbound is populated ONLY by the authenticated transport engine.
// This type does not authenticate its caller. Never unmarshal message content
// into it or derive Sender/Recipient from Message.To, rumor claims, or Matrix IDs.
// N2/N3 at a2a-transport-nostr 4ac03aed supplies Event.Sender (verified seal key),
// Event.ID (rumor ID), Event.Time and local Self().ID (the verified recipient).
// The private held queue may retain this projection with its authenticated event.
type TrustedNostrInbound struct {
	Sender    string    `json:"sender"`
	Recipient string    `json:"recipient"`
	EventID   string    `json:"event_id"`
	Time      time.Time `json:"time"`
	// Presentation is untrusted full grant-cert data extracted separately from
	// the authenticated message. Nil means absent; explicit malformed is not nil.
	Presentation *NostrPresentation `json:"presentation,omitempty"`
}

type NostrPresentation struct {
	GrantID string `json:"grant_id"`
	Bytes   []byte `json:"bytes"`
}

// TrustedNostrOutbound names ONE exact delivery target selected by the engine
// from the transport's validated conversation. Check each target again on every
// attempt, before signing/encryption/upload. No event ID exists before signing.
type TrustedNostrOutbound struct {
	Recipient string
}
