// Package envelopeobserve labels received messages without admitting or refusing delivery.
package envelopeobserve

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/relux-works/a2a-swarm/internal/matrix"
	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-envelope/verifier"
)

const Unsigned = "unsigned (no envelope)"
const UnknownAuthor = "unknown-author"

// Observer contains a snapshot supplied by the host, never by the event.
// A verdict is observation only. No returned verifier plan is persisted or used.
type Observer struct {
	authors map[string]string // exact Matrix sender -> exact author key
	context verifier.Context
}

func invalid(reason string) string { return "invalid: " + reason }
func errorCode(err error) string {
	var e *record.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return "envelope_malformed"
}

// Observe checks the original content and body before any display sanitization.
// It performs no network, signing, mutation, receipts or authority decisions.
// A nil observer explicitly represents an unavailable host roster.
func (o *Observer) Observe(ev matrix.Event, room, recipient string, now time.Time) string {
	// First inspect presence; unsigned ordinary content keeps its existing semantics.
	// Strict parsing below prevents duplicate/alias/invalid-UTF8 content from verifying.
	var presence map[string]json.RawMessage
	if json.Unmarshal(ev.Content, &presence) != nil {
		return invalid("content_malformed")
	}
	if _, present := presence[matrix.EnvelopeContentKey]; !present {
		return Unsigned
	}
	if len(ev.Content) > matrix.EnvelopeEventContentBudget {
		return invalid("content_too_large")
	}
	content, err := record.Parse(ev.Content, matrix.EnvelopeEventContentBudget, 16)
	if err != nil {
		return invalid("content_malformed")
	}
	m, ok := content.(map[string]any)
	if !ok {
		return invalid("content_malformed")
	}
	value := m[matrix.EnvelopeContentKey]
	encoded, ok := value.(string)
	if !ok {
		return invalid("envelope_malformed")
	}
	raw, err := matrix.DecodeEnvelope(encoded)
	if err != nil {
		return invalid(matrix.RefusalCode(err))
	}
	parsed, err := record.Parse(raw, matrix.EnvelopeMaxBytes, 16)
	if err != nil {
		return invalid(errorCode(err))
	}
	envelope, ok := parsed.(map[string]any)
	if !ok {
		return invalid("envelope_malformed")
	}
	body, ok := envelope["body"].(map[string]any)
	if !ok {
		return invalid("envelope_malformed")
	}
	author, ok := body["author"].(string)
	if !ok || author == "" {
		return invalid("envelope_malformed")
	}
	if o == nil {
		return UnknownAuthor
	}
	expected, known := o.authors[ev.Sender]
	if !known {
		return UnknownAuthor
	}
	if expected != author {
		return invalid("author_mismatch")
	}
	text, ok := m["body"].(string)
	if !ok {
		return invalid("message_text_unavailable")
	}
	// Only exact spellings are interpreted; aliases cannot disagree with display decoding.
	for key := range m {
		if key != "body" && strings.EqualFold(key, "body") || key != matrix.EnvelopeContentKey && strings.EqualFold(key, matrix.EnvelopeContentKey) {
			return invalid("content_key_alias")
		}
	}
	if ev.IsRedacted() {
		return invalid("event_redacted")
	}
	c := o.context
	c.Now, err = verifier.Present(now.UTC().Format("2006-01-02T15:04:05Z"))
	if err != nil {
		return invalid("time_unavailable")
	}
	c.Delivery, err = verifier.Present(map[string]any{"room": room, "to": recipient, "text": []byte(text)})
	if err != nil {
		return invalid("message_context_unavailable")
	}
	result := verifier.New(c).VerifyMessage(raw)
	if result.Code != "accept" {
		return invalid(result.Code)
	}
	return "verified: " + ev.Sender
}
