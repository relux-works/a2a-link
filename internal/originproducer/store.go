package originproducer

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/relux-works/a2a-swarm/internal/config"
	"github.com/relux-works/a2a-swarm/internal/matrix"
	"github.com/relux-works/a2a-swarm/runorigin"
)

// retainedEvent is what the agent's own store holds for one event reference.
type retainedEvent struct {
	Sender  string
	Content []byte
}

// eventStore reads a retained event by reference. The reference is the only
// value that originates from the launcher; the bytes never do.
type eventStore interface {
	retained(ctx context.Context, base, identity string, ref runorigin.EventRef) (retainedEvent, error)
}

// mailboxStore reads the durable mailbox of the mapped identity. An entry is
// retained there from admission until its receipt, so a received, redacted or
// never admitted event is absent.
type mailboxStore struct{}

func (mailboxStore) retained(ctx context.Context, base, identity string, ref runorigin.EventRef) (retainedEvent, error) {
	var zero retainedEvent
	if ctx == nil || ctx.Err() != nil {
		return zero, unavailable(ReasonCancelled)
	}
	if !matrix.ValidVerificationID(ref.RoomID, '!') || !matrix.ValidVerificationID(ref.EventID, '$') {
		return zero, refuse(ReasonEventAbsent)
	}
	mailbox, err := config.OpenMailbox(config.Paths{Base: base}, identity)
	if err != nil {
		return zero, refuse(ReasonEventAbsent)
	}
	entries := mailbox.InOrder([]string{ref.EventID})
	if len(entries) != 1 {
		return zero, refuse(ReasonEventAbsent)
	}
	entry := entries[0]
	if entry.ID != ref.EventID || entry.Room != ref.RoomID || entry.Kind != config.MailEvent || len(entry.Event) == 0 || !matrix.ValidVerificationID(entry.Sender, '@') {
		return zero, refuse(ReasonEventAbsent)
	}
	var event struct {
		Type    string          `json:"type"`
		Sender  string          `json:"sender"`
		Content json.RawMessage `json:"content"`
	}
	if json.Unmarshal(entry.Event, &event) != nil || event.Type != "m.room.message" || len(event.Content) == 0 || (event.Sender != "" && event.Sender != entry.Sender) {
		return zero, refuse(ReasonEventAbsent)
	}
	return retainedEvent{Sender: entry.Sender, Content: bytes.Clone(event.Content)}, nil
}
