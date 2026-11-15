package cli

import (
	"context"
	"errors"
	"io"
	"slices"
	"time"

	"github.com/relux-works/a2a-swarm/internal/config"
	"github.com/relux-works/a2a-swarm/internal/matrix"
)

// Seen by: after `a2a inbox` the agent's account places a public m.read receipt
// in a room, on the latest event up to which every earlier entry of that room
// reached the session in full (config.ReadReceipts). A truncated print, an
// ack, a wait/watch line, a hook notice or a gap is not delivery. A receipt
// failure never changes mail: the ledger is written under the delivery lock,
// the receipt is posted after the lock is released, bounded and silent, and a
// failed attempt is retried by the next inbox.

// readReceiptBudget bounds all receipt attempts of one command; one request
// is bounded by readReceiptCallMax.
var (
	readReceiptBudget  = 5 * time.Second
	readReceiptCallMax = 3 * time.Second
	// readReceiptQuarantine holds a room after an attempt with no definite
	// homeserver answer, which the homeserver may still apply later.
	readReceiptQuarantine = 2 * time.Minute
)

// fullyPrinted reports whether inbox's frame or JSON line carries the
// complete body of it.
func fullyPrinted(it waitItem, server string) bool {
	if it.ev == nil || it.gap != nil {
		return false
	}
	_, cut := inboxRecord(it, server)
	return cut == 0
}

// briefDelivered reports whether the brief inlined the complete body of it.
// A summary excerpt never counts: it is folded to one line before --width
// applies, so even an uncut excerpt is not the full body.
func briefDelivered(it waitItem, inline bool) bool {
	return inline && it.ev != nil && it.gap == nil
}

// noteDelivered records, inside the delivery transaction and BEFORE the
// mailbox receipt, which of entries reached the session in full. A ledger
// that cannot be read or written only withholds receipts.
func (s *session) noteDelivered(mb *config.Mailbox, entries []config.MailEntry, done map[string]bool) {
	if len(entries) == 0 {
		return
	}
	r, err := config.LoadReadReceipts(s.paths, s.name)
	if err != nil {
		return
	}
	r.NoteReceived(mb, entries, func(e config.MailEntry) bool { return done[e.ID] })
	_ = config.SaveReadReceipts(s.paths, s.name, r)
}

// noteFullPrint completes ledger marks for events `a2a read --event` printed
// in full, after a successful write and flush. Only marks already in the
// ledger change, each on its own. It takes the lock only when room has marks.
func noteFullPrint(ctx context.Context, paths config.Paths, name, room string, ids []string) bool {
	if len(ids) == 0 {
		return false
	}
	if r, err := config.LoadReadReceipts(paths, name); err != nil || r.Rooms[room] == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), readReceiptCallMax)
	defer cancel()
	changed := false
	_ = config.UpdateReadReceipts(ctx, paths, name, func(r *config.ReadReceipts, _ *config.Mailbox) (bool, error) {
		changed = r.NoteFullPrint(room, ids)
		return changed, nil
	})
	return changed
}

// sendReadReceipts posts the receipts the ledger now allows. It holds no lock
// across HTTP, prints nothing and returns nothing: mail is already done.
func (s *session) sendReadReceipts(ctx context.Context) {
	if s.client == nil {
		return
	}
	if r, err := config.LoadReadReceipts(s.paths, s.name); err != nil || len(r.Rooms) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readReceiptBudget)
	defer cancel()
	var want map[string]string
	var rooms []string
	now := s.app.Now()
	// The claim outlives this command's attempts, so a competing command never
	// sends an older target for the same room meanwhile.
	until := now.Add(readReceiptBudget + readReceiptCallMax).UnixMilli()
	if err := config.UpdateReadReceipts(ctx, s.paths, s.name, func(r *config.ReadReceipts, mb *config.Mailbox) (bool, error) {
		wasBroken := r.Broken
		want = r.Claim(mb, now.UnixMilli(), until)
		rooms = r.Order(want)
		return len(want) > 0 || r.Broken != wasBroken, nil
	}); err != nil || len(want) == 0 {
		return
	}
	accepted, definite := map[string]bool{}, map[string]bool{}
	tried := []string{}
	for _, room := range rooms {
		if ctx.Err() != nil {
			break
		}
		call, done := context.WithTimeout(ctx, readReceiptCallMax)
		err := s.client.SendReadReceipt(call, room, want[room])
		done()
		tried = append(tried, room)
		accepted[room] = err == nil
		var refused *matrix.Error
		definite[room] = err == nil || errors.As(err, &refused) || errors.Is(err, matrix.ErrAuth)
	}
	quarantine := s.app.Now().Add(readReceiptQuarantine).UnixMilli()
	record, stop := context.WithTimeout(context.WithoutCancel(ctx), readReceiptCallMax)
	defer stop()
	_ = config.UpdateReadReceipts(record, s.paths, s.name, func(r *config.ReadReceipts, _ *config.Mailbox) (bool, error) {
		for room := range want {
			if !slices.Contains(tried, room) {
				r.Release(room, want[room])
			}
		}
		for _, room := range tried {
			r.Attempted(room, now.UnixMilli())
			switch {
			case accepted[room]:
				r.Accepted(room, want[room])
			case definite[room]:
				r.Failure(room, want[room])
			default:
				r.Uncertain(room, want[room], quarantine)
			}
		}
		return true, nil
	})
}

// trackedWriter remembers the first failed or short write, so a print that
// did not fully reach the session is never counted as delivery.
type trackedWriter struct {
	w   io.Writer
	err error
}

func (t *trackedWriter) Write(p []byte) (int, error) {
	if t.err != nil {
		return 0, t.err
	}
	n, err := t.w.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		t.err = err
	}
	return n, err
}

// flush flushes the underlying writer, if it buffers, and reports any failure.
func (t *trackedWriter) flush() error {
	if t.err != nil {
		return t.err
	}
	if f, ok := t.w.(interface{ Flush() error }); ok {
		if err := f.Flush(); err != nil {
			t.err = err
		}
	}
	return t.err
}
