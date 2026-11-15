package config

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
)

// Read receipts ("Seen by") are public m.read markers an agent places only
// after real delivery. The ledger (state/<name>.read-receipts.json, mode 0600)
// records, per room, the mailbox entries this identity received in receipt
// order and whether each one reached the session in full. It is written under
// the state lock BEFORE the mailbox receipt, so an interruption can only leave
// a mark for an entry that is still pending (printed again later), never a
// received entry without its mark.
//
// The receipt target of a room is the last mark of its leading run of fully
// delivered marks whose earlier same-room mailbox entries were all received
// when it was marked (Waits). A truncated, acked or gap entry stops the run
// until it is completed (a full print of that event), so a receipt never covers
// an entry that did not reach the session. Entries received before this ledger
// existed are the baseline and are not judged.
//
// The ledger never grants or withholds delivery: it is consulted only to
// decide whether a receipt may be sent.

// ReadReceiptLogMax bounds the marks kept per room.
const ReadReceiptLogMax = 512

// readReceiptWaitsMax bounds the earlier pending ids recorded for one mark;
// more freezes the room, since the mark's timeline position is then unknown.
const readReceiptWaitsMax = ReadReceiptLogMax

// ReadReceiptMark is one received mailbox entry of a room.
type ReadReceiptMark struct {
	ID string `json:"id"`
	// Done: the complete body reached the session (an untruncated print).
	Done bool `json:"done,omitempty"`
	// Gap: a gap record; the events it stands for were never delivered.
	Gap bool `json:"gap,omitempty"`
	// Waits are same-room entries appended to the mailbox before this one that
	// were still pending (or hidden from this view) when it was received. They
	// are earlier in the room's timeline: a later mark of any of them goes
	// before this mark, and nothing at or past this mark is a target while any
	// of them is still pending.
	Waits []string `json:"waits,omitempty"`
}

// ReadReceiptRoom is the ledger of one room.
type ReadReceiptRoom struct {
	// Sent is the last event the homeserver accepted a receipt for.
	Sent string `json:"sent,omitempty"`
	// Log holds the marks after Sent in the room's mailbox (timeline) order,
	// whatever order they were received in.
	Log []ReadReceiptMark `json:"log,omitempty"`
	// Frozen: the log overflowed with undelivered marks only; no further
	// receipt is sent in this room.
	Frozen bool `json:"frozen,omitempty"`
	// Failed counts consecutive failed receipt attempts.
	Failed int `json:"failed,omitempty"`
	// Tried is when a receipt was last attempted in this room (Unix ms); the
	// least recently tried room goes first, so a hanging room cannot starve
	// the others.
	Tried int64 `json:"tried,omitempty"`
	// Claim is the event one command is sending until ClaimUntil (Unix ms);
	// a competing command skips the room meanwhile, so two senders never race
	// an older receipt past a newer one.
	Claim      string `json:"claim,omitempty"`
	ClaimUntil int64  `json:"claim_until,omitempty"`
}

// ReadReceipts is the ledger of one identity.
type ReadReceipts struct {
	Rooms map[string]*ReadReceiptRoom `json:"rooms,omitempty"`
	// Before and Last bracket the newest mailbox receipt this ledger noted:
	// the receipt index ended at Before when the batch was noted, and ends at
	// Last once that batch is received. Any other newest receipt means
	// entries were received without a ledger mark (a failed ledger write, an
	// older binary): their disposition is unknown, so the ledger is Broken.
	Before string `json:"before,omitempty"`
	Last   string `json:"last,omitempty"`
	Noted  bool   `json:"noted,omitempty"`
	// Broken: no receipt is ever sent again from this ledger. Recovery is an
	// explicit new baseline (removing the ledger file).
	Broken bool `json:"broken,omitempty"`
}

// verify marks the ledger Broken when the mailbox received entries that the
// ledger never noted. It returns whether the ledger may still be used.
func (r *ReadReceipts) verify(mb *Mailbox) bool {
	if r.Broken {
		return false
	}
	if !r.Noted {
		return true
	}
	got := mb.LastReceived()
	switch {
	case got == r.Last:
	case got == r.Before && r.Last != r.Before && mb.Live(r.Last):
		// The noted batch was not received (an interrupted inbox): consistent.
	default:
		r.Broken = true
		return false
	}
	return true
}

// Verify is verify for callers that persist the result.
func (r *ReadReceipts) Verify(mb *Mailbox) bool { return r.verify(mb) }

// ReadReceiptsFile is the ledger file of name.
func (p Paths) ReadReceiptsFile(name string) string {
	return filepath.Join(p.Base, "state", name+".read-receipts.json")
}

// ReadReceiptsMarkerFile records that the ledger of name was created. A ledger
// that is missing while its marker exists was lost after it began judging
// deliveries, so it is broken, never a new baseline.
func (p Paths) ReadReceiptsMarkerFile(name string) string {
	return filepath.Join(p.Base, "state", name+".read-receipts.init")
}

// LoadReadReceipts reads the ledger; a missing file is an empty ledger, unless
// its marker shows it existed (then it is broken). Anything but a regular 0600
// file with a valid ledger is refused.
func LoadReadReceipts(p Paths, name string) (*ReadReceipts, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	path := p.ReadReceiptsFile(name)
	r := &ReadReceipts{Rooms: map[string]*ReadReceiptRoom{}}
	if err := checkSecretFile(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			if _, merr := os.Lstat(p.ReadReceiptsMarkerFile(name)); !errors.Is(merr, fs.ErrNotExist) {
				r.Broken, r.Noted = true, true
			}
			return r, nil
		}
		return nil, fmt.Errorf("read receipts: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read receipts: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(r); err != nil {
		return nil, fmt.Errorf("read receipts: %w", err)
	}
	if r.Rooms == nil {
		r.Rooms = map[string]*ReadReceiptRoom{}
	}
	for room, rr := range r.Rooms {
		if room == "" || rr == nil {
			return nil, errors.New("read receipts: malformed room entry")
		}
	}
	return r, nil
}

// SaveReadReceipts atomically replaces the ledger (mode 0600).
func SaveReadReceipts(p Paths, name string, r *ReadReceipts) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	path := p.ReadReceiptsFile(name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		if err := checkSecretFile(path); err != nil {
			return fmt.Errorf("read receipts: %w", err)
		}
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	// The marker exists before the first ledger does, and is never removed by a2a.
	marker := p.ReadReceiptsMarkerFile(name)
	if f, err := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL|openNoFollow, SecretFileMode); err == nil {
		if err := f.Sync(); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("read receipts: %w", err)
	}
	return writeSecretAtomic(path, name+".read-receipts", append(data, '\n'))
}

// UpdateReadReceipts runs fn on the ledger and the mailbox under the state lock
// (state/<name>.lock, bounded by ctx), without touching the state file, and
// saves the ledger when fn reports a change.
func UpdateReadReceipts(ctx context.Context, p Paths, name string, fn func(*ReadReceipts, *Mailbox) (bool, error)) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	dir := filepath.Dir(p.StateFile(name))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	unlock, err := lockFileContext(ctx, filepath.Join(dir, name+".lock"))
	if err != nil {
		return err
	}
	defer unlock()
	// Mailbox first: the ledger is written before any receipt, so a ledger read
	// after the mailbox knows every entry that mailbox shows as received.
	mb, err := OpenMailbox(p, name)
	if err != nil {
		return err
	}
	r, err := LoadReadReceipts(p, name)
	if err != nil {
		return err
	}
	changed, err := fn(r, mb)
	if err != nil || !changed {
		return err
	}
	return SaveReadReceipts(p, name, r)
}

func (r *ReadReceipts) room(id string) *ReadReceiptRoom {
	rr := r.Rooms[id]
	if rr == nil {
		rr = &ReadReceiptRoom{}
		r.Rooms[id] = rr
	}
	return rr
}

// NoteReceived records the entries about to be received, in mailbox order.
// done reports whether an event entry's complete body reached the session.
// It must run before mb.Receive of the same entries (Waits reads the live set).
// Invites are not room events and carry no mark.
//
// entries must be in the order the caller passes their ids to mb.Receive: the
// expected newest receipt (Last) is derived from it.
func (r *ReadReceipts) NoteReceived(mb *Mailbox, entries []MailEntry, done func(MailEntry) bool) {
	if !r.verify(mb) {
		return
	}
	batch := map[string]bool{}
	ids := make([]string, 0, len(entries))
	before := mb.LastReceived()
	last := before
	for _, e := range entries {
		if !batch[e.ID] && mb.Live(e.ID) {
			last = e.ID
		}
		batch[e.ID] = true
		ids = append(ids, e.ID)
	}
	r.Before, r.Last, r.Noted = before, last, true
	for _, e := range mb.InOrder(ids) {
		if e.Kind != MailEvent && e.Kind != MailGap {
			continue
		}
		rr := r.room(e.Room)
		if rr.Frozen {
			continue
		}
		mark := ReadReceiptMark{ID: e.ID, Gap: e.Kind == MailGap}
		mark.Done = e.Kind == MailEvent && done(e)
		if i := rr.index(e.ID); i >= 0 {
			// Printed again (an interrupted earlier receipt): keep the stronger fact.
			rr.Log[i].Done = rr.Log[i].Done || mark.Done
			continue
		}
		cut := false
		for _, w := range mb.earlierLive(e.Room, e.ID) {
			// Earlier entries of this same batch are marked first, in order.
			if batch[w] {
				continue
			}
			if len(mark.Waits) == readReceiptWaitsMax {
				cut = true
				break
			}
			mark.Waits = append(mark.Waits, w)
		}
		if cut {
			rr.Frozen, rr.Log = true, nil
			continue
		}
		rr.insert(mark)
		rr.bound()
	}
}

// NoteFullPrint marks entries whose complete body an explicit read printed
// (`a2a read`, `a2a inbox show`). Only marks already in the ledger change.
// It returns whether any mark changed.
func (r *ReadReceipts) NoteFullPrint(room string, ids []string) bool {
	rr := r.Rooms[room]
	if rr == nil {
		return false
	}
	changed := false
	for _, id := range ids {
		if i := rr.index(id); i >= 0 && !rr.Log[i].Gap && !rr.Log[i].Done {
			rr.Log[i].Done = true
			changed = true
		}
	}
	return changed
}

// insert places mark in timeline order. The log is kept sorted: a mark that
// is already in the log and comes later in the room's timeline was received
// while this entry was still pending, so it lists this entry in its Waits;
// marks earlier in the timeline never do. So the new mark goes just before
// the first mark that waits on it, or last.
func (rr *ReadReceiptRoom) insert(mark ReadReceiptMark) {
	for i, m := range rr.Log {
		if slices.Contains(m.Waits, mark.ID) {
			rr.Log = slices.Insert(rr.Log, i, mark)
			return
		}
	}
	rr.Log = append(rr.Log, mark)
}

func (rr *ReadReceiptRoom) index(id string) int {
	for i, m := range rr.Log {
		if m.ID == id {
			return i
		}
	}
	return -1
}

// bound keeps the log within ReadReceiptLogMax. Dropping a delivered mark never
// widens a receipt: a target needs only the marks before it to be delivered,
// and an id absent from both the log and the mailbox counts as received and
// delivered. Undelivered marks are never dropped; a log of only those freezes.
func (rr *ReadReceiptRoom) bound() {
	for len(rr.Log) > ReadReceiptLogMax {
		dropped := false
		for i, m := range rr.Log {
			if m.Done {
				rr.Log = append(rr.Log[:i], rr.Log[i+1:]...)
				dropped = true
				break
			}
		}
		if !dropped {
			rr.Frozen = true
			rr.Log = nil
			return
		}
	}
}

// Target returns the event a receipt may now cover in room, or "" when it
// may not advance past Sent.
func (r *ReadReceipts) Target(mb *Mailbox, room string) string {
	rr := r.Rooms[room]
	if rr == nil || rr.Frozen || !r.verify(mb) {
		return ""
	}
	undelivered := map[string]bool{}
	for _, m := range rr.Log {
		if !m.Done {
			undelivered[m.ID] = true
		}
	}
	target := ""
walk:
	for _, m := range rr.Log {
		if !m.Done {
			break
		}
		for _, w := range m.Waits {
			// A pending earlier entry precedes this mark and everything after it.
			if mb.Live(w) || undelivered[w] {
				break walk
			}
		}
		target = m.ID
	}
	if target == rr.Sent {
		return ""
	}
	return target
}

// Claim returns room -> event for every room whose receipt may advance and
// that no other command is sending, and claims each until (Unix ms).
func (r *ReadReceipts) Claim(mb *Mailbox, now, until int64) map[string]string {
	out := map[string]string{}
	if !r.verify(mb) {
		return out
	}
	rooms := make([]string, 0, len(r.Rooms))
	for room := range r.Rooms {
		rooms = append(rooms, room)
	}
	sort.Strings(rooms)
	for _, room := range rooms {
		rr := r.Rooms[room]
		if rr.Claim != "" && rr.ClaimUntil > now {
			continue
		}
		if t := r.Target(mb, room); t != "" {
			out[room] = t
			rr.Claim, rr.ClaimUntil = t, until
		}
	}
	return out
}

// Order returns the claimed rooms least recently tried first (then by id),
// so every room is eventually attempted even when others keep hanging.
func (r *ReadReceipts) Order(claimed map[string]string) []string {
	rooms := make([]string, 0, len(claimed))
	for room := range claimed {
		rooms = append(rooms, room)
	}
	sort.Slice(rooms, func(i, j int) bool {
		a, b := r.Rooms[rooms[i]], r.Rooms[rooms[j]]
		if a.Tried != b.Tried {
			return a.Tried < b.Tried
		}
		return rooms[i] < rooms[j]
	})
	return rooms
}

// Attempted records that a receipt was attempted in room at now (Unix ms).
func (r *ReadReceipts) Attempted(room string, now int64) {
	if rr := r.Rooms[room]; rr != nil {
		rr.Tried = now
	}
}

// Release ends this command's claim on room for event (a later claim stays).
func (r *ReadReceipts) Release(room, event string) {
	if rr := r.Rooms[room]; rr != nil && rr.Claim == event {
		rr.Claim, rr.ClaimUntil = "", 0
	}
}

// Accepted records that the homeserver accepted a receipt for event in room:
// the marks up to and including it leave the log.
func (r *ReadReceipts) Accepted(room, event string) {
	rr := r.Rooms[room]
	if rr == nil {
		return
	}
	i := rr.index(event)
	if i < 0 {
		return
	}
	rr.Sent = event
	rr.Log = append([]ReadReceiptMark(nil), rr.Log[i+1:]...)
	rr.Failed = 0
	r.Release(room, event)
}

// Uncertain records an attempt whose outcome is unknown (no definite
// homeserver answer: a timeout or a broken connection). The homeserver may
// still apply it, so the claim on event is held until until (Unix ms): no
// other receipt for room is sent before then, so a late apply of this one
// cannot land after a newer one sent meanwhile.
func (r *ReadReceipts) Uncertain(room, event string, until int64) {
	rr := r.Rooms[room]
	if rr == nil {
		return
	}
	if rr.Failed < 1<<20 {
		rr.Failed++
	}
	if rr.Claim == event {
		rr.ClaimUntil = until
	}
}

// Failure records one failed attempt to send event in room.
func (r *ReadReceipts) Failure(room, event string) {
	if rr := r.Rooms[room]; rr != nil && rr.Failed < 1<<20 {
		rr.Failed++
	}
	r.Release(room, event)
}
