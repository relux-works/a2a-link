package config

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func roomEv(room, id string) MailEntry {
	return MailEntry{ID: id, Kind: MailEvent, Room: room, Rel: "to"}
}

// receiptWorld is a mailbox holding ids in room !r (and !s for ids prefixed "s").
func receiptWorld(t *testing.T, ids ...string) (Paths, *Mailbox, *ReadReceipts) {
	t.Helper()
	p := testPaths(t)
	mb, err := OpenMailbox(p, "a")
	if err != nil {
		t.Fatal(err)
	}
	var entries []MailEntry
	for _, id := range ids {
		room := "!r"
		if id[1] == 's' {
			room = "!s"
		}
		entries = append(entries, roomEv(room, id))
	}
	if _, err := mb.Append(entries); err != nil {
		t.Fatal(err)
	}
	return p, mb, &ReadReceipts{Rooms: map[string]*ReadReceiptRoom{}}
}

// deliver notes the ids as received (done holds the fully printed ones) and receives them.
func deliver(t *testing.T, mb *Mailbox, r *ReadReceipts, ids []string, done ...string) {
	t.Helper()
	full := map[string]bool{}
	for _, id := range done {
		full[id] = true
	}
	r.NoteReceived(mb, mb.InOrder(ids), func(e MailEntry) bool { return full[e.ID] })
	if _, err := mb.Receive(ids); err != nil {
		t.Fatal(err)
	}
}

// Proves the receipt target is the last fully delivered entry of a contiguous
// run: everything delivered -> the newest; a truncated entry stops the run just
// before it (never past it, even when later entries are delivered); a later
// full print completes it and the run extends to the newest delivered entry.
func TestReadReceiptContiguousTarget(t *testing.T) {
	_, mb, r := receiptWorld(t, "$1", "$2", "$3", "$4")
	deliver(t, mb, r, []string{"$1", "$2"}, "$1", "$2")
	if got := r.Target(mb, "!r"); got != "$2" {
		t.Fatalf("all delivered: target %q, want $2", got)
	}
	deliver(t, mb, r, []string{"$3", "$4"}, "$4") // $3 truncated
	if got := r.Target(mb, "!r"); got != "$2" {
		t.Fatalf("truncated $3: target %q, want $2 (never $4)", got)
	}
	if !r.NoteFullPrint("!r", []string{"$3"}) {
		t.Fatal("full print of the truncated entry changed nothing")
	}
	if got := r.Target(mb, "!r"); got != "$4" {
		t.Fatalf("after completing $3: target %q, want $4", got)
	}
}

// Proves undelivered kinds each stop the run: an ack (no print) and a gap
// record. A gap is never completed by a full print, an ack'd entry is.
func TestReadReceiptAckAndGapBlock(t *testing.T) {
	p, mb, r := receiptWorld(t, "$1", "$2", "$3")
	if _, err := mb.Append([]MailEntry{{ID: "gap:!r:x", Kind: MailGap, Room: "!r"}, roomEv("!r", "$5")}); err != nil {
		t.Fatal(err)
	}
	deliver(t, mb, r, []string{"$1"}, "$1")
	deliver(t, mb, r, []string{"$2"}) // acked
	deliver(t, mb, r, []string{"$3"}, "$3")
	if got := r.Target(mb, "!r"); got != "$1" {
		t.Fatalf("acked $2: target %q, want $1", got)
	}
	r.NoteFullPrint("!r", []string{"$2"})
	if got := r.Target(mb, "!r"); got != "$3" {
		t.Fatalf("completed ack: target %q, want $3", got)
	}
	deliver(t, mb, r, []string{"gap:!r:x", "$5"}, "$5")
	if got := r.Target(mb, "!r"); got != "$3" {
		t.Fatalf("gap: target %q, want $3", got)
	}
	if r.NoteFullPrint("!r", []string{"gap:!r:x"}) {
		t.Fatal("a print completed a gap record")
	}
	if got := r.Target(mb, "!r"); got != "$3" {
		t.Fatalf("gap after print: target %q, want $3", got)
	}
	_ = p
}

// Proves an entry received out of mailbox order (an ack of a later entry while
// earlier ones are pending) is no target until those earlier entries are
// received AND delivered, although an earlier delivered entry may be; once all
// are delivered the target moves forward.
func TestReadReceiptOutOfOrderWaits(t *testing.T) {
	_, mb, r := receiptWorld(t, "$1", "$2", "$3")
	deliver(t, mb, r, []string{"$3"}) // acked ahead of $1 and $2
	r.NoteFullPrint("!r", []string{"$3"})
	if got := r.Target(mb, "!r"); got != "" {
		t.Fatalf("$1/$2 pending: target %q, want none", got)
	}
	deliver(t, mb, r, []string{"$1", "$2"}, "$1") // $2 truncated
	if got := r.Target(mb, "!r"); got != "$1" {
		t.Fatalf("$2 truncated: target %q, want $1 (never $3, which waits on $2)", got)
	}
	r.NoteFullPrint("!r", []string{"$2"})
	if got := r.Target(mb, "!r"); got != "$3" {
		// Receipt order was $3, $1, $2; the target is the LATEST delivered
		// event of the room's timeline, never an older one.
		t.Fatalf("all delivered: target %q, want $3", got)
	}
	if ids := markIDs(r.Rooms["!r"]); ids != "$1,$2,$3" {
		t.Fatalf("log order %s, want timeline order", ids)
	}
}

func markIDs(rr *ReadReceiptRoom) string {
	var ids []string
	for _, m := range rr.Log {
		ids = append(ids, m.ID)
	}
	return strings.Join(ids, ",")
}

// Proves marks are kept and pruned in timeline order: a later event acked
// before an earlier one stays in the log when the earlier one becomes the
// target and is accepted, and becomes the target itself once completed.
func TestReadReceiptTimelineOrderPrune(t *testing.T) {
	_, mb, r := receiptWorld(t, "$1", "$2", "$3")
	deliver(t, mb, r, []string{"$2"}) // acked ahead of $1, undelivered
	deliver(t, mb, r, []string{"$1"}, "$1")
	if got := r.Target(mb, "!r"); got != "$1" {
		t.Fatalf("target %q, want $1", got)
	}
	r.Accepted("!r", "$1")
	if ids := markIDs(r.Rooms["!r"]); ids != "$2" {
		t.Fatalf("after accepting $1 the log is %q; the undelivered later $2 was dropped", ids)
	}
	deliver(t, mb, r, []string{"$3"}, "$3")
	if got := r.Target(mb, "!r"); got != "" {
		t.Fatalf("target %q past undelivered $2", got)
	}
	r.NoteFullPrint("!r", []string{"$2"})
	if got := r.Target(mb, "!r"); got != "$3" {
		t.Fatalf("target %q, want $3", got)
	}
}

// Proves a mark whose earlier pending entries exceed the bound freezes its
// room (its timeline position would be unknown), while a neighbour room and
// a mark within the bound are unaffected.
func TestReadReceiptWaitsOverflowFreezes(t *testing.T) {
	var ids []string
	for i := 0; i <= ReadReceiptLogMax; i++ {
		ids = append(ids, "$"+strconv.Itoa(i))
	}
	ids = append(ids, "$last", "$s1")
	_, mb, r := receiptWorld(t, ids...)
	deliver(t, mb, r, []string{"$last"}) // ReadReceiptLogMax+1 earlier entries pending
	if !r.Rooms["!r"].Frozen {
		t.Fatal("overflowing waits did not freeze the room")
	}
	deliver(t, mb, r, []string{"$s1"}, "$s1")
	if got := r.Target(mb, "!s"); got != "$s1" {
		t.Fatalf("neighbour room: %q", got)
	}
	_, mb2, r2 := receiptWorld(t, "$a", "$b")
	deliver(t, mb2, r2, []string{"$b"}) // one earlier entry: within the bound
	if r2.Rooms["!r"].Frozen {
		t.Fatal("a bounded wait froze the room")
	}
}

// Proves fair ordering: claimed rooms go least recently tried first, so a
// room that was never reached is tried before rooms that just hung.
func TestReadReceiptOrderLeastRecentlyTried(t *testing.T) {
	r := &ReadReceipts{Rooms: map[string]*ReadReceiptRoom{"!a": {Tried: 50}, "!b": {Tried: 50}, "!c": {}}}
	if got := strings.Join(r.Order(map[string]string{"!a": "$1", "!b": "$2", "!c": "$3"}), ","); got != "!c,!a,!b" {
		t.Fatalf("order %s", got)
	}
	r.Attempted("!c", 60)
	if got := strings.Join(r.Order(map[string]string{"!a": "$1", "!b": "$2", "!c": "$3"}), ","); got != "!a,!b,!c" {
		t.Fatalf("order after attempt %s", got)
	}
}

// Proves the mailbox fence: the first receipt under a ledger carries it in
// the same append; it survives compaction and reopening; a ledger missing
// while the fence is present (its first save failed, or it was lost) is
// Broken, never a new baseline; a mailbox without the fence keeps the
// pre-ledger baseline rule; the explicit reset makes a fresh usable ledger at
// the current position, and nothing older is targeted afterwards.
func TestReadReceiptsMailboxFence(t *testing.T) {
	p, mb, r := receiptWorld(t, "$1", "$2", "$3")
	if mb.SeenByFence() {
		t.Fatal("fresh mailbox fenced")
	}
	deliver(t, mb, r, []string{"$1"}) // ledger never saved: a failed first save
	if !mb.SeenByFence() {
		t.Fatal("the receipt did not carry the fence")
	}
	if err := mb.compact(); err != nil {
		t.Fatal(err)
	}
	mb, err := OpenMailbox(p, "a")
	if err != nil || !mb.SeenByFence() {
		t.Fatalf("fence lost by compaction or reopen: %v", err)
	}
	lost, err := LoadReadReceipts(p, "a")
	if err != nil {
		t.Fatal(err)
	}
	deliver(t, mb, lost, []string{"$2"}, "$2")
	if !lost.Broken || lost.Target(mb, "!r") != "" || len(lost.Claim(mb, 0, 1)) != 0 {
		t.Fatalf("missing ledger with fence: %+v", lost)
	}
	// Control: an unfenced mailbox keeps the pre-ledger baseline.
	_, mb2, r2 := receiptWorld(t, "$a")
	deliver(t, mb2, r2, []string{"$a"}, "$a")
	if r2.Broken || r2.Target(mb2, "!r") != "$a" {
		t.Fatalf("unfenced control: %+v", r2)
	}
	// Reset: a fresh ledger at the current position; $3 then delivers normally.
	pos, err := ResetReadReceipts(context.Background(), p, "a")
	if err != nil || pos != "$2" {
		t.Fatalf("reset: %q %v", pos, err)
	}
	fresh, err := LoadReadReceipts(p, "a")
	if err != nil || fresh.Broken || len(fresh.Rooms) != 0 {
		t.Fatalf("after reset: %v %+v", err, fresh)
	}
	mb, _ = OpenMailbox(p, "a")
	if got := fresh.Target(mb, "!r"); got != "" {
		t.Fatalf("reset targeted an older entry: %q", got)
	}
	deliver(t, mb, fresh, []string{"$3"}, "$3")
	if got := fresh.Target(mb, "!r"); got != "$3" || fresh.Broken {
		t.Fatalf("after reset: target %q broken %v", got, fresh.Broken)
	}
}

// Proves an older reader is unaffected by a fenced mailbox: with every fence
// form removed (the op seenby lines and the rcpt seenby field), as a reader
// that does not know them sees the file, the same entries are pending and
// received.
func TestReadReceiptsFenceOlderReader(t *testing.T) {
	p, mb, r := receiptWorld(t, "$1", "$2", "$3")
	deliver(t, mb, r, []string{"$1"}, "$1")
	if err := mb.AddSeenByFence(); err != nil {
		t.Fatal(err)
	}
	if err := mb.compact(); err != nil {
		t.Fatal(err)
	}
	deliver(t, mb, r, []string{"$2"}, "$2")
	raw, err := os.ReadFile(p.MailboxFile("a"))
	if err != nil {
		t.Fatal(err)
	}
	var old []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var l map[string]any
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			t.Fatalf("fenced line is not JSON: %q", line)
		}
		if l["op"] == "seenby" {
			continue
		}
		delete(l, "seenby")
		data, _ := json.Marshal(l)
		old = append(old, string(data))
	}
	stripped := testPaths(t)
	if err := os.MkdirAll(filepath.Dir(stripped.MailboxFile("a")), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stripped.MailboxFile("a"), []byte(strings.Join(old, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := OpenMailbox(p, "a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := OpenMailbox(stripped, "a")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(pendingIDs(a), ",") != strings.Join(pendingIDs(b), ",") || a.LastReceived() != b.LastReceived() || b.SeenByFence() || !a.SeenByFence() {
		t.Fatalf("fenced %v/%q vs older view %v/%q", pendingIDs(a), a.LastReceived(), pendingIDs(b), b.LastReceived())
	}
}

// Proves a hidden (filtered) earlier entry of the same room holds the target,
// while another room is independent.
func TestReadReceiptHiddenEarlierAndRoomsIndependent(t *testing.T) {
	_, mb, r := receiptWorld(t, "$1", "$s1", "$2")
	mb.SetPendingFilter(func(e MailEntry) bool { return e.ID != "$1" })
	deliver(t, mb, r, []string{"$s1", "$2"}, "$s1", "$2")
	if got := r.Target(mb, "!r"); got != "" {
		t.Fatalf("hidden $1 pending: target %q, want none", got)
	}
	if got := r.Target(mb, "!s"); got != "$s1" {
		t.Fatalf("other room: target %q, want $s1", got)
	}
	if got := r.Claim(mb, 0, 1); len(got) != 1 || got["!s"] != "$s1" {
		t.Fatalf("claimed %v", got)
	}
}

// Proves monotonic sending: an accepted receipt prunes its marks, the same
// event is never a target again, and a failure keeps the target for a retry.
func TestReadReceiptAcceptedAndFailure(t *testing.T) {
	_, mb, r := receiptWorld(t, "$1", "$2", "$3")
	deliver(t, mb, r, []string{"$1", "$2"}, "$1", "$2")
	r.Failure("!r", "$2")
	if got := r.Target(mb, "!r"); got != "$2" || r.Rooms["!r"].Failed != 1 {
		t.Fatalf("after failure: target %q failed %d", got, r.Rooms["!r"].Failed)
	}
	r.Accepted("!r", "$2")
	if got := r.Target(mb, "!r"); got != "" || r.Rooms["!r"].Sent != "$2" || len(r.Rooms["!r"].Log) != 0 || r.Rooms["!r"].Failed != 0 {
		t.Fatalf("after accept: target %q room %+v", got, r.Rooms["!r"])
	}
	deliver(t, mb, r, []string{"$3"}, "$3")
	if got := r.Target(mb, "!r"); got != "$3" {
		t.Fatalf("next: target %q, want $3", got)
	}
	r.Accepted("!r", "$nope") // unknown event changes nothing
	if r.Rooms["!r"].Sent != "$2" {
		t.Fatal("unknown accepted event moved Sent")
	}
}

// Proves the bound: delivered marks are dropped first without widening the
// target past an undelivered mark; a log of undelivered marks only freezes the
// room (no receipt ever), while a neighbour room is unaffected.
func TestReadReceiptBound(t *testing.T) {
	ids := []string{"$s1"}
	for i := 0; i < ReadReceiptLogMax+2; i++ {
		ids = append(ids, "$"+strconv.Itoa(i))
	}
	_, mb, r := receiptWorld(t, ids...)
	deliver(t, mb, r, []string{"$0"}) // undelivered
	var rest []string
	for i := 1; i < ReadReceiptLogMax+2; i++ {
		rest = append(rest, "$"+strconv.Itoa(i))
	}
	deliver(t, mb, r, rest, rest...)
	if n := len(r.Rooms["!r"].Log); n > ReadReceiptLogMax || r.Rooms["!r"].Frozen {
		t.Fatalf("log %d frozen %v", n, r.Rooms["!r"].Frozen)
	}
	if got := r.Target(mb, "!r"); got != "" {
		t.Fatalf("undelivered $0 kept: target %q, want none", got)
	}

	_, mb2, r2 := receiptWorld(t, ids...)
	deliver(t, mb2, r2, ids[1:]) // all acked: undelivered only
	deliver(t, mb2, r2, []string{"$s1"}, "$s1")
	if !r2.Rooms["!r"].Frozen || r2.Target(mb2, "!r") != "" {
		t.Fatalf("undelivered overflow did not freeze: %+v", r2.Rooms["!r"].Frozen)
	}
	if got := r2.Target(mb2, "!s"); got != "$s1" {
		t.Fatalf("neighbour room: %q", got)
	}
}

// Proves a re-print of an entry whose earlier receipt was interrupted keeps
// the stronger fact and adds no duplicate mark.
func TestReadReceiptRenoteKeepsDone(t *testing.T) {
	_, mb, r := receiptWorld(t, "$1")
	r.NoteReceived(mb, mb.InOrder([]string{"$1"}), func(MailEntry) bool { return true })
	r.NoteReceived(mb, mb.InOrder([]string{"$1"}), func(MailEntry) bool { return false })
	if l := r.Rooms["!r"].Log; len(l) != 1 || !l[0].Done {
		t.Fatalf("log %+v", l)
	}
}

// Proves the ledger file round-trips under the lock helper, is 0600, and a
// malformed or wrongly permissioned file is refused (receipts withheld).
func TestReadReceiptsFile(t *testing.T) {
	p, mb, _ := receiptWorld(t, "$1")
	_ = mb
	err := UpdateReadReceipts(context.Background(), p, "a", func(r *ReadReceipts, mb *Mailbox) (bool, error) {
		r.NoteReceived(mb, mb.InOrder([]string{"$1"}), func(MailEntry) bool { return true })
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := LoadReadReceipts(p, "a")
	if err != nil || len(r.Rooms["!r"].Log) != 1 {
		t.Fatalf("reload: %v %+v", err, r)
	}
	st, err := os.Lstat(p.ReadReceiptsFile("a"))
	if err != nil || st.Mode().Perm() != SecretFileMode {
		t.Fatalf("mode: %v %v", err, st)
	}
	if err := os.WriteFile(p.ReadReceiptsFile("a"), []byte(`{"rooms":{"!r":{"bogus":1}}}`), SecretFileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadReadReceipts(p, "a"); err == nil {
		t.Fatal("unknown field accepted")
	}
	if err := os.WriteFile(p.ReadReceiptsFile("a"), []byte(`{}`), SecretFileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p.ReadReceiptsFile("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadReadReceipts(p, "a"); err == nil {
		t.Fatal("0644 ledger accepted")
	}
}

// Proves the durable gap model across mailbox receipt, compaction and restart:
// A=full, B=truncated, C=full, D=truncated, E=full gives target A; the full
// read of B makes it exactly C (never E: D still holds), the full read of D
// makes it E. Compaction keeps only received ids, without body, room or
// disposition; the ledger alone carries the disposition.
func TestReadReceiptDurableGapModel(t *testing.T) {
	p, mb, r := receiptWorld(t, "$A", "$B", "$C", "$D", "$E")
	deliver(t, mb, r, []string{"$A", "$B", "$C", "$D", "$E"}, "$A", "$C", "$E")
	if err := SaveReadReceipts(p, "a", r); err != nil {
		t.Fatal(err)
	}
	if err := mb.compact(); err != nil {
		t.Fatal(err)
	}
	// Restart: both files are read back from disk.
	mb, err := OpenMailbox(p, "a")
	if err != nil {
		t.Fatal(err)
	}
	if len(mb.live) != 0 || !mb.Received("$B") || !mb.Received("$D") {
		t.Fatalf("after compaction: live %d, B %v, D %v", len(mb.live), mb.Received("$B"), mb.Received("$D"))
	}
	if r, err = LoadReadReceipts(p, "a"); err != nil {
		t.Fatal(err)
	}
	if got := r.Target(mb, "!r"); got != "$A" {
		t.Fatalf("initial target %q, want $A", got)
	}
	r.NoteFullPrint("!r", []string{"$B"})
	if got := r.Target(mb, "!r"); got != "$C" {
		t.Fatalf("after B: target %q, want exactly $C", got)
	}
	r.NoteFullPrint("!r", []string{"$D"})
	if got := r.Target(mb, "!r"); got != "$E" {
		t.Fatalf("after D: target %q, want $E", got)
	}
}

// Proves a competing sender is excluded: while one command holds a live claim
// on a room, another gets no target there (so it cannot send an older event
// after a newer one); the claim expires, and an accept or failure releases it.
func TestReadReceiptClaimExcludesCompetingSender(t *testing.T) {
	_, mb, r := receiptWorld(t, "$1", "$2")
	deliver(t, mb, r, []string{"$1"}, "$1")
	if got := r.Claim(mb, 100, 200); got["!r"] != "$1" {
		t.Fatalf("first claim %v", got)
	}
	deliver(t, mb, r, []string{"$2"}, "$2")
	if got := r.Claim(mb, 150, 300); len(got) != 0 {
		t.Fatalf("competing claim during a live claim: %v", got)
	}
	r.Accepted("!r", "$1")
	if got := r.Claim(mb, 150, 300); got["!r"] != "$2" {
		t.Fatalf("after accept: %v", got)
	}
	r.Failure("!r", "$2")
	if rr := r.Rooms["!r"]; rr.Claim != "" || rr.Sent != "$1" {
		t.Fatalf("failure did not release: %+v", rr)
	}
	if got := r.Claim(mb, 400, 500); got["!r"] != "$2" {
		t.Fatalf("retry claim: %v", got)
	}
	if got := r.Claim(mb, 501, 600); got["!r"] != "$2" {
		t.Fatalf("expired claim not reclaimable: %v", got)
	}
	r.Release("!r", "$other") // a stale release never drops a newer claim
	if r.Rooms["!r"].Claim != "$2" {
		t.Fatal("stale release dropped the live claim")
	}
}

// Proves a failed ledger write never widens a receipt: entries the mailbox
// received while the ledger kept its older state (B truncated, C full) are
// detected at the next note, the ledger becomes Broken, and no receipt ever
// covers them, not even after a full print of B. The control saves the
// ledger and keeps its normal target.
func TestReadReceiptLedgerWriteFailureBreaks(t *testing.T) {
	for _, saved := range []bool{true, false} {
		p, mb, r := receiptWorld(t, "$A", "$B", "$C", "$D")
		deliver(t, mb, r, []string{"$A"}, "$A")
		if err := SaveReadReceipts(p, "a", r); err != nil {
			t.Fatal(err)
		}
		deliver(t, mb, r, []string{"$B", "$C"}, "$C") // B truncated
		if saved {
			if err := SaveReadReceipts(p, "a", r); err != nil {
				t.Fatal(err)
			}
		}
		r, err := LoadReadReceipts(p, "a")
		if err != nil {
			t.Fatal(err)
		}
		deliver(t, mb, r, []string{"$D"}, "$D")
		r.NoteFullPrint("!r", []string{"$B"})
		got := r.Target(mb, "!r")
		switch {
		case saved && (got != "$D" || r.Broken):
			t.Fatalf("control: target %q broken %v", got, r.Broken)
		case !saved && (got != "" || !r.Broken || len(r.Claim(mb, 0, 1)) != 0):
			t.Fatalf("lost write: target %q broken %v", got, r.Broken)
		}
	}
}

// Proves an interrupted inbox (ledger noted, mailbox receipt never written)
// stays sound: the entries are printed and noted again, then received.
func TestReadReceiptInterruptedReceiptStaysSound(t *testing.T) {
	_, mb, r := receiptWorld(t, "$1", "$2")
	r.NoteReceived(mb, mb.InOrder([]string{"$1", "$2"}), func(MailEntry) bool { return true })
	if !r.Verify(mb) {
		t.Fatal("unreceived noted batch broke the ledger")
	}
	deliver(t, mb, r, []string{"$1", "$2"}, "$1", "$2")
	if got := r.Target(mb, "!r"); got != "$2" || r.Broken {
		t.Fatalf("target %q broken %v", got, r.Broken)
	}
}

// Proves an attempt with no definite answer holds its room: the claim stays
// until the quarantine ends, so no other receipt for the room goes meanwhile;
// afterwards the newest target is claimable.
func TestReadReceiptUncertainQuarantine(t *testing.T) {
	_, mb, r := receiptWorld(t, "$1", "$2")
	deliver(t, mb, r, []string{"$1"}, "$1")
	if got := r.Claim(mb, 100, 200); got["!r"] != "$1" {
		t.Fatalf("claim %v", got)
	}
	r.Uncertain("!r", "$1", 10_000)
	deliver(t, mb, r, []string{"$2"}, "$2")
	if got := r.Claim(mb, 5_000, 6_000); len(got) != 0 {
		t.Fatalf("claimed during quarantine: %v", got)
	}
	if got := r.Claim(mb, 10_001, 11_000); got["!r"] != "$2" {
		t.Fatalf("after quarantine: %v", got)
	}
}

// Proves the legacy/unnoted path is closed with the reviewer's witness: an
// existing ledger file that never noted a batch (an earlier revision's empty
// ledger) is Broken on load. With it on disk, a batch noted in memory whose
// ledger write is lost while the mailbox receipt succeeds can never become a
// new baseline: a later fully delivered entry yields no target. Beside a
// never-initialised mailbox (no file, no fence), which keeps the baseline rule.
func TestReadReceiptsUnnotedLedgerFileIsBroken(t *testing.T) {
	p, mb, _ := receiptWorld(t, "$A", "$B", "$C")
	if err := os.MkdirAll(filepath.Dir(p.ReadReceiptsFile("a")), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.ReadReceiptsFile("a"), []byte(`{"rooms":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := LoadReadReceipts(p, "a")
	if err != nil || !r.Broken {
		t.Fatalf("unnoted ledger file: %v %+v", err, r)
	}
	inMemory := &ReadReceipts{Rooms: map[string]*ReadReceiptRoom{}}
	deliver(t, mb, inMemory, []string{"$A", "$B"}, "$A") // B truncated; this write is lost
	r, err = LoadReadReceipts(p, "a")
	if err != nil {
		t.Fatal(err)
	}
	deliver(t, mb, r, []string{"$C"}, "$C")
	if got := r.Target(mb, "!r"); got != "" || !r.Broken {
		t.Fatalf("recovery after a lost write: target %q broken %v", got, r.Broken)
	}
	// Control: no file and no fence is a never-initialised mailbox.
	p2, mb2, _ := receiptWorld(t, "$x")
	fresh, err := LoadReadReceipts(p2, "a")
	if err != nil || fresh.Broken {
		t.Fatalf("never initialised: %v %+v", err, fresh)
	}
	deliver(t, mb2, fresh, []string{"$x"}, "$x")
	if got := fresh.Target(mb2, "!r"); got != "$x" {
		t.Fatalf("never-initialised control: %q", got)
	}
}

// Proves the integrity checkpoint follows the exact order the receipt is
// committed in: entries noted and received in the same (timeline) order keep
// the ledger sound, while a receipt committed in a different order than noted
// is detected (the guard is not weakened).
func TestReadReceiptCheckpointFollowsReceiveOrder(t *testing.T) {
	_, mb, r := receiptWorld(t, "$A", "$B", "$C")
	live := mb.InOrder([]string{"$B", "$A"}) // timeline order, whatever the argument order
	r.NoteReceived(mb, live, func(MailEntry) bool { return true })
	if _, err := mb.Receive([]string{live[0].ID, live[1].ID}); err != nil {
		t.Fatal(err)
	}
	if !r.Verify(mb) {
		t.Fatal("timeline-ordered receipt broke the ledger")
	}
	_, mb2, r2 := receiptWorld(t, "$A", "$B")
	r2.NoteReceived(mb2, mb2.InOrder([]string{"$A", "$B"}), func(MailEntry) bool { return true })
	if _, err := mb2.Receive([]string{"$B", "$A"}); err != nil { // committed in another order
		t.Fatal(err)
	}
	if r2.Verify(mb2) {
		t.Fatal("a receipt committed in another order than noted was not detected")
	}
}
