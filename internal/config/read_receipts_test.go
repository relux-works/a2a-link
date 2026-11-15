package config

import (
	"context"
	"os"
	"strconv"
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
	if got := r.Target(mb, "!r"); got != "$2" {
		// Receipt order is $3, $1, $2: $2 is the last mark and its waits are met.
		t.Fatalf("all delivered: target %q, want $2", got)
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
	if got := r.Targets(mb); len(got) != 1 || got["!s"] != "$s1" {
		t.Fatalf("targets %v", got)
	}
}

// Proves monotonic sending: an accepted receipt prunes its marks, the same
// event is never a target again, and a failure keeps the target for a retry.
func TestReadReceiptAcceptedAndFailure(t *testing.T) {
	_, mb, r := receiptWorld(t, "$1", "$2", "$3")
	deliver(t, mb, r, []string{"$1", "$2"}, "$1", "$2")
	r.Failure("!r")
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
