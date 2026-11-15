package cli

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/a2a-swarm/internal/config"
	"github.com/relux-works/skill-go-testing-tools/tuitestkit"
)

const receiptRoute = "POST /_matrix/client/v3/rooms/{room}/receipt/{type}/{event}"

// seenWorld is world with alice's first inbox done (the delivery baseline)
// and canonical test paths (saved frames refuse symlink ancestry).
func seenWorld(t *testing.T) (*env, string) {
	t.Helper()
	e, room := world(t)
	var err error
	if e.dir, err = filepath.EvalSymlinks(e.dir); err != nil {
		t.Fatal(err)
	}
	e.as("alice", "inbox").ok(t)
	return e, room
}

func (e *env) receiptEvents() []string {
	var out []string
	for _, r := range e.hs.readReceipts() {
		out = append(out, r.event)
	}
	return out
}

func (e *env) wantReceipts(want ...string) {
	e.t.Helper()
	if got := e.receiptEvents(); strings.Join(got, ",") != strings.Join(want, ",") {
		e.t.Fatalf("read receipts %v, want %v", got, want)
	}
}

func (e *env) ledgerRoom(name, room string) config.ReadReceiptRoom {
	e.t.Helper()
	r, err := config.LoadReadReceipts(e.paths(), name)
	if err != nil {
		e.t.Fatal(err)
	}
	if rr := r.Rooms[room]; rr != nil {
		return *rr
	}
	return config.ReadReceiptRoom{}
}

// Proves the wire and the positive path: after an inbox that printed every
// body in full, exactly one public unthreaded m.read receipt (empty JSON body)
// goes to the newest delivered event, from the reader's own account; a later
// inbox with nothing new sends nothing again.
func TestSeenByReceiptAfterFullDelivery(t *testing.T) {
	e, room := seenWorld(t)
	e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "first"))
	id2 := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "second"))
	e.as("alice", "inbox").ok(t)
	got := e.hs.readReceipts()
	if len(got) != 1 || got[0].user != "@alice:test.local" || got[0].room != room || got[0].typ != "m.read" || got[0].event != id2 || got[0].body != "{}" {
		t.Fatalf("receipts %+v", got)
	}
	e.as("alice", "inbox").ok(t)
	e.wantReceipts(id2)
}

// Proves a truncated print is not delivery: the receipt stops on the event
// before it and never covers it, even when later events were delivered; the
// full print the truncation marker names (`a2a read --event`) completes it and
// the receipt advances to the newest delivered event.
func TestSeenByTruncatedEntryHoldsUntilFullRead(t *testing.T) {
	e, room := seenWorld(t)
	id1 := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "short"))
	id2 := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", strings.Repeat("long ", 500)))
	id3 := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "after"))
	out := e.as("alice", "inbox").ok(t).stdout
	tuitestkit.ContainsStr(t, out, "[truncated: ")
	e.wantReceipts(id1)
	if !e.received("alice", id2) || !e.received("alice", id3) {
		t.Fatal("mail was not received")
	}
	e.as("alice", "read", "proj", "--event", id2).ok(t)
	e.wantReceipts(id1, id3)
}

// Proves an ack (received without printing) holds the receipt in its room,
// that a doorbell and a JSON print of a truncated body are not delivery either,
// and that completing the acked entry lets the receipt cover later deliveries.
func TestSeenByAckDoorbellAndJSONTruncation(t *testing.T) {
	e, room := seenWorld(t)
	id1 := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "one"))
	id2 := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "two"))
	e.as("alice", "inbox", "--limit", "1").ok(t)
	e.wantReceipts(id1)
	e.as("alice", "ack", id2).ok(t)
	id3 := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "three"))
	e.hook("alice", "prompt", `{}`) // a doorbell (whatever it prints) is no delivery
	e.wantReceipts(id1)
	e.as("alice", "inbox").ok(t)
	e.wantReceipts(id1) // id3 delivered, but acked id2 precedes it
	id4 := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", strings.Repeat("json ", 500)))
	e.as("alice", "inbox", "--json").ok(t)
	e.wantReceipts(id1)
	e.as("alice", "read", "proj", "--event", id2).ok(t)
	e.wantReceipts(id1, id3) // id4 was cut in the JSON line
	e.as("alice", "read", "proj", "--event", id4, "--json").ok(t)
	e.wantReceipts(id1, id3, id4)
}

// Proves a saved inbox counts only what stdout carried in full: a summary
// excerpt cut by --width is not delivery, an excerpt holding the whole body
// is; `a2a inbox show` of the saved full body completes the cut entry without
// HTTP, and the next inbox sends its receipt.
func TestSeenBySummaryWidthAndInboxShow(t *testing.T) {
	e, room := seenWorld(t)
	id1 := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "hi"))
	e.as("alice", "inbox", "--out", filepath.Join(outputTestDir(t), "f1"), "--summary", "--width", "2000").ok(t)
	e.wantReceipts(id1)
	id2 := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", strings.Repeat("wide ", 80)))
	e.as("alice", "inbox", "--out", filepath.Join(outputTestDir(t), "f2"), "--summary", "--width", "20").ok(t)
	e.wantReceipts(id1)
	requests := len(e.hs.urls())
	e.as("alice", "inbox", "show", id2).ok(t)
	if len(e.hs.urls()) != requests {
		t.Fatal("inbox show performed HTTP")
	}
	e.as("alice", "inbox").ok(t)
	e.wantReceipts(id1, id2)
}

// Proves failure isolation for a failing endpoint: the inbox still succeeds,
// prints the mail exactly as without receipts, says nothing about the receipt
// and receives the mail; the failure is counted, and the next inbox retries
// once and then sends nothing more.
func TestSeenByFailingEndpointIsQuietAndRetried(t *testing.T) {
	e, room := seenWorld(t)
	e.hs.fail(receiptRoute, 500, "M_UNKNOWN", "receipt store down")
	id := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "mail"))
	r := e.as("alice", "inbox").ok(t)
	tuitestkit.ContainsStr(t, r.stdout, id)
	tuitestkit.NotContainsStr(t, r.stdout+r.stderr, "receipt")
	if !e.received("alice", id) {
		t.Fatal("mail was not received")
	}
	if len(e.hs.CallsFor(receiptRoute)) != 1 || e.ledgerRoom("alice", room).Failed != 1 {
		t.Fatalf("attempts %d, ledger %+v", len(e.hs.CallsFor(receiptRoute)), e.ledgerRoom("alice", room))
	}
	e.hs.mu.Lock()
	delete(e.hs.failures, receiptRoute)
	e.hs.mu.Unlock()
	e.as("alice", "inbox").ok(t)
	e.wantReceipts(id)
	e.as("alice", "inbox").ok(t)
	e.wantReceipts(id)
	if rr := e.ledgerRoom("alice", room); rr.Sent != id || rr.Failed != 0 || len(rr.Log) != 0 {
		t.Fatalf("ledger %+v", rr)
	}
}

// Proves failure isolation for a hanging endpoint: the attempt is bounded, the
// inbox returns promptly with the mail received, and the next inbox against a
// responsive endpoint sends the receipt.
func TestSeenByHangingEndpointIsBounded(t *testing.T) {
	oldBudget, oldCall := readReceiptBudget, readReceiptCallMax
	readReceiptBudget, readReceiptCallMax = 300*time.Millisecond, 150*time.Millisecond
	t.Cleanup(func() { readReceiptBudget, readReceiptCallMax = oldBudget, oldCall })
	e, room := seenWorld(t)
	hang := make(chan struct{})
	e.hs.mu.Lock()
	e.hs.receiptHang = hang
	e.hs.mu.Unlock()
	id := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "mail"))
	start := time.Now()
	e.as("alice", "inbox").ok(t)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("inbox took %s with a hanging receipt endpoint", d)
	}
	if !e.received("alice", id) || len(e.hs.readReceipts()) != 0 || e.ledgerRoom("alice", room).Failed != 1 {
		t.Fatalf("received %v receipts %v ledger %+v", e.received("alice", id), e.receiptEvents(), e.ledgerRoom("alice", room))
	}
	e.hs.mu.Lock()
	e.hs.receiptHang = nil
	e.hs.mu.Unlock()
	close(hang)
	e.as("alice", "inbox").ok(t)
	e.wantReceipts(id)
}

// Proves rooms are independent: a truncated entry in one room does not hold
// the receipt of another room.
func TestSeenByRoomsIndependent(t *testing.T) {
	e, room := seenWorld(t)
	lobby := e.hs.aliases["#lobby:test.local"]
	if lobby == "" {
		t.Fatal("no lobby room")
	}
	e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", strings.Repeat("long ", 500)))
	id := e.hs.inject(lobby, "@bob:test.local", toMsg("bob", "notice", "lobby"))
	e.as("alice", "inbox").ok(t)
	got := e.hs.readReceipts()
	if len(got) != 1 || got[0].room != lobby || got[0].event != id {
		t.Fatalf("receipts %+v", got)
	}
}
