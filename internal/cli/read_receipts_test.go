package cli

import (
	"context"
	"os"
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

// Proves a saved inbox counts only full bodies on stdout: a --summary excerpt
// is never delivery, not even one holding the whole (folded) body, and
// `a2a inbox show` does not complete it; a --brief inline body is delivery.
func TestSeenBySummaryIsNotDeliveryBriefInlineIs(t *testing.T) {
	e, room := seenWorld(t)
	id1 := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "hi"))
	e.as("alice", "inbox", "--out", filepath.Join(outputTestDir(t), "f1"), "--summary", "--width", "2000").ok(t)
	e.wantReceipts()
	if !e.received("alice", id1) {
		t.Fatal("mail was not received")
	}
	e.as("alice", "inbox", "show", id1).ok(t)
	e.as("alice", "inbox").ok(t)
	e.wantReceipts()
	e.as("alice", "read", "proj", "--event", id1).ok(t)
	e.wantReceipts(id1)
	id2 := e.hs.inject(room, "@bob:test.local", toMsg("bob", "request", "please review"))
	e.as("alice", "inbox", "--brief").ok(t)
	e.wantReceipts(id1, id2)
}

// Proves the durable gap model end to end: A=full, B=truncated, C=full,
// D=truncated, E=full in one inbox gives a receipt on A; the full read of B
// moves it to exactly C, the full read of D to E. Each command is a fresh
// process over the same files (restart).
func TestSeenByDurableGapModel(t *testing.T) {
	e, room := seenWorld(t)
	long := strings.Repeat("long ", 500)
	a := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "A"))
	b := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "B "+long))
	c := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "C"))
	d := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "D "+long))
	ev := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "E"))
	e.as("alice", "inbox").ok(t)
	e.wantReceipts(a)
	e.as("alice", "read", "proj", "--event", b).ok(t)
	e.wantReceipts(a, c)
	e.as("alice", "read", "proj", "--event", d).ok(t)
	e.wantReceipts(a, c, ev)
}

// Proves a full read completes only through --event and only after a full
// write: a failed write (a closed pipe) and a --last listing complete
// nothing, and the same --event read with a working stdout does.
func TestSeenByReadCompletesOnlyAfterFullEventWrite(t *testing.T) {
	e, room := seenWorld(t)
	a := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "A"))
	b := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", strings.Repeat("long ", 500)))
	e.as("alice", "inbox").ok(t)
	e.wantReceipts(a)
	e.configure = func(a *App) { a.Stdout = failWriter{} }
	e.as("alice", "read", "proj", "--event", b)
	e.configure = nil
	e.wantReceipts(a)
	e.as("alice", "read", "proj", "--last", "5").ok(t)
	e.wantReceipts(a)
	if rr := e.ledgerRoom("alice", room); len(rr.Log) != 1 || rr.Log[0].ID != b || rr.Log[0].Done {
		t.Fatalf("ledger %+v", rr)
	}
	c := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "C"))
	e.as("alice", "inbox").ok(t)
	e.wantReceipts(a)
	e.as("alice", "read", "proj", "--event", b).ok(t)
	e.wantReceipts(a, c)
}

// Proves a competing sender's live claim on a room stops this command from
// sending there (no older receipt can overtake a newer one), and that the
// next command sends once the claim has expired.
func TestSeenByCompetingSenderClaim(t *testing.T) {
	e, room := seenWorld(t)
	id := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "mail"))
	e.as("alice", "inbox", "--limit", "1").ok(t)
	e.wantReceipts(id)
	id2 := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "more"))
	claim := func(until int64) {
		t.Helper()
		if err := config.UpdateReadReceipts(context.Background(), e.paths(), "alice", func(r *config.ReadReceipts, _ *config.Mailbox) (bool, error) {
			r.Rooms[room].Claim, r.Rooms[room].ClaimUntil = "$competing", until
			return true, nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	claim(time.Now().Add(time.Hour).UnixMilli())
	e.as("alice", "inbox").ok(t)
	e.wantReceipts(id)
	if !e.received("alice", id2) {
		t.Fatal("mail was not received")
	}
	claim(1)
	e.as("alice", "inbox").ok(t)
	e.wantReceipts(id, id2)
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
	oldBudget, oldCall, oldQ := readReceiptBudget, readReceiptCallMax, readReceiptQuarantine
	readReceiptBudget, readReceiptCallMax, readReceiptQuarantine = 300*time.Millisecond, 150*time.Millisecond, 0
	t.Cleanup(func() { readReceiptBudget, readReceiptCallMax, readReceiptQuarantine = oldBudget, oldCall, oldQ })
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

// Proves an attempt without a definite answer (a timeout) quarantines its
// room: the next inbox sends no receipt there, even for newer mail, so the
// abandoned request cannot be overtaken; once the quarantine ends the newest
// target is sent. A definite refusal (500) releases at once: see
// TestSeenByFailingEndpointIsQuietAndRetried.
func TestSeenByUncertainAttemptQuarantinesRoom(t *testing.T) {
	oldBudget, oldCall := readReceiptBudget, readReceiptCallMax
	readReceiptBudget, readReceiptCallMax = 300*time.Millisecond, 150*time.Millisecond
	t.Cleanup(func() { readReceiptBudget, readReceiptCallMax = oldBudget, oldCall })
	e, room := seenWorld(t)
	hang := make(chan struct{})
	e.hs.mu.Lock()
	e.hs.receiptHang = hang
	e.hs.mu.Unlock()
	e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "first"))
	e.as("alice", "inbox").ok(t)
	e.hs.mu.Lock()
	e.hs.receiptHang = nil
	e.hs.mu.Unlock()
	close(hang)
	id2 := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "second"))
	e.as("alice", "inbox").ok(t)
	e.wantReceipts()
	if err := config.UpdateReadReceipts(context.Background(), e.paths(), "alice", func(r *config.ReadReceipts, _ *config.Mailbox) (bool, error) {
		r.Rooms[room].ClaimUntil = 1 // the quarantine has ended
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	e.as("alice", "inbox").ok(t)
	e.wantReceipts(id2)
}

// Proves a ledger that could not be written never widens a receipt: while the
// ledger file is unusable, inbox delivers mail (B truncated, C full) without
// marks; after the storage recovers (the older ledger is back), the ledger
// detects the unmarked receipts and sends nothing more, not even after a full
// read of B and a fully delivered D. Beside TestSeenByTruncatedEntryHoldsUntilFullRead.
func TestSeenByLedgerWriteFailureNeverWidens(t *testing.T) {
	e, room := seenWorld(t)
	a := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "A"))
	e.as("alice", "inbox").ok(t)
	e.wantReceipts(a)
	path := e.paths().ReadReceiptsFile("alice")
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil { // the ledger cannot be read or replaced
		t.Fatal(err)
	}
	b := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", strings.Repeat("long ", 500)))
	c := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "C"))
	e.as("alice", "inbox").ok(t)
	if !e.received("alice", b) || !e.received("alice", c) {
		t.Fatal("mail was not received")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	e.as("alice", "read", "proj", "--event", b).ok(t)
	e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "D"))
	e.as("alice", "inbox").ok(t)
	e.wantReceipts(a)
	r, err := config.LoadReadReceipts(e.paths(), "alice")
	if err != nil || !r.Broken {
		t.Fatalf("ledger not marked broken: %v %+v", err, r)
	}
}

// Proves fair progression across runs: two rooms whose endpoint hangs use up
// one run's whole budget, yet the next run serves the healthy room first
// (least recently tried), instead of starving it behind the same two rooms
// forever. The quarantine is off, so only the ordering is exercised.
func TestSeenByHangingRoomsDoNotStarveOthers(t *testing.T) {
	oldBudget, oldCall, oldQ := readReceiptBudget, readReceiptCallMax, readReceiptQuarantine
	readReceiptBudget, readReceiptCallMax, readReceiptQuarantine = 300*time.Millisecond, 150*time.Millisecond, 0
	t.Cleanup(func() { readReceiptBudget, readReceiptCallMax, readReceiptQuarantine = oldBudget, oldCall, oldQ })
	e, room := seenWorld(t)
	lobby := e.hs.aliases["#lobby:test.local"]
	healthy := e.hs.addRoom("zzz", "@alice:test.local", "@bob:test.local") // sorts after both hanging rooms
	hang := make(chan struct{})
	t.Cleanup(func() { close(hang) })
	e.hs.mu.Lock()
	e.hs.receiptHang, e.hs.receiptHangRooms = hang, map[string]bool{room: true, lobby: true}
	e.hs.mu.Unlock()
	e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "proj"))
	e.hs.inject(lobby, "@bob:test.local", toMsg("bob", "notice", "lobby"))
	id := e.hs.inject(healthy, "@bob:test.local", toMsg("bob", "notice", "healthy"))
	e.as("alice", "inbox").ok(t)
	if len(e.hs.readReceipts()) != 0 || e.ledgerRoom("alice", healthy).Tried != 0 {
		t.Fatalf("first run: receipts %v, healthy tried %d (the budget should be spent on the hanging rooms)", e.receiptEvents(), e.ledgerRoom("alice", healthy).Tried)
	}
	e.as("alice", "inbox").ok(t)
	got := e.hs.readReceipts()
	if len(got) != 1 || got[0].room != healthy || got[0].event != id {
		t.Fatalf("second run starved the healthy room: %+v", got)
	}
}

// Proves unreadable-ledger neighbours fail closed while mail still flows: a
// corrupt ledger sends nothing and is left as found; a ledger removed later is
// broken (the mailbox fence remains), not a new baseline; reset-seen-by
// without --confirm changes nothing, and with it receipts resume from the next
// full delivery only.
func TestSeenByUnreadableLedgerFailsClosed(t *testing.T) {
	e, room := seenWorld(t)
	a := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "A"))
	e.as("alice", "inbox").ok(t)
	e.wantReceipts(a)
	path := e.paths().ReadReceiptsFile("alice")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "B"))
	e.as("alice", "inbox").ok(t)
	if !e.received("alice", b) || readFile(t, path) != "{not json" {
		t.Fatal("corrupt ledger: mail not received or ledger rewritten")
	}
	e.wantReceipts(a)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "C"))
	e.as("alice", "inbox").ok(t)
	e.wantReceipts(a)
	if r, err := config.LoadReadReceipts(e.paths(), "alice"); err != nil || !r.Broken {
		t.Fatalf("lost ledger not broken: %v %+v", err, r)
	}
	before := readFile(t, path)
	e.as("alice", "inbox", "reset-seen-by").failsWith(t, ExitUsage, "--confirm")
	if readFile(t, path) != before {
		t.Fatal("reset without --confirm changed the ledger")
	}
	e.as("alice", "inbox", "reset-seen-by", "--confirm").ok(t)
	e.wantReceipts(a) // a reset sends nothing by itself
	d := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "D"))
	e.as("alice", "inbox").ok(t)
	e.wantReceipts(a, d)
}

// Proves the FIRST-initialization witness: before any ledger exists, the
// ledger cannot be created while mailbox appends work; inbox still delivers A
// (full) and B (truncated). After the storage recovers, no receipt ever
// passes B: not for a later full C, not after a full read of B. Only the
// explicit reset starts a new baseline. Beside the healthy first init in
// TestSeenByTruncatedEntryHoldsUntilFullRead.
func TestSeenByFirstInitFailureNeverBecomesBaseline(t *testing.T) {
	e, room := seenWorld(t)
	path := e.paths().ReadReceiptsFile("alice")
	if _, err := os.Lstat(path); err == nil {
		t.Fatal("a ledger already exists before the first delivery")
	}
	if err := os.Mkdir(path, 0o700); err != nil { // the ledger cannot be created
		t.Fatal(err)
	}
	e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "A"))
	b := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", strings.Repeat("long ", 500)))
	e.as("alice", "inbox").ok(t)
	if !e.received("alice", b) || !e.mailbox("alice").SeenByFence() {
		t.Fatal("mail not received, or its receipt carried no fence")
	}
	e.wantReceipts()
	if err := os.Remove(path); err != nil { // storage recovers
		t.Fatal(err)
	}
	e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "C"))
	e.as("alice", "inbox").ok(t)
	e.as("alice", "read", "proj", "--event", b).ok(t)
	e.wantReceipts()
	e.as("alice", "inbox", "reset-seen-by", "--confirm").ok(t)
	d := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "D"))
	e.as("alice", "inbox").ok(t)
	e.wantReceipts(d)
}

// Proves a multi-id ack in reverse argument order ("ack B A") keeps the
// ledger sound: no false identity-wide Broken, and once both are completed by
// full reads a later delivery is receipted. Beside the single-id ack in
// TestSeenByAckDoorbellAndJSONTruncation.
func TestSeenByAckArgumentOrderKeepsLedgerSound(t *testing.T) {
	e, room := seenWorld(t)
	a := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "A"))
	b := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "B"))
	c := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "C"))
	e.as("alice", "inbox", "--limit", "1").ok(t) // delivers A; B and C stay pending
	e.wantReceipts(a)
	e.as("alice", "ack", c, b).ok(t) // reverse timeline order
	if r, err := config.LoadReadReceipts(e.paths(), "alice"); err != nil || r.Broken {
		t.Fatalf("ack in argument order broke the ledger: %v %+v", err, r)
	}
	e.as("alice", "read", "proj", "--event", b).ok(t)
	e.wantReceipts(a, b)
	e.as("alice", "read", "proj", "--event", c).ok(t)
	e.wantReceipts(a, b, c)
	d := e.hs.inject(room, "@bob:test.local", toMsg("bob", "notice", "D"))
	e.as("alice", "inbox").ok(t)
	e.wantReceipts(a, b, c, d)
}
