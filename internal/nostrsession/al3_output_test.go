package nostrsession

import (
	"context"
	"errors"
	"testing"
)

// This is the existing AL2 storage boundary, with a transport-only fixture (not
// CG1 evidence): failed output leaves exactly the same mailbox item after restart;
// a successful neighboring output receipts it once. No permission is injected.
func TestAL3FailedOutputRetainsMailbox(t *testing.T) {
	w := newWorld(t)
	id := w.post(t, "receipt-boundary", nil)
	syncSession(t, w.s)
	failed := errors.New("fixture output failure")
	if e := w.s.ReadInbox(context.Background(), 50, func(rows []Record) error {
		if len(rows) != 1 || rows[0].ID != id {
			t.Fatal("missing input")
		}
		return failed
	}); e != failed {
		t.Fatal("output failure not propagated")
	}
	w.restart(t)
	if rows := pending(t, w.s); len(rows) != 1 || rows[0].ID != id {
		t.Fatal("failed output receipted")
	}
	if e := w.s.ReadInbox(context.Background(), 50, func(rows []Record) error {
		if len(rows) != 1 || rows[0].ID != id {
			t.Fatal("valid output lost input")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	w.restart(t)
	syncSession(t, w.s)
	if len(pending(t, w.s)) != 0 {
		t.Fatal("successful receipt not durable")
	}
}
