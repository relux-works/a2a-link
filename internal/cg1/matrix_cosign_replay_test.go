package cg1

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/a2a-swarm/internal/admission"
	"github.com/relux-works/a2a-swarm/internal/cg1cosign"
)

// Proves two distinct fully valid nonce-dependent co-signatures on one exact envelope remain one inbound/outbound replay identity, with fresh same-delivery retry.
func TestMatrixCosignatureIndependentReplay(t *testing.T) {
	for _, direction := range []string{"in", "out"} {
		t.Run(direction, func(t *testing.T) {
			f := newMatrixFixture(t)
			sender, to, scalar := matrixBob, matrixAlice, byte(2)
			if direction == "out" {
				sender, to, scalar = matrixAlice, matrixBob, 1
			}
			first := f.content(t, sender, to, f.body(sender, to, "hello", map[string]any{"cg1": nil}))
			raw := envelopeBytes(t, first)
			second := cloneContent(t, first)
			var fixture [32]byte
			fixture[31] = scalar
			key, _ := btcec.PrivKeyFromBytes(fixture[:])
			defer key.Zero()
			digest, e := cg1cosign.Digest(raw)
			if e != nil {
				t.Fatal(e)
			}
			var aux [32]byte
			aux[0] = 1
			sig, e := schnorr.Sign(key, digest[:], schnorr.CustomNonce(aux))
			if e != nil {
				t.Fatal(e)
			}
			co := second[cg1cosign.ContentKey].(map[string]any)
			co["sig"] = hex.EncodeToString(sig.Serialize())
			original := first[cg1cosign.ContentKey].(map[string]any)
			if co["sig"] == original["sig"] || !bytes.Equal(raw, envelopeBytes(t, second)) {
				t.Fatal("distinct signature/same envelope setup failed")
			}
			for _, content := range []map[string]any{first, second} {
				if _, e := (cg1cosign.BIP340{}).Verify(raw, content[cg1cosign.ContentKey]); e != nil {
					t.Fatal("fully valid co-signature control refused", e)
				}
			}
			check := func(content map[string]any, alternate bool) admission.Decision {
				var d admission.Decision
				var err error
				if direction == "in" {
					in := f.incoming(t, content)
					if alternate {
						in.EventID = "$second-signature-event"
					}
					d, err = f.c.Inbound(context.Background(), in)
				} else {
					out := f.outgoing(t, content)
					if alternate {
						out.TransactionID = "second-signature-transaction"
					}
					d, err = f.c.Outbound(context.Background(), out)
				}
				if err != nil {
					t.Fatal(err)
				}
				return d
			}
			if d := check(first, false); d.Verdict != admission.Live {
				t.Fatal("initial valid control refused", d)
			}
			path := filepath.Join(f.c.state, matrixJournalName)
			before := admissionReadMatrix(t, path)
			if d := check(second, true); d.Verdict != admission.Refused || d.Reason != "denied" || d.Retryable {
				t.Fatal("co-signature bytes created a second message", d)
			}
			if f.fake.inCalls+f.fake.outCalls != 1 || !bytes.Equal(before, admissionReadMatrix(t, path)) {
				t.Fatal("replay reached grantcheck or changed history")
			}
			if d := check(second, false); d.Verdict != admission.Live || f.fake.inCalls+f.fake.outCalls != 2 {
				t.Fatal("identical delivery retry was not freshly checked", d)
			}
			var journal matrixJournal
			if e := json.Unmarshal(admissionReadMatrix(t, path), &journal); e != nil {
				t.Fatal(e)
			}
			parsed, e := parseMatrixEnvelope(raw)
			if e != nil {
				t.Fatal(e)
			}
			if len(journal.Entries) != 1 {
				t.Fatal("one envelope became multiple ledger entries")
			}
			if _, ok := journal.Entries[strings.TrimPrefix(parsed.ID, "sha256:")]; !ok {
				t.Fatal("ledger does not key on envelope id")
			}
			entries, e := os.ReadDir(f.c.state)
			if e != nil {
				t.Fatal(e)
			}
			files := 0
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), "envelope-") {
					files++
				}
			}
			if files != 1 {
				t.Fatal("one envelope became multiple byte records", files)
			}
		})
	}
}
