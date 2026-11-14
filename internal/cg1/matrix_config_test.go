package cg1

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/a2a-swarm/internal/admission"
)

// Proves the registered Matrix factory constructs the actual pinned W backend and rejects unsafe/mismatched config without repairing it.
func TestMatrixFactoryConfiguration(t *testing.T) {
	for _, mode := range []string{"valid", "mode", "symlink", "hardlink", "identity", "matrix-id-key", "duplicate-key", "alias", "changed-pins", "nostr"} {
		t.Run(mode, func(t *testing.T) {
			f := newMatrixFixture(t)
			path := filepath.Join(f.c.dir, matrixConfigName)
			cfg := admission.Config{Identity: "alice", StateDir: f.c.dir, MatrixUserID: matrixAlice}
			switch mode {
			case "mode":
				if e := os.Chmod(path, 0600); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				other := filepath.Join(f.c.dir, "config-source.json")
				if e := os.Rename(path, other); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(other, path); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				if e := os.Link(path, filepath.Join(f.c.dir, "linked.json")); e != nil {
					t.Fatal(e)
				}
			case "identity":
				cfg.MatrixUserID = matrixBob
			case "matrix-id-key":
				pin := f.cfg.Pins[matrixBob]
				pin.Key = matrixBob
				f.cfg.Pins[matrixBob] = pin
				f.save(t, f.c.dir)
			case "duplicate-key":
				b := admissionReadMatrix(t, path)
				b = append([]byte(`{"version":1,`), b[1:]...)
				if e := os.WriteFile(path, b, 0700); e != nil {
					t.Fatal(e)
				}
			case "alias":
				b := admissionReadMatrix(t, path)
				b = bytes.Replace(b, []byte(`"version"`), []byte(`"Version"`), 1)
				if e := os.WriteFile(path, b, 0700); e != nil {
					t.Fatal(e)
				}
			case "changed-pins":
				pin := f.cfg.Pins[matrixBob]
				pin.Key = xonly(3)
				f.cfg.Pins[matrixBob] = pin
				f.save(t, f.c.dir)
			case "nostr":
				cfg.Nostr = true
			}
			c, e := admission.Open(MatrixPolicy, cfg)
			if mode == "valid" {
				if e != nil {
					t.Fatal("valid W Matrix factory failed", e)
				}
				defer c.Close()
				d, e := c.Inbound(context.Background(), admission.Inbound{})
				want(t, d, e, admission.Refused, "denied", false)
			} else if e == nil || c != nil {
				if c != nil {
					c.Close()
				}
				t.Fatal("unsafe config accepted")
			}
		})
	}
}

// Proves immutable pin mutation and missing/corrupt replay state cannot recover by forgetting history; unchanged config has an adjacent valid control.
func TestMatrixStateRefusals(t *testing.T) {
	for _, mode := range []string{"missing", "corrupt", "changed-pins"} {
		t.Run(mode, func(t *testing.T) {
			f := newMatrixFixture(t)
			m := f.content(t, matrixBob, matrixAlice, f.body(matrixBob, matrixAlice, "hello", map[string]any{"cg1": nil}))
			d, e := f.c.Inbound(context.Background(), f.incoming(t, m))
			want(t, d, e, admission.Live, "allowed", false)
			switch mode {
			case "missing":
				if e := os.Remove(filepath.Join(f.c.state, matrixJournalName)); e != nil {
					t.Fatal(e)
				}
			case "corrupt":
				if e := os.WriteFile(filepath.Join(f.c.state, matrixJournalName), []byte(`{}`), 0600); e != nil {
					t.Fatal(e)
				}
			case "changed-pins":
				p := f.cfg.Pins[matrixBob]
				p.Key = xonly(3)
				f.cfg.Pins[matrixBob] = p
				f.save(t, f.c.dir)
			}
			d, e = f.c.Inbound(context.Background(), f.incoming(t, m))
			reason, retry := "storage_error", true
			if mode == "changed-pins" {
				reason, retry = "policy_invalid", false
			}
			want(t, d, e, admission.Refused, reason, retry)
			if f.fake.inCalls != 1 {
				t.Fatal("state refusal reached grantcheck")
			}
		})
	}
}
