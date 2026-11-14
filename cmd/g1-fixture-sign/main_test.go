package main

import (
	"bytes"
	"encoding/json"
	"github.com/relux-works/a2a-swarm/internal/cg1cosign"
	"os"
	"path/filepath"
	"testing"
)

// Proves the helper emits a verifiable fixture signature and no output for unknown keys, custody flags, missing files or oversize input.
func TestFixtureCLI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "envelope.json")
	raw := []byte("{}\n")
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	var out bytes.Buffer
	if e := run([]string{"--fixture", "alice", "--envelope", path}, &out); e != nil {
		t.Fatal(e)
	}
	var co map[string]any
	if json.Unmarshal(out.Bytes(), &co) != nil {
		t.Fatal("invalid helper output")
	}
	if _, e := (cg1cosign.BIP340{}).Verify(raw, co); e != nil {
		t.Fatal(e)
	}
	for _, args := range [][]string{{"--fixture", "real", "--envelope", path}, {"--private-key", path, "--fixture", "alice", "--envelope", path}, {"--fixture", "alice", "--envelope", path + ".missing"}, {"--fixture", "alice"}} {
		out.Reset()
		if e := run(args, &out); e == nil || out.Len() != 0 {
			t.Fatal("invalid fixture request released output")
		}
	}
	if e := os.WriteFile(path, make([]byte, 65537), 0600); e != nil {
		t.Fatal(e)
	}
	out.Reset()
	if e := run([]string{"--fixture", "alice", "--envelope", path}, &out); e == nil || out.Len() != 0 {
		t.Fatal("oversize input released output")
	}
}
