package config

import (
	"os"
	"path/filepath"
	"testing"
)

// Proves roster selection is explicit, bounded and scoped to the original
// config root, with missing/malformed/relative inputs treated as unavailable.
func TestEnvelopeRosterPath(t *testing.T) {
	base := t.TempDir()
	p := Paths{Base: base}
	if got := EnvelopeRosterPath(p); got != "" {
		t.Fatal(got)
	}
	for _, tc := range []struct{ raw, want string }{
		{`{"roster_path":"/protected/roster.json"}`, "/protected/roster.json"},
		{`{"roster_path":"relative.json"}`, ""},
		{`{"roster_path":null}`, ""},
		{`{`, ""},
	} {
		if err := os.WriteFile(filepath.Join(base, "envelope-observe.json"), []byte(tc.raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := EnvelopeRosterPath(p); got != tc.want {
			t.Fatalf("got %q want %q", got, tc.want)
		}
	}
	p.Root = t.TempDir()
	if got := EnvelopeRosterPath(p); got != "" {
		t.Fatal("selected child config over original root")
	}
	if err := os.WriteFile(filepath.Join(p.Root, "envelope-observe.json"), []byte(`{"roster_path":"/original/roster.json"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := EnvelopeRosterPath(p); got != "/original/roster.json" {
		t.Fatal(got)
	}
	if err := os.Truncate(filepath.Join(p.Root, "envelope-observe.json"), 4097); err != nil {
		t.Fatal(err)
	}
	if got := EnvelopeRosterPath(p); got != "" {
		t.Fatal("oversized config accepted")
	}
}
