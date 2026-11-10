package nostrsession

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fx "github.com/relux-works/a2a-swarm/internal/nostrtest"
)

// Carrier keys cannot use escapes. Decoded certificate duplicate detection
// compares unescaped keys at every nesting level without rewriting proof bytes.
func TestPresentationUniqueJSON(t *testing.T) {
	valid := []byte(`{"grant":{"scope":["deliver"]}}`)
	carrier := fx.Carrier(t, strings.Repeat("a", 64), valid)
	p, e := presentation(carrier)
	if e != nil || !bytes.Equal(p.Bytes, valid) {
		t.Fatal("valid carrier refused", e)
	}
	escaped := bytes.Replace(carrier, []byte(`"grant_id"`), []byte(`"grant_\u0069d"`), 1)
	if _, e := presentation(escaped); e != ErrPresentation {
		t.Fatal("escaped carrier key accepted", e)
	}
	certificate := []byte(`{"gr\u0061nt":{"scope":["deliver"]}}`)
	if got, e := presentation(fx.Carrier(t, strings.Repeat("a", 64), certificate)); e != nil || !bytes.Equal(got.Bytes, certificate) {
		t.Fatal("opaque certificate bytes rewritten or refused", e)
	}
	for _, pair := range [][2]string{{`"x":1`, `"x":2`}, {`"x":1`, `"\u0078":2`}, {`"v":1`, `"\u0076":2`}} {
		for reverse := 0; reverse < 2; reverse++ {
			a, b := pair[reverse], pair[1-reverse]
			for _, raw := range []string{"{" + a + "," + b + "}", `{"nested":[{` + a + "," + b + "}]}"} {
				if uniqueJSON([]byte(raw)) {
					t.Fatalf("accepted duplicate keys: %s", raw)
				}
				if _, e := presentation(fx.Carrier(t, strings.Repeat("a", 64), []byte(raw))); e != ErrPresentation {
					t.Fatal("duplicate certificate accepted", e)
				}
			}
		}
	}
	for _, extra := range []string{`"v":2,`, `"\u0076":2,`} {
		for _, raw := range []string{"{" + extra + string(carrier[1:]), string(carrier[:len(carrier)-1]) + "," + strings.TrimSuffix(extra, ",") + "}"} {
			if _, e := presentation([]byte(raw)); e != ErrPresentation {
				t.Fatal("duplicate carrier accepted", e)
			}
		}
	}
	for _, raw := range []string{`null`, `[]`, `1`, `{} {}`, strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66)} {
		if _, e := presentation(fx.Carrier(t, strings.Repeat("a", 64), []byte(raw))); e != ErrPresentation {
			t.Fatal("non-object/deep/trailing proof accepted", e)
		}
	}
}

// Only a private, physical, explicit host configuration selects a session.
// Invalid metadata never falls back, repairs permissions, or initializes a key.
func TestHostConfigurationClosed(t *testing.T) {
	base := fx.Root(t)
	root := Root(base, "alice")
	if selected, e := Selected(base, "alice"); e != nil || selected {
		t.Fatal("absent namespace selected")
	}
	if selected, _ := Selected(base, "../alice"); selected {
		t.Fatal("invalid identity selected")
	}
	good := []byte(`{"version":1,"admission_policy":"none","settings":{"read_relays":"[\"ws://127.0.0.1:1\"]"}}`)
	fx.Write(t, filepath.Join(root, "session.json"), good)
	if selected, e := Selected(base, "alice"); e != nil || !selected {
		t.Fatal("host namespace not selected")
	}
	if _, cfg, e := readSettings(root); e != nil || cfg.Policy != "none" {
		t.Fatal("valid host configuration", e)
	}
	for _, raw := range [][]byte{
		[]byte(`{}`), []byte(`null`), []byte(`{"version":1,"admission_policy":"unknown"}`),
		bytes.Replace(good, []byte(`"version"`), []byte(`"Version"`), 1),
		bytes.Replace(good, []byte(`"admission_policy":"none"`), []byte(`"admission_policy":"none","admission_\u0070olicy":"cg1"`), 1),
		append(bytes.Clone(good), []byte(` {}`)...),
	} {
		fx.Write(t, filepath.Join(root, "session.json"), raw)
		if _, _, e := readSettings(root); e != ErrConfiguration {
			t.Fatal("invalid configuration accepted", e)
		}
	}
	fx.Write(t, filepath.Join(root, "session.json"), good)
	if e := os.Chmod(filepath.Join(root, "session.json"), 0644); e != nil {
		t.Fatal(e)
	}
	if _, _, e := readSettings(root); e != ErrConfiguration {
		t.Fatal("broad file accepted")
	}
	if e := os.Chmod(filepath.Join(root, "session.json"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(root, 0755); e != nil {
		t.Fatal(e)
	}
	if _, _, e := readSettings(root); e != ErrConfiguration {
		t.Fatal("broad root accepted")
	}
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(base, "linked")
	if e := os.Symlink(root, link); e != nil {
		t.Fatal(e)
	}
	if _, _, e := readSettings(link); e != ErrConfiguration {
		t.Fatal("linked namespace accepted")
	}
	if e := os.Rename(filepath.Join(root, "session.json"), filepath.Join(root, "actual.json")); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("actual.json", filepath.Join(root, "session.json")); e != nil {
		t.Fatal(e)
	}
	if _, _, e := readSettings(root); e != ErrConfiguration {
		t.Fatal("linked file accepted")
	}
	var cfg settings
	if json.Unmarshal(good, &cfg) != nil {
		t.Fatal("invalid positive fixture")
	}
}
