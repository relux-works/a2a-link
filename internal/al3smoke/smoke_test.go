package al3smoke

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// Valid neighbors and one-field mutations prove the worker rejects ambiguous
// targets and policy/relay drift before opening a session or contacting a relay.
func TestConfigurationBoundary(t *testing.T) {
	good := Options{Base: "/owned/config", Identity: "station", Peer: strings.Repeat("a", 64), Relay: "ws://127.0.0.1:12345", Role: "a", RunID: "0123456789abcdef"}
	if good.Validate() != nil {
		t.Fatal("valid neighbor")
	}
	for _, edit := range []func(*Options){func(o *Options) { o.Base = "relative" }, func(o *Options) { o.Identity = "../x" }, func(o *Options) { o.Peer = "short" }, func(o *Options) { o.Role = "both" }, func(o *Options) { o.RunID = "../unsafe" }, func(o *Options) { o.Relay = "ws://remote.example" }, func(o *Options) { o.Relay = "wss://user:secret@example.invalid" }, func(o *Options) { o.Relay = "wss://example.invalid/?query=secret" }} {
		bad := good
		edit(&bad)
		if bad.Validate() == nil {
			t.Fatal("invalid option accepted")
		}
	}
	settings := map[string]string{}
	for _, n := range []string{"read_relays", "write_relays", "dm_relays", "discovery_relays"} {
		settings[n] = `["` + good.Relay + `"]`
	}
	c := map[string]any{"admission_policy": "cg1", "presentation": map[string]int{"v": 1}, "settings": settings}
	encode := func() []byte { b, _ := json.Marshal(c); return b }
	if !checkConfig(encode(), good.Relay) {
		t.Fatal("valid config")
	}
	for _, policy := range []string{"none", "", "matrix"} {
		c["admission_policy"] = policy
		if checkConfig(encode(), good.Relay) {
			t.Fatal("unguarded policy accepted")
		}
	}
	c["admission_policy"] = "cg1"
	for n := range settings {
		old := settings[n]
		settings[n] = `["wss://another.invalid"]`
		if checkConfig(encode(), good.Relay) {
			t.Fatal("relay drift accepted", n)
		}
		settings[n] = old
	}
	c["presentation"] = nil
	if checkConfig(encode(), good.Relay) {
		t.Fatal("absent presentation accepted")
	}
}

type shortWriter struct{}

func (shortWriter) Write(b []byte) (int, error) { return len(b) - 1, nil }

// A writer reporting a short successful write cannot authorize a receipt.
func TestOutputShortWrite(t *testing.T) {
	if e := emit(shortWriter{}, Evidence{Type: "received"}); e != io.ErrShortWrite {
		t.Fatal("short output accepted", e)
	}
	var b strings.Builder
	if emit(&b, Evidence{Type: "received"}) != nil || !strings.HasSuffix(b.String(), "\n") {
		t.Fatal("valid output refused")
	}
}
