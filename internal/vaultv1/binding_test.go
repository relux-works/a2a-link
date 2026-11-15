package vaultv1

import (
	"strings"
	"testing"

	"github.com/relux-works/a2a-swarm/internal/config"
)

// b1Vector is the public B1 vector (B1-public-vector-r3.json, frozen r4 pack).
func b1Vector() ConsumerBinding {
	return ConsumerBinding{BindingV: 1, Kind: "a2a-matrix", Purpose: "matrix-access-token", A2ASelector: "fixture-agent",
		UserID: "@fixture-agent:example.invalid", HomeserverURL: "https://matrix.example.invalid", ServerName: "example.invalid"}
}

// Claim: B1 validation admits the public vector and the source/native
// intersection neighbours, and refuses each one-variable change with the r4
// precedence: native byte limit E_LIMIT before typed version E_VERSION before
// fixed kind/purpose, representation and pinned source predicates E_FORMAT.
func TestBindingValidation(t *testing.T) {
	// validServerName caps the host at 253 bytes; a port reaches 255.
	server255 := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 58) + ":8448"
	if len(server255) != 255 {
		t.Fatal("fixture length")
	}
	sel64 := "s" + strings.Repeat("x", 63)
	// A syntactically root URL with a long valid hostname: total exactly 8192.
	longURL := func(n int) string {
		host := ""
		for len(host) < n-len("https://")-64 {
			host += strings.Repeat("h", 62) + "."
		}
		host += strings.Repeat("z", n-len("https://")-len(host))
		return "https://" + host
	}
	for _, tc := range []struct {
		label string
		mut   func(*ConsumerBinding)
	}{
		{"public B1 vector", nil},
		{"64-byte selector and 255-byte server (user_id 321 bytes)", func(b *ConsumerBinding) {
			b.A2ASelector, b.ServerName, b.UserID = sel64, server255, "@"+sel64+":"+server255
		}},
		{"HTTPS endpoint with different declared server", func(b *ConsumerBinding) { b.HomeserverURL = "https://matrix-a.example.invalid/" }},
		{"loopback HTTP", func(b *ConsumerBinding) { b.HomeserverURL = "http://127.0.0.1:8008" }},
	} {
		b := b1Vector()
		if tc.mut != nil {
			tc.mut(&b)
		}
		if err := ValidateBinding(b); err != nil {
			t.Fatalf("%s refused: %v", tc.label, err)
		}
	}
	if b := b1Vector(); len(b.UserID) > 321 {
		t.Fatal("fixture")
	}
	for _, tc := range []struct {
		label string
		mut   func(*ConsumerBinding)
		want  Code
	}{
		{"source-valid 8193-byte URL", func(b *ConsumerBinding) { b.HomeserverURL = longURL(8193) }, ELimit},
		{"65-byte selector", func(b *ConsumerBinding) { b.A2ASelector = strings.Repeat("a", 65) }, ELimit},
		{"4097-byte server", func(b *ConsumerBinding) { b.ServerName = strings.Repeat("a", 4097) }, ELimit},
		{"4097-byte user_id", func(b *ConsumerBinding) { b.UserID = strings.Repeat("a", 4097) }, ELimit},
		{"limit beats version", func(b *ConsumerBinding) { b.BindingV = 2; b.A2ASelector = strings.Repeat("a", 65) }, ELimit},
		{"binding_v 2", func(b *ConsumerBinding) { b.BindingV = 2 }, EVersion},
		{"binding_v 0", func(b *ConsumerBinding) { b.BindingV = 0 }, EVersion},
		{"unknown kind", func(b *ConsumerBinding) { b.Kind = "a2a-xmpp" }, EFormat},
		{"unknown purpose", func(b *ConsumerBinding) { b.Purpose = "matrix-password" }, EFormat},
		{"empty selector", func(b *ConsumerBinding) { b.A2ASelector = ""; b.UserID = "@:example.invalid" }, EFormat},
		{"uppercase selector", func(b *ConsumerBinding) { b.A2ASelector = "Fixture-agent"; b.UserID = "@Fixture-agent:example.invalid" }, EFormat},
		{"control in URL", func(b *ConsumerBinding) { b.HomeserverURL = "https://matrix.example.invalid\u0085" }, EFormat},
		{"256-byte server within envelope", func(b *ConsumerBinding) {
			s := server255 + "8" // 256 bytes, port 84488 also invalid; within the 4096 envelope
			b.ServerName, b.UserID = s, "@fixture-agent:"+s
		}, EFormat},
		{"65-byte localpart in user_id within envelope", func(b *ConsumerBinding) { b.UserID = "@" + strings.Repeat("a", 65) + ":example.invalid" }, EFormat},
		{"user_id not exact selector MXID", func(b *ConsumerBinding) { b.UserID = "@fixture-agent:other.invalid" }, EFormat},
		{"remote HTTP", func(b *ConsumerBinding) { b.HomeserverURL = "http://matrix.example.invalid" }, EFormat},
		{"URL with path", func(b *ConsumerBinding) { b.HomeserverURL = "https://matrix.example.invalid/_matrix" }, EFormat},
		{"URL with userinfo", func(b *ConsumerBinding) { b.HomeserverURL = "https://u@matrix.example.invalid" }, EFormat},
	} {
		b := b1Vector()
		tc.mut(&b)
		if got := code(t, ValidateBinding(b)); got != tc.want {
			t.Fatalf("%s: got %s want %s", tc.label, got, tc.want)
		}
	}
	// The 8192-byte URL is the positive neighbour of the 8193-byte limit case.
	b := b1Vector()
	b.HomeserverURL = longURL(8192)
	if len(b.HomeserverURL) != 8192 || config.ValidateMatrixRouting(b.HomeserverURL, b.ServerName) != nil || ValidateBinding(b) != nil {
		t.Fatal("8192-byte source-valid URL neighbour was not admitted")
	}
	if u := longURL(8193); len(u) != 8193 || config.ValidateMatrixRouting(u, b.ServerName) != nil {
		t.Fatal("8193-byte URL fixture is not source-valid; the limit case would be vacuous")
	}
}

// Claim: DeriveBinding takes the selector, full MXID, endpoint and declared
// server exactly from the selected agents-class ConnectionBinding, keeps URL
// spellings distinct, and refuses the humans class before any other use.
func TestDeriveBinding(t *testing.T) {
	c := config.Connection{ID: "fixture-a", URL: "https://matrix-a.example.invalid/", ServerName: "a.example.invalid", Store: config.CredentialStore{Backend: config.BackendVaultV1}}
	b, err := c.Binding("fixture", false)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DeriveBinding("fixture", b)
	want := ConsumerBinding{BindingV: 1, Kind: BindingKind, Purpose: BindingPurpose, A2ASelector: "fixture", UserID: "@fixture:a.example.invalid", HomeserverURL: "https://matrix-a.example.invalid/", ServerName: "a.example.invalid"}
	if err != nil || got != want {
		t.Fatalf("derived %+v, %v", got, err)
	}
	h, err := c.Binding("fixture", true)
	if err != nil {
		t.Fatal(err)
	}
	if got := code(t, func() error { _, e := DeriveBinding("fixture", h); return e }()); got != EBackendConfig {
		t.Fatalf("humans class: %s", got)
	}
}
