package cli

import (
	"strings"
	"testing"

	"github.com/relux-works/a2a-swarm/internal/config"
)

// vaultB1Vector is the public B1 vector (B1-public-vector-r3.json, frozen r4 pack).
func vaultB1Vector() vaultConsumerBinding {
	return vaultConsumerBinding{BindingV: 1, Kind: "a2a-matrix", Purpose: "matrix-access-token", A2ASelector: "fixture-agent",
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
		mut   func(*vaultConsumerBinding)
	}{
		{"public B1 vector", nil},
		{"64-byte selector and 255-byte server (user_id 321 bytes)", func(b *vaultConsumerBinding) {
			b.A2ASelector, b.ServerName, b.UserID = sel64, server255, "@"+sel64+":"+server255
		}},
		{"HTTPS endpoint with different declared server", func(b *vaultConsumerBinding) { b.HomeserverURL = "https://matrix-a.example.invalid/" }},
		{"loopback HTTP", func(b *vaultConsumerBinding) { b.HomeserverURL = "http://127.0.0.1:8008" }},
	} {
		b := vaultB1Vector()
		if tc.mut != nil {
			tc.mut(&b)
		}
		if err := vaultValidateBinding(b); err != nil {
			t.Fatalf("%s vaultRefused: %v", tc.label, err)
		}
	}
	if b := vaultB1Vector(); len(b.UserID) > 321 {
		t.Fatal("fixture")
	}
	for _, tc := range []struct {
		label string
		mut   func(*vaultConsumerBinding)
		want  vaultCode
	}{
		{"source-valid 8193-byte URL", func(b *vaultConsumerBinding) { b.HomeserverURL = longURL(8193) }, vaultELimit},
		{"65-byte selector", func(b *vaultConsumerBinding) { b.A2ASelector = strings.Repeat("a", 65) }, vaultELimit},
		{"4097-byte server", func(b *vaultConsumerBinding) { b.ServerName = strings.Repeat("a", 4097) }, vaultELimit},
		{"4097-byte user_id", func(b *vaultConsumerBinding) { b.UserID = strings.Repeat("a", 4097) }, vaultELimit},
		{"limit beats version", func(b *vaultConsumerBinding) { b.BindingV = 2; b.A2ASelector = strings.Repeat("a", 65) }, vaultELimit},
		{"binding_v 2", func(b *vaultConsumerBinding) { b.BindingV = 2 }, vaultEVersion},
		{"binding_v 0", func(b *vaultConsumerBinding) { b.BindingV = 0 }, vaultEVersion},
		{"vaultUnknown kind", func(b *vaultConsumerBinding) { b.Kind = "a2a-xmpp" }, vaultEFormat},
		{"vaultUnknown purpose", func(b *vaultConsumerBinding) { b.Purpose = "matrix-password" }, vaultEFormat},
		{"empty selector", func(b *vaultConsumerBinding) { b.A2ASelector = ""; b.UserID = "@:example.invalid" }, vaultEFormat},
		{"uppercase selector", func(b *vaultConsumerBinding) {
			b.A2ASelector = "Fixture-agent"
			b.UserID = "@Fixture-agent:example.invalid"
		}, vaultEFormat},
		{"control in URL", func(b *vaultConsumerBinding) { b.HomeserverURL = "https://matrix.example.invalid\u0085" }, vaultEFormat},
		{"256-byte server within envelope", func(b *vaultConsumerBinding) {
			s := server255 + "8" // 256 bytes, port 84488 also invalid; within the 4096 envelope
			b.ServerName, b.UserID = s, "@fixture-agent:"+s
		}, vaultEFormat},
		{"65-byte localpart in user_id within envelope", func(b *vaultConsumerBinding) { b.UserID = "@" + strings.Repeat("a", 65) + ":example.invalid" }, vaultEFormat},
		{"user_id not exact selector MXID", func(b *vaultConsumerBinding) { b.UserID = "@fixture-agent:other.invalid" }, vaultEFormat},
		{"remote HTTP", func(b *vaultConsumerBinding) { b.HomeserverURL = "http://matrix.example.invalid" }, vaultEFormat},
		{"URL with path", func(b *vaultConsumerBinding) { b.HomeserverURL = "https://matrix.example.invalid/_matrix" }, vaultEFormat},
		{"URL with userinfo", func(b *vaultConsumerBinding) { b.HomeserverURL = "https://u@matrix.example.invalid" }, vaultEFormat},
	} {
		b := vaultB1Vector()
		tc.mut(&b)
		if got := vaultTestCode(t, vaultValidateBinding(b)); got != tc.want {
			t.Fatalf("%s: got %s want %s", tc.label, got, tc.want)
		}
	}
	// The 8192-byte URL is the positive neighbour of the 8193-byte limit case.
	b := vaultB1Vector()
	b.HomeserverURL = longURL(8192)
	if len(b.HomeserverURL) != 8192 || config.ValidateMatrixRouting(b.HomeserverURL, b.ServerName) != nil || vaultValidateBinding(b) != nil {
		t.Fatal("8192-byte source-valid URL neighbour was not admitted")
	}
	if u := longURL(8193); len(u) != 8193 || config.ValidateMatrixRouting(u, b.ServerName) != nil {
		t.Fatal("8193-byte URL fixture is not source-valid; the limit case would be vacuous")
	}
}

// Claim: vaultDeriveBinding takes the selector, full MXID, endpoint and declared
// server exactly from the selected agents-class ConnectionBinding, keeps URL
// spellings distinct, and refuses the humans class before any other use.
func TestDeriveBinding(t *testing.T) {
	c := config.Connection{ID: "fixture-a", URL: "https://matrix-a.example.invalid/", ServerName: "a.example.invalid", Store: config.CredentialStore{Backend: config.BackendVaultV1}}
	b, err := c.Binding("fixture", false)
	if err != nil {
		t.Fatal(err)
	}
	got, err := vaultDeriveBinding("fixture", b)
	want := vaultConsumerBinding{BindingV: 1, Kind: vaultBindingKind, Purpose: vaultBindingPurpose, A2ASelector: "fixture", UserID: "@fixture:a.example.invalid", HomeserverURL: "https://matrix-a.example.invalid/", ServerName: "a.example.invalid"}
	if err != nil || got != want {
		t.Fatalf("derived %+v, %v", got, err)
	}
	h, err := c.Binding("fixture", true)
	if err != nil {
		t.Fatal(err)
	}
	if got := vaultTestCode(t, func() error { _, e := vaultDeriveBinding("fixture", h); return e }()); got != vaultEBackendConfig {
		t.Fatalf("humans class: %s", got)
	}
}
