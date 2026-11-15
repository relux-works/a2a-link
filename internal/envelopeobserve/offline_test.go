package envelopeobserve

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

type forbiddenNetwork struct{ t *testing.T }

func (f forbiddenNetwork) RoundTrip(*http.Request) (*http.Response, error) {
	f.t.Error("verification attempted network I/O")
	return nil, errors.New("offline verification")
}

// Proves the valid and tampered vector path needs no default HTTP transport;
// carrier collection is tested separately and legitimately uses the fake server.
func TestObserveOffline(t *testing.T) {
	previous := http.DefaultTransport
	http.DefaultTransport = forbiddenNetwork{t}
	defer func() { http.DefaultTransport = previous }()
	o, ev, room, to, now := fromVector(t, loadVector(t, "PA1"))
	if got := o.Observe(ev, room, to, now); got != "verified: @author:test.invalid" {
		t.Fatal(got)
	}
	ev.Content = []byte(strings.Replace(string(ev.Content), `"body":"hello"`, `"body":"tampered"`, 1))
	if got := o.Observe(ev, room, to, now); got != "invalid: message_text_mismatch" {
		t.Fatal(got)
	}
}
