package al3smoke

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func transcriptFixture() ([]Evidence, []Evidence, string, string, string, string) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	url, run := "ws://127.0.0.1:12345", "0123456789abcdef"
	id1, id2 := strings.Repeat("1", 64), strings.Repeat("2", 64)
	routes := map[string][]string{a: {url}, b: {url}}
	ping, pong := "al3:"+run+":ping", "al3:"+run+":pong"
	return []Evidence{{Type: "ready", Role: "a", Sender: a, Recipient: b}, {Type: "sent", Role: "a", ID: id1, Sender: a, Recipient: b, Text: ping, Routes: routes}, {Type: "received", Role: "a", ID: id2, Sender: b, Recipient: a, Text: pong}, {Type: "complete", Role: "a"}}, []Evidence{{Type: "ready", Role: "b", Sender: b, Recipient: a}, {Type: "received", Role: "b", ID: id1, Sender: a, Recipient: b, Text: ping}, {Type: "sent", Role: "b", ID: id2, Sender: b, Recipient: a, Text: pong, Routes: routes}, {Type: "complete", Role: "b"}}, a, b, url, run
}

// Missing/extra/reordered events, wrong verified tuples, unmatched IDs, payload
// changes and route drift must not normalize into the same successful result.
func TestTranscriptRefusals(t *testing.T) {
	a, b, self, peer, url, run := transcriptFixture()
	want, e := Normalize(a, b, self, peer, url, run)
	if e != nil || !json.Valid(want) {
		t.Fatal("valid neighbor")
	}
	for _, name := range []string{"missing", "duplicate", "order", "sender", "recipient", "id", "same-id", "text", "route", "pending", "ready"} {
		t.Run(name, func(t *testing.T) {
			x, y, sa, sb, u, r := transcriptFixture()
			switch name {
			case "missing":
				x = x[:3]
			case "duplicate":
				x = append(x, x[1])
			case "order":
				x[1], x[2] = x[2], x[1]
			case "sender":
				x[2].Sender = sa
			case "recipient":
				x[2].Recipient = sb
			case "id":
				x[2].ID = strings.Repeat("3", 64)
			case "same-id":
				x[2].ID = x[1].ID
				y[2].ID = x[1].ID
			case "text":
				x[2].Text = "wrong"
			case "route":
				x[1].Routes[sa] = []string{"wss://other.invalid"}
			case "pending":
				x[3].Pending = 1
			case "ready":
				x[0].Sender = sb
			}
			if got, e := Normalize(x, y, sa, sb, u, r); e == nil || got != nil {
				t.Fatal("invalid transcript normalized", name)
			}
		})
	}
	// A new run's correlated IDs are different, but its validated result is equal.
	a[1].ID = strings.Repeat("4", 64)
	b[1].ID = a[1].ID
	a[2].ID = strings.Repeat("5", 64)
	b[2].ID = a[2].ID
	got, e := Normalize(a, b, self, peer, url, run)
	if e != nil || !bytes.Equal(got, want) {
		t.Fatal("valid normalized run changed")
	}
}
