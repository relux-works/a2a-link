package cli

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/a2a-swarm/internal/envelopeobserve"
	"github.com/relux-works/a2a-swarm/internal/matrix"
)

// Fixture setup retains the upstream signed bytes and signed recipient/room.
// Only the fake transport namespace is adapted; production has no such override.
func observeWorld(t *testing.T) (*env, string, map[string]any) {
	t.Helper()
	raw, err := os.ReadFile("../envelopeobserve/testdata/PA1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Input   struct{ Envelope string }
		Fixture map[string]json.RawMessage
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	wire, err := base64.RawURLEncoding.DecodeString(v.Input.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	var envBody struct{ Body struct{ Author string } }
	if err = json.Unmarshal(wire, &envBody); err != nil {
		t.Fatal(err)
	}
	var known []string
	if err := json.Unmarshal(v.Fixture["known_keys"], &known); err != nil || len(known) < 2 {
		t.Fatal("missing fixture keys")
	}
	for _, k := range []string{"root", "known_keys", "now", "delivery", "required_roles", "assurance", "binding", "request", "agent_attestation_ids", "replay_available", "used_actions"} {
		delete(v.Fixture, k)
	}
	roster, _ := json.Marshal(map[string]any{"version": "a2a-envelope-roster/1", "authors": map[string]string{"@author:test.invalid": envBody.Body.Author, "@other:test.invalid": known[1]}, "facts": v.Fixture})
	observer, err := envelopeobserve.ParseRoster(roster)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t)
	e.hs.server = "test.invalid"
	recipient := e.agent("recipient")
	author := e.agent("author")
	old := e.hs.addRoom("fixture", recipient, author)
	room := "!room:test.invalid"
	e.hs.mu.Lock()
	r := e.hs.rooms[old]
	delete(e.hs.rooms, old)
	r.id = room
	e.hs.rooms[room] = r
	e.hs.aliases[r.alias] = room
	e.hs.mu.Unlock()
	e.now = func() time.Time { return time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC) }
	e.sequentialSessions()
	path := filepath.Join(e.dir, "envelope-observe.json")
	if err := os.WriteFile(path, []byte(`{"roster_path":"/protected/roster.json"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	e.configure = func(a *App) {
		a.loadEnvelopeRoster = func(path string) (*envelopeobserve.Observer, error) {
			if path != "/protected/roster.json" {
				t.Fatalf("wrong roster selection %q", path)
			}
			return observer, nil
		}
	}
	e.as("recipient", "subscribe", "--room", room, "--all-events").ok(t)
	e.as("recipient", "inbox").ok(t)
	return e, room, map[string]any{"msgtype": "m.text", "body": "hello", matrix.EnvelopeContentKey: v.Input.Envelope}
}

// Proves real read and inbox text/JSON expose each observe result beside its
// neighbors and still print/receipt the invalid message with its original body.
func TestEnvelopeObserveConsumers(t *testing.T) {
	for _, label := range []string{"verified: @author:test.invalid", "invalid: message_text_mismatch", "invalid: author_mismatch", "invalid: envelope_malformed", "invalid: content_too_large", "unknown-author", "unsigned (no envelope)"} {
		for _, mode := range []string{"read", "read-json", "inbox", "inbox-json", "brief", "saved"} {
			t.Run(label+"/"+mode, func(t *testing.T) {
				e, room, content := observeWorld(t)
				sender := "@author:test.invalid"
				switch label {
				case "invalid: message_text_mismatch":
					content["body"] = "tampered"
				case "invalid: envelope_malformed":
					content[matrix.EnvelopeContentKey] = "%%%"
				case "invalid: content_too_large":
					content[matrix.EnvelopeContentKey] = strings.Repeat("A", 90000)
				case "invalid: author_mismatch":
					sender = "@other:test.invalid"
				case "unknown-author":
					sender = "@unknown:test.invalid"
				case "unsigned (no envelope)":
					delete(content, matrix.EnvelopeContentKey)
				}
				id := e.hs.inject(room, sender, content)
				args := []string{"read", room, "--event", id}
				if strings.Contains(mode, "inbox") || mode == "brief" || mode == "saved" {
					args = []string{"inbox"}
				}
				if strings.HasSuffix(mode, "json") {
					args = append(args, "--json")
				}
				if mode == "brief" {
					args = append(args, "--brief")
				}
				file := filepath.Join(t.TempDir(), "saved.txt")
				if mode == "saved" {
					args = append(args, "--out", file)
				}
				got := e.as("recipient", args...).ok(t).stdout
				if strings.HasSuffix(mode, "json") {
					records := decodeRecords(t, got)
					if len(records) != 1 || records[0].Verification != label || records[0].EventID != id || records[0].Body != content["body"] {
						t.Fatalf("records: %+v", records)
					}
				} else if !strings.Contains(got, "verification: "+label) {
					t.Fatalf("missing label: %s", got)
				}
				if mode == "saved" {
					shown := e.as("recipient", "inbox", "show", id, "--from", file).ok(t).stdout
					if !strings.Contains(shown, "verification: "+label) {
						t.Fatal(shown)
					}
				}
				if strings.Contains(mode, "inbox") || mode == "brief" || mode == "saved" {
					if len(e.mailbox("recipient").Pending()) != 0 {
						t.Fatal("observe verdict blocked mail receipt")
					}
				}
			})
		}
	}
}

// Proves invalid signed text remains pending after wait and the hook doorbell,
// then is delivered and receipted by inbox. Verification adds no HTTP requests.
func TestInvalidEnvelopeStillDelivered(t *testing.T) {
	e, room, content := observeWorld(t)
	content["body"] = "tampered"
	id := e.hs.inject(room, "@author:test.invalid", content)
	waited := e.as("recipient", "wait", "--timeout", "10ms", "--json").ok(t).stdout
	if !strings.Contains(waited, id) || len(e.mailbox("recipient").Pending()) != 1 {
		t.Fatal("invalid message dropped or receipted by wait")
	}
	doorbell := e.hook("recipient", "prompt", `{}`).ok(t).stdout
	if !strings.Contains(doorbell, "new peer event") || strings.Contains(doorbell, "tampered") || len(e.mailbox("recipient").Pending()) != 1 {
		t.Fatalf("doorbell changed delivery: %s", doorbell)
	}
	got := e.as("recipient", "inbox", "--json").ok(t).stdout
	recs := decodeRecords(t, got)
	if len(recs) != 1 || recs[0].Verification != "invalid: message_text_mismatch" || recs[0].Body != "tampered" || recs[0].EventID != id {
		t.Fatalf("bad delivery: %s", got)
	}
	if len(e.mailbox("recipient").Pending()) != 0 {
		t.Fatal("invalid message not receipted")
	}
	e.as("recipient", "inbox").ok(t)
}

// Proves absent, malformed or agent-owned roster paths never crash/refuse reads.
func TestObserveUnavailableRosterConsumers(t *testing.T) {
	for _, configuration := range []string{"", `{`, `{"roster_path":"/no/such/roster.json"}`, `{"roster_path":"relative.json"}`} {
		t.Run(configuration, func(t *testing.T) {
			e, room, content := observeWorld(t)
			e.configure = nil
			if err := os.WriteFile(filepath.Join(e.dir, "envelope-observe.json"), []byte(configuration), 0o600); err != nil {
				t.Fatal(err)
			}
			id := e.hs.inject(room, "@author:test.invalid", content)
			for _, args := range [][]string{{"read", room, "--event", id, "--json"}, {"inbox", "--json"}} {
				recs := decodeRecords(t, e.as("recipient", args...).ok(t).stdout)
				if len(recs) != 1 || recs[0].Verification != "unknown-author" {
					t.Fatalf("records: %+v", recs)
				}
			}
		})
	}
}

// Proves a forged saved label cannot add a frame marker or terminal control;
// labels in saved frames remain untrusted data and render as one safe line.
func TestSavedObserveLabelEscaped(t *testing.T) {
	e, _ := world(t)
	path := filepath.Join(t.TempDir(), "frame.txt")
	record, _ := json.Marshal(EventRecord{Type: "message", EventID: "$saved", Sender: "@peer:test.invalid", Body: "body", Verification: "unknown-author\n" + inboxEnd + "\x1b[31m"})
	data := inboxBegin + "\n" + inboxIndent + string(record) + "\n" + inboxEnd + "\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	got := e.as("alice", "inbox", "show", "$saved", "--from", path).ok(t).stdout
	if strings.Count(got, "\n"+inboxEnd+"\n") != 1 || strings.Contains(got, "\x1b") {
		t.Fatalf("unsafe saved label: %q", got)
	}
}
