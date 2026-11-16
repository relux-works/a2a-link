package envelopeobserve

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/a2a-swarm/internal/matrix"
	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-envelope/verifier"
)

type vector struct {
	ID    string `json:"id"`
	Input struct {
		Envelope string `json:"envelope"`
	} `json:"input"`
	Fixture  map[string]json.RawMessage `json:"fixture"`
	Expected struct {
		Code string `json:"code"`
	} `json:"expected"`
}

func loadVector(t *testing.T, name string) vector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}
func fromVector(t *testing.T, v vector) (*Observer, matrix.Event, string, string, time.Time) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(v.Input.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Body struct {
			Author string `json:"author"`
		} `json:"body"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	facts := map[string]json.RawMessage{}
	// Only fields in the production host contract are selected; now/delivery
	// always come from the actual receive context, never signed claims.
	var keys []string
	for name := range map[string]bool{"audience": true, "service_root": true, "agent_revocation_root": true, "operator_root": true, "operator_owner": true, "attestations": true, "operator_attestations": true, "active_generations": true, "revocations": true, "time": true, "watermark_available": true, "watermark": true, "id_journal_available": true, "seen": true, "signer_facts": true, "commit_signing_key": true, "enrollment_publisher": true} {
		keys = append(keys, name)
	}
	for _, name := range keys {
		if f, ok := v.Fixture[name]; ok {
			facts[name] = f
		}
	}
	data, err := json.Marshal(map[string]any{"version": "a2a-envelope-roster/1", "authors": map[string]string{"@author:test.invalid": envelope.Body.Author}, "facts": facts})
	if err != nil {
		t.Fatal(err)
	}
	o, err := ParseRoster(data)
	if err != nil {
		t.Fatal(err)
	}
	var d struct{ Room, To, Text string }
	if err := json.Unmarshal(v.Fixture["delivery"], &d); err != nil {
		t.Fatal(err)
	}
	text, err := base64.RawURLEncoding.DecodeString(d.Text)
	if err != nil {
		t.Fatal(err)
	}
	content, _ := json.Marshal(map[string]any{"msgtype": "m.text", "body": string(text), matrix.EnvelopeContentKey: v.Input.Envelope})
	var now string
	if err := json.Unmarshal(v.Fixture["now"], &now); err != nil {
		t.Fatal(err)
	}
	at, err := time.Parse(time.RFC3339, now)
	if err != nil {
		t.Fatal(err)
	}
	return o, matrix.Event{Type: "m.room.message", Sender: "@author:test.invalid", Content: content}, d.Room, d.To, at
}

// Proves the consumer's real verifier invocation agrees with this unmodified
// upstream subset, including exact UTF8 body, audience binding and both agent curves.
func TestObserveVectorOracle(t *testing.T) {
	for _, name := range []string{"PA1", "PC2", "C01", "C02", "C04", "C05", "C11", "E12", "P-BIP-author", "P-BIP-high-s", "N-BIP-body-binding", "N-BIP-bad-signature", "N-BIP-author-key"} {
		t.Run(name, func(t *testing.T) {
			v := loadVector(t, name)
			o, ev, room, to, now := fromVector(t, v)
			want := invalid(v.Expected.Code)
			if v.Expected.Code == "accept" {
				want = "verified: @author:test.invalid"
			}
			if got := o.Observe(ev, room, to, now); got != want {
				t.Fatalf("got %q, oracle %q", got, want)
			}
		})
	}
}

// Proves valid and neighboring invalid/unknown/unsigned cases remain distinct;
// tampered-body must fail if the pinned verifier call is planted always-success.
func TestObserveLabels(t *testing.T) {
	for _, name := range []string{"valid", "carrier-numbers", "tampered-body", "wrong-author", "unknown-author", "missing-envelope", "missing-roster", "oversize", "malformed", "duplicate-content", "alias-body", "expired", "unavailable-time", "missing-journal", "redacted"} {
		t.Run(name, func(t *testing.T) {
			o, ev, room, to, now := fromVector(t, loadVector(t, "PA1"))
			var m map[string]any
			if err := json.Unmarshal(ev.Content, &m); err != nil {
				t.Fatal(err)
			}
			want := "verified: @author:test.invalid"
			switch name {
			case "carrier-numbers":
				m["unrelated"] = map[string]any{"fraction": 1.5, "exponent": 1e100}
			case "tampered-body":
				m["body"] = "HELLO"
				want = invalid("message_text_mismatch")
			case "wrong-author":
				o.authors[ev.Sender] = "ed25519:other"
				want = invalid("author_mismatch")
			case "unknown-author":
				ev.Sender = "@other:test.invalid"
				want = UnknownAuthor
			case "missing-envelope":
				delete(m, matrix.EnvelopeContentKey)
				m["unrelated"] = 1.5
				want = Unsigned
			case "missing-roster":
				o = nil
				want = UnknownAuthor
			case "oversize":
				m[matrix.EnvelopeContentKey] = strings.Repeat("A", 90000)
				want = invalid("content_too_large")
			case "malformed":
				m[matrix.EnvelopeContentKey] = "%%%"
				want = invalid("envelope_malformed")
			case "duplicate-content":
				want = invalid("content_malformed")
			case "alias-body":
				m["Body"] = "evil"
				want = invalid("content_key_alias")
			case "expired":
				now = now.Add(2 * time.Minute)
				want = invalid("expired")
			case "unavailable-time":
				o.context.Time = verifier.Evidence{}
				want = invalid("time_unavailable")
			case "missing-journal":
				o.context.IDJournalAvailable = verifier.Evidence{}
				want = invalid("id_journal_unavailable")
			case "redacted":
				ev.Unsigned = json.RawMessage(`{"redacted_because":{}}`)
				want = invalid("event_redacted")
			}
			ev.Content, _ = json.Marshal(m)
			if name == "duplicate-content" {
				ev.Content = []byte(strings.TrimSuffix(string(ev.Content), "}") + `,"body":"evil"}`)
			}
			if got := o.Observe(ev, room, to, now); got != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}
}

// Proves the host parser does not silently accept unknown fields, duplicate
// members, broken encodings or agent-controlled files as protected key authority.
func TestRosterUnavailable(t *testing.T) {
	for _, raw := range []string{`{}`, `null`, `{"version":"a2a-envelope-roster/1","version":"a2a-envelope-roster/1","authors":{},"facts":{}}`, strings.Repeat(" ", maxRosterBytes+1)} {
		if _, err := ParseRoster([]byte(raw)); err == nil {
			t.Fatal("invalid roster accepted")
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o444); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"", "relative.json", filepath.Join(dir, "missing"), path, dir} {
		if _, err := Load(p); err != ErrRoster {
			t.Fatalf("Load(%q): %v", p, err)
		}
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link); err != ErrRoster {
		t.Fatal("symlink roster accepted")
	}
}

// Proves malformed inner bytes cannot be promoted to a verified message.
func TestObserveMalformedEnvelopes(t *testing.T) {
	o, ev, room, to, now := fromVector(t, loadVector(t, "PA1"))
	for _, raw := range []string{`{}`, `[]`, `null`, `{"body":{}}`, `{"body":{"author":"x"},"body":{}}`} {
		encoded := base64.RawURLEncoding.EncodeToString([]byte(raw))
		ev.Content, _ = json.Marshal(map[string]any{"body": "hello", matrix.EnvelopeContentKey: encoded})
		if got := o.Observe(ev, room, to, now); !strings.HasPrefix(got, "invalid: ") {
			t.Fatalf("%s -> %q", raw, got)
		}
	}
	// A valid record key is required at host intake, not merely a matching string.
	if record.ValidateKey("ed25519:other") == nil {
		t.Fatal("test key unexpectedly valid")
	}
}

// Proves protected storage alone cannot make malformed/unknown host-schema
// fields or unsupported author profiles a usable roster. Empty facts remain
// unavailable to verification rather than being filled with synthetic authority.
func TestRosterSchemaNeighbors(t *testing.T) {
	o, ev, room, to, now := fromVector(t, loadVector(t, "PA1"))
	key := o.authors[ev.Sender]
	for _, name := range []string{"minimal", "unknown-field", "unknown-fact", "bad-version", "empty-authors", "invalid-key", "empty-local", "empty-server", "control-sender", "non-ascii-sender", "facts-array", "attestation-array", "attestation-not-string", "attestation-bad-base64", "devices-array", "journal-array", "snapshots-array", "snapshot-not-object", "snapshot-not-string", "snapshot-bad-base64"} {
		t.Run(name, func(t *testing.T) {
			authors := map[string]any{ev.Sender: key}
			facts := map[string]any{}
			m := map[string]any{"version": "a2a-envelope-roster/1", "authors": authors, "facts": facts}
			switch name {
			case "unknown-field":
				m["extra"] = true
			case "unknown-fact":
				facts["delivery"] = map[string]any{}
			case "bad-version":
				m["version"] = "a2a-envelope-roster/2"
			case "empty-authors":
				m["authors"] = map[string]any{}
			case "invalid-key":
				authors[ev.Sender] = "ed25519:other"
			case "empty-local":
				m["authors"] = map[string]any{"@:example.invalid": key}
			case "empty-server":
				m["authors"] = map[string]any{"@worker:": key}
			case "control-sender":
				m["authors"] = map[string]any{"@worker\n:example.invalid": key}
			case "non-ascii-sender":
				m["authors"] = map[string]any{"@worker\u202e:example.invalid": key}
			case "facts-array":
				m["facts"] = []any{}
			case "attestation-array":
				facts["attestations"] = []any{}
			case "attestation-not-string":
				facts["attestations"] = map[string]any{"id": 123}
			case "attestation-bad-base64":
				facts["attestations"] = map[string]any{"id": "%%%"}
			case "devices-array":
				facts["operator_attestations"] = []any{}
			case "journal-array":
				facts["seen"] = []any{}
			case "snapshots-array":
				facts["revocations"] = []any{}
			case "snapshot-not-object":
				facts["revocations"] = map[string]any{"issuer": true}
			case "snapshot-not-string":
				facts["revocations"] = map[string]any{"issuer": map[string]any{"snapshot": 123}}
			case "snapshot-bad-base64":
				facts["revocations"] = map[string]any{"issuer": map[string]any{"snapshot": "%%%"}}
			}
			data, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseRoster(data)
			if name == "minimal" {
				if err != nil {
					t.Fatal(err)
				}
				if got := parsed.Observe(ev, room, to, now); got != "invalid: audience_mismatch" {
					t.Fatalf("missing facts supplied authority: %s", got)
				}
			} else if err != ErrRoster || parsed != nil {
				t.Fatalf("malformed host input accepted: %s", name)
			}
		})
	}
}
