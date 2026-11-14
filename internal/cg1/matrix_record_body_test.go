package cg1

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/a2a-swarm/internal/admission"
	"github.com/relux-works/swarma-envelope/record"
)

type signedBodyCase struct {
	name, profile, path string
	bad                 any
	extra               bool
}

func signedBodyCases() []signedBodyCase {
	return []signedBodyCase{
		{"att-type", "agent", "type", "wrong", false},
		{"att-issuer", "agent", "issuer", false, false},
		{"att-body-closed", "agent", "extra", true, true},
		{"att-subject", "agent", "subject", false, false},
		{"att-key_class", "agent", "key_class", "unknown", false},
		{"att-purpose", "agent", "purpose", "wrong", false},
		{"att-roles", "agent", "roles", []any{"unknown"}, false},
		{"att-actions", "agent", "actions", []any{"unknown"}, false},
		{"att-iat", "agent", "iat", "2026-01-01T00:00:00.1Z", false},
		{"att-exp", "agent", "exp", "2026-01-01T01:00:00.1Z", false},
		{"att-positive-window", "agent", "exp", "2026-01-01T00:00:00Z", false},
		{"att-window-bound", "agent", "exp", "2026-01-02T00:00:01Z", false},
		{"att-binding", "agent", "binding", false, false},
		{"subject-closed", "agent", "subject.extra", true, true},
		{"subject-algorithm", "agent", "subject.algorithm", false, false},
		{"subject-key_id", "agent", "subject.key_id", edID(testEd(12)), false},
		{"subject-public_bytes", "agent", "subject.public_bytes", base64.RawURLEncoding.EncodeToString(testEd(12).Public().(ed25519.PublicKey)), false},
		{"agent-binding-closed", "agent", "binding.extra", true, true},
		{"agent-uid", "agent", "binding.uid", int64(-1), false},
		{"agent-registration_number", "agent", "binding.registration_number", int64(0), false},
		{"agent-generation", "agent", "binding.generation", false, false},
		{"agent-master_epoch", "agent", "binding.master_epoch", false, false},
		{"agent-owner", "agent", "binding.owner", false, false},
		{"agent-path", "agent", "binding.path", false, false},
		{"device-binding-closed", "device", "binding.extra", true, true},
		{"device-owner", "device", "binding.owner", false, false},
		{"device-algorithm", "device", "subject.algorithm", "Ed25519", false},
		{"device-purpose", "device", "purpose", "wrong", false},
		{"device-roles", "device", "roles", []any{"approver", "act"}, false},
		{"device-actions", "device", "actions", []any{"act.sign"}, false},
		{"service-binding-closed", "service", "binding.extra", true, true},
		{"service-owner", "service", "binding.owner", false, false},
		{"service-purpose", "service", "purpose", "wrong", false},
		{"service-roles", "service", "roles", []any{"delegate"}, false},
		{"service-actions", "service", "actions", []any{"message.sign"}, false},
		{"service-window-bound", "service", "exp", "2026-01-02T00:00:01Z", false},
		{"rev-type", "revocation", "type", "wrong", false},
		{"rev-issuer", "revocation", "issuer", false, false},
		{"rev-body-closed", "revocation", "extra", true, true},
		{"rev-issued_at", "revocation", "issued_at", "invalid", false},
		{"rev-complete", "revocation", "complete", "true", false},
		{"rev-entries", "revocation", "entries", map[string]any{}, false},
		{"rev-entry-object", "revocation", "entry", false, false},
		{"rev-entry-closed", "revocation", "entry.extra", true, true},
		{"rev-kind", "revocation", "entry.kind", "unknown", false},
		{"rev-key-id", "revocation", "entry.id", false, false},
		{"rev-record-id", "rev-record", "entry.id", false, false},
		{"rev-from", "revocation", "entry.from", "invalid", false},
	}
}
func fixtureEvidenceBody(t *testing.T, f *matrixFixture, profile string) (string, map[string]any) {
	t.Helper()
	if profile == "revocation" || profile == "rev-record" {
		kind, id := "key", edID(f.bob)
		if profile == "rev-record" {
			kind, id = "record", f.att[edID(f.bob)]
		}
		return "revocation/1", map[string]any{"type": "revocation/1", "issuer": edID(testEd(21)), "issued_at": "2026-01-01T00:01:00Z", "complete": true, "entries": []any{map[string]any{"kind": kind, "id": id, "from": "2026-01-01T00:00:00Z"}}}
	}
	subject := map[string]any{"algorithm": "Ed25519", "key_id": edID(f.bob), "public_bytes": base64.RawURLEncoding.EncodeToString(f.bob.Public().(ed25519.PublicKey))}
	body := map[string]any{"type": "attestation/1", "issuer": edID(testEd(20)), "subject": subject, "key_class": "agent", "purpose": "swarma-msg", "roles": []any{"author"}, "actions": []any{"message.sign"}, "iat": "2026-01-01T00:00:00Z", "exp": "2026-01-01T01:00:00Z", "binding": map[string]any{"uid": int64(1000), "generation": "g1", "registration_number": int64(1), "master_epoch": "epoch-1", "owner": "fixture-owner", "path": "fixture/message"}}
	if profile == "device" {
		x, y := elliptic.P256().ScalarBaseMult([]byte{1})
		public := base64.RawURLEncoding.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), x, y))
		body["subject"] = map[string]any{"algorithm": "P-256", "key_id": "p256:" + public, "public_bytes": public}
		body["key_class"], body["purpose"] = "operator-device", "operator-device"
		body["roles"], body["actions"] = []any{"act", "approver"}, []any{"act.sign", "grant.sign", "message.approve"}
		body["binding"] = map[string]any{"owner": "fixture-owner"}
	} else if profile == "service" {
		body["key_class"], body["purpose"] = "service", "grant-service"
		body["actions"] = []any{"grant.sign"}
		body["binding"] = map[string]any{"owner": "fixture-owner"}
	}
	return "attestation/1", body
}
func signEvidenceBody(t *testing.T, kind string, body map[string]any) ([]byte, string) {
	t.Helper()
	root := testEd(20)
	if kind == "revocation/1" {
		root = testEd(21)
	}
	key := edID(root)
	id, e := record.ContentID(kind, body)
	if e != nil {
		t.Fatal(e)
	}
	pre, e := record.SigningPreimage(kind, key, "author", body)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := record.Canonical(map[string]any{"version": "swarm-envelope/2", "body": body, "id": id, "signatures": []any{map[string]any{"role": "author", "key": key, "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(root, pre))}}})
	if e != nil {
		t.Fatal(e)
	}
	return raw, id
}
func installEvidenceBody(t *testing.T, f *matrixFixture, kind string, body map[string]any) {
	t.Helper()
	raw, id := signEvidenceBody(t, kind, body)
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	if kind == "attestation/1" {
		f.cfg.Evidence["attestations"] = evidenceJSON(t, map[string]any{id: encoded})
	} else {
		f.cfg.Evidence["revocations"] = evidenceJSON(t, map[string]any{edID(testEd(21)): map[string]any{"availability": "available", "max_age": int64(60), "rollback_safe": true, "snapshot": encoded}})
	}
}
func mutateEvidenceBody(body map[string]any, path string, value any, remove bool) {
	parts := strings.Split(path, ".")
	object := body
	if parts[0] == "entry" {
		entries := body["entries"].([]any)
		if len(parts) == 1 {
			entries[0] = value
			return
		}
		object = entries[0].(map[string]any)
		parts = parts[1:]
	}
	for _, p := range parts[:len(parts)-1] {
		object = object[p].(map[string]any)
	}
	if remove {
		delete(object, parts[len(parts)-1])
	} else {
		object[parts[len(parts)-1]] = value
	}
}

// Proves each named closed body/nested field rejects a correctly fixture-signed violation before any state write; its valid same-namespace neighbor starts.
func TestMatrixSignedEvidenceBodies(t *testing.T) {
	for _, tc := range signedBodyCases() {
		t.Run(tc.name, func(t *testing.T) {
			f, dir, cfg := freshMatrixConfig(t)
			modes := []bool{false}
			if !tc.extra && tc.path != "entry" {
				modes = append(modes, true)
			}
			for _, remove := range modes {
				for _, bad := range evidenceBodyBadValues(tc) {
					kind, body := fixtureEvidenceBody(t, f, tc.profile)
					mutateEvidenceBody(body, tc.path, bad, remove)
					installEvidenceBody(t, f, kind, body)
					f.save(t, dir)
					c, e := admission.Open(MatrixPolicy, cfg)
					if c != nil {
						c.Close()
					}
					if e == nil || c != nil {
						t.Fatal("malformed signed evidence body admitted at startup", tc.name, remove)
					}
					noMatrixBinding(t, dir)
					entries, e := os.ReadDir(dir)
					if e != nil || len(entries) != 1 || entries[0].Name() != matrixConfigName {
						t.Fatal("signed body refusal created state", e)
					}
				}
			}
			kind, body := fixtureEvidenceBody(t, f, tc.profile)
			installEvidenceBody(t, f, kind, body)
			f.save(t, dir)
			c, e := admission.Open(MatrixPolicy, cfg)
			if e != nil || c == nil {
				t.Fatal("valid signed body neighbor cannot start", e)
			}
			c.Close()
		})
	}
}

func evidenceBodyBadValues(tc signedBodyCase) []any {
	values := []any{tc.bad}
	switch tc.name {
	case "att-type", "rev-type":
		values = append(values, false)
	case "att-issuer", "rev-issuer":
		values = append(values, "ed25519:invalid")
	case "att-subject", "att-binding":
		values = append(values, map[string]any{})
	case "att-roles", "att-actions", "device-roles", "device-actions", "service-roles", "service-actions":
		values = append(values, false, []any{}, []any{"author", "author"})
	case "att-iat", "att-exp", "rev-issued_at", "rev-from":
		values = append(values, false, "invalid", "1969-12-31T23:59:59Z", "2026-02-30T00:00:00Z")
	case "att-positive-window":
		values = append(values, "2025-12-31T23:59:59Z")
	case "agent-uid":
		values = append(values, true, "1000", int64(4294967295))
	case "agent-registration_number":
		values = append(values, true, "1")
	case "agent-generation", "agent-master_epoch", "agent-owner", "agent-path", "device-owner", "service-owner":
		values = append(values, "", strings.Repeat("x", 256))
	case "subject-key_id":
		values = append(values, false, "ed25519:invalid")
	case "subject-public_bytes":
		values = append(values, false, "AA", base64.RawURLEncoding.EncodeToString(testEd(12).Public().(ed25519.PublicKey))+"=")
	case "rev-complete":
		values = append(values, false, int64(1))
	case "rev-entries":
		entries := []any{}
		for i := 0; i < 65; i++ {
			entries = append(entries, map[string]any{"kind": "key", "id": edID(testEd(10)), "from": "2026-01-01T00:00:00Z"})
		}
		values = append(values, false, entries)
	}
	return values
}

// Proves inclusive numeric/text/array boundaries and empty complete snapshots start, while retaining the original encoded evidence bytes.
func TestMatrixSignedEvidenceBodyBoundaries(t *testing.T) {
	for _, which := range []string{"agent-max", "agent-min", "rev-empty", "rev-max", "device-long"} {
		t.Run(which, func(t *testing.T) {
			f, dir, cfg := freshMatrixConfig(t)
			profile := "agent"
			if strings.HasPrefix(which, "rev-") {
				profile = "revocation"
			}
			if which == "device-long" {
				profile = "device"
			}
			kind, body := fixtureEvidenceBody(t, f, profile)
			switch which {
			case "agent-max":
				b := body["binding"].(map[string]any)
				b["uid"] = int64(4294967294)
				b["registration_number"] = int64(9007199254740991)
				for _, k := range []string{"generation", "master_epoch", "owner", "path"} {
					b[k] = strings.Repeat("x", 255)
				}
				body["exp"] = "2026-01-02T00:00:00Z"
			case "agent-min":
				b := body["binding"].(map[string]any)
				b["uid"] = int64(0)
				b["registration_number"] = int64(1)
			case "rev-empty":
				body["entries"] = []any{}
			case "rev-max":
				entries := []any{}
				for i := 0; i < 64; i++ {
					entries = append(entries, body["entries"].([]any)[0])
				}
				body["entries"] = entries
			case "device-long":
				body["exp"] = "9999-12-31T23:59:59Z"
			}
			installEvidenceBody(t, f, kind, body)
			f.save(t, dir)
			before := admissionReadMatrix(t, filepath.Join(dir, matrixConfigName))
			c, e := admission.Open(MatrixPolicy, cfg)
			if e != nil || c == nil {
				t.Fatal("valid boundary refused", e)
			}
			c.Close()
			if !bytes.Equal(before, admissionReadMatrix(t, filepath.Join(dir, matrixConfigName))) {
				t.Fatal("startup rewrote signed evidence")
			}
		})
	}
}

// Proves startup shape checks do not verify signatures, while runtime still refuses a well-shaped bad signature before the fake backend; its valid neighbor passes.
func TestMatrixSignedEvidenceShapeIsNotAuthority(t *testing.T) {
	for _, bad := range []bool{true, false} {
		t.Run(fmt.Sprint(bad), func(t *testing.T) {
			f, dir, cfg := freshMatrixConfig(t)
			var records map[string]string
			if e := json.Unmarshal(f.cfg.Evidence["attestations"], &records); e != nil {
				t.Fatal(e)
			}
			if bad {
				raw, e := base64.RawURLEncoding.DecodeString(records[f.att[edID(f.bob)]])
				if e != nil {
					t.Fatal(e)
				}
				parsed, e := record.Parse(raw, 8192, 16)
				if e != nil {
					t.Fatal(e)
				}
				object := parsed.(map[string]any)
				sig := object["signatures"].([]any)[0].(map[string]any)
				rawSig, e := base64.RawURLEncoding.DecodeString(sig["sig"].(string))
				if e != nil {
					t.Fatal(e)
				}
				rawSig[0] ^= 1
				sig["sig"] = base64.RawURLEncoding.EncodeToString(rawSig)
				raw, e = record.Canonical(object)
				if e != nil {
					t.Fatal(e)
				}
				records[f.att[edID(f.bob)]] = base64.RawURLEncoding.EncodeToString(raw)
			}
			f.cfg.Evidence["attestations"] = evidenceJSON(t, records)
			f.save(t, dir)
			opened, e := admission.Open(MatrixPolicy, cfg)
			if e != nil || opened == nil {
				t.Fatal("shape-only startup checked signature authority", e)
			}
			defer opened.Close()
			checker := opened.(*matrixChecker)
			checker.core = f.fake
			checker.now = func() time.Time { return f.now }
			content := f.content(t, matrixBob, matrixAlice, f.body(matrixBob, matrixAlice, "hello", map[string]any{"cg1": nil}))
			decision, e := checker.Inbound(context.Background(), f.incoming(t, content))
			if e != nil {
				t.Fatal(e)
			}
			if bad {
				if decision.Verdict != admission.Refused || decision.Reason != "denied" || decision.Retryable || f.fake.inCalls != 0 {
					t.Fatal("bad runtime signature reached grantcheck", decision)
				}
			} else if decision.Verdict != admission.Live || f.fake.inCalls != 1 {
				t.Fatal("valid runtime neighbor refused", decision)
			}
		})
	}
}

// Proves the typed shape check also rejects the upper registration bound; the shared CCJ reader rejects that integer before a wire record can reach this helper.
func TestMatrixSignedEvidenceBodyIntegerBounds(t *testing.T) {
	f := newMatrixFixture(t)
	_, body := fixtureEvidenceBody(t, f, "agent")
	binding := body["binding"].(map[string]any)
	binding["registration_number"] = int64(9007199254740992)
	if evidenceSignedBody(body, "attestation/1") {
		t.Fatal("out-of-range registration admitted")
	}
	binding["registration_number"] = int64(9007199254740991)
	if !evidenceSignedBody(body, "attestation/1") {
		t.Fatal("maximum registration refused")
	}
}
