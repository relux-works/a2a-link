package cg1

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/grantcheck"
	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-envelope/verifier"
)

const matrixMessageAction = "a2a.message"

var errMatrixEnvelope = errors.New("cg1: invalid envelope")

type matrixEnvelope struct {
	ID, Author, To string
	Arguments      map[string]any
}

func validEdAuthor(key string) bool {
	alg, _, e := record.KeyBytes(key)
	return e == nil && alg == "ed25519" && record.ValidateKey(key) == nil
}
func parseMatrixEnvelope(raw []byte) (matrixEnvelope, error) {
	var zero matrixEnvelope
	value, e := record.Parse(raw, 65536, 16)
	if e != nil {
		return zero, e
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return zero, errMatrixEnvelope
	}
	body, ok := obj["body"].(map[string]any)
	if !ok {
		return zero, errMatrixEnvelope
	}
	id, _ := obj["id"].(string)
	author, _ := body["author"].(string)
	to, _ := body["to"].(string)
	args, ok := body["arguments"].(map[string]any)
	target, _ := body["target"].(map[string]any)
	if !record.IsContentID(id) || !validEdAuthor(author) || !ok || body["action"] != matrixMessageAction || len(target) != 2 || target["kind"] != "station" || target["id"] != "cg1" {
		return zero, errMatrixEnvelope
	}
	return matrixEnvelope{id, author, to, args}, nil
}
func matrixPresentation(args map[string]any) (*grantcheck.Presentation, error) {
	if len(args) != 1 {
		return nil, errMatrixEnvelope
	}
	value, ok := args["cg1"]
	if !ok {
		return nil, errMatrixEnvelope
	}
	if value == nil {
		return nil, nil
	}
	obj, ok := value.(map[string]any)
	if !ok || len(obj) != 2 {
		return nil, errMatrixEnvelope
	}
	id, ok := obj["grant_id"].(string)
	if !ok || !validID(id) {
		return nil, errMatrixEnvelope
	}
	chunks, ok := obj["proof"].([]any)
	if !ok || len(chunks) == 0 || len(chunks) > 6 {
		return nil, errMatrixEnvelope
	}
	var b strings.Builder
	for i, item := range chunks {
		s, ok := item.(string)
		if !ok || len(s) == 0 || len(s) > 4096 || (i < len(chunks)-1 && len(s) != 4096) {
			return nil, errMatrixEnvelope
		}
		b.WriteString(s)
	}
	encoded := b.String()
	if len(encoded) > base64.RawURLEncoding.EncodedLen(grantcheck.MaxPresentationBytes) {
		return nil, errMatrixEnvelope
	}
	proof, e := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if e != nil || len(proof) == 0 || len(proof) > grantcheck.MaxPresentationBytes || base64.RawURLEncoding.EncodeToString(proof) != encoded {
		return nil, errMatrixEnvelope
	}
	return &grantcheck.Presentation{GrantID: id, Bytes: proof}, nil
}
func evidenceValue(raw json.RawMessage) (any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if e := d.Decode(&v); e != nil {
		return nil, e
	}
	var convert func(any) (any, error)
	convert = func(v any) (any, error) {
		switch x := v.(type) {
		case json.Number:
			i, e := strconv.ParseInt(string(x), 10, 64)
			if e != nil {
				return nil, e
			}
			return i, nil
		case map[string]any:
			for k, y := range x {
				n, e := convert(y)
				if e != nil {
					return nil, e
				}
				x[k] = n
			}
		case []any:
			for i, y := range x {
				n, e := convert(y)
				if e != nil {
					return nil, e
				}
				x[i] = n
			}
		}
		return v, nil
	}
	return convert(v)
}
func verifyMatrixEnvelope(cfg matrixSettings, raw []byte, room, to string, text []byte, now time.Time, watermark, id string, previous []byte) string {
	c := verifier.Context{}
	slots := map[string]*verifier.Evidence{"service_root": &c.ServiceRoot, "agent_revocation_root": &c.AgentRevocationRoot, "attestations": &c.Attestations, "active_generations": &c.CurrentGenerations, "revocations": &c.SignedSnapshots, "time": &c.Time, "operator_root": &c.OperatorRoot, "operator_owner": &c.OperatorOwner, "operator_attestations": &c.DeviceAttestations, "signer_facts": &c.SignerFacts}
	for name, rawEvidence := range cfg.Evidence {
		slot, ok := slots[name]
		if !ok {
			return "envelope_malformed"
		}
		value, e := evidenceValue(rawEvidence)
		if e != nil {
			return "envelope_malformed"
		}
		if name == "attestations" || name == "operator_attestations" {
			collection, ok := value.(map[string]any)
			if !ok {
				return "envelope_malformed"
			}
			for key, item := range collection {
				encoded, ok := item.(string)
				if !ok {
					return "envelope_malformed"
				}
				b, e := record.DecodeBase64(encoded, -1)
				if e != nil || len(b) > 8192 {
					return "envelope_malformed"
				}
				collection[key] = b
			}
		}
		if name == "revocations" {
			collection, ok := value.(map[string]any)
			if !ok {
				return "envelope_malformed"
			}
			for _, item := range collection {
				row, ok := item.(map[string]any)
				if !ok {
					return "envelope_malformed"
				}
				encoded, ok := row["snapshot"].(string)
				if !ok {
					return "envelope_malformed"
				}
				b, e := record.DecodeBase64(encoded, -1)
				if e != nil || len(b) > 8192 {
					return "envelope_malformed"
				}
				row["snapshot"] = b
			}
		}
		snapshot, e := verifier.Present(value)
		if e != nil {
			return "envelope_malformed"
		}
		*slot = snapshot
	}
	known := []any{}
	for _, p := range cfg.Pins {
		known = append(known, p.Author)
	}
	seen := map[string]any{}
	if len(previous) > 0 {
		seen[id] = previous
	}
	values := []struct {
		slot  *verifier.Evidence
		value any
	}{
		{&c.Audience, cfg.Audience}, {&c.RequiredRoles, []any{"author"}}, {&c.AdmittedKeys, known},
		{&c.Now, now.Format("2006-01-02T15:04:05Z")}, {&c.WatermarkAvailable, true}, {&c.Watermark, watermark},
		{&c.IDJournalAvailable, true}, {&c.IDJournal, seen}, {&c.Delivery, map[string]any{"room": room, "to": to, "text": text}},
	}
	for _, x := range values {
		snapshot, e := verifier.Present(x.value)
		if e != nil {
			return "envelope_malformed"
		}
		*x.slot = snapshot
	}
	return verifier.New(c).VerifyMessage(raw).Code
}
