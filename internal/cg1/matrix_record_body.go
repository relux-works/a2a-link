package cg1

import (
	"bytes"
	"time"

	"github.com/relux-works/swarma-envelope/record"
)

type evidenceAttestationProfile struct {
	algorithm, purpose, binding string
	roles, actions              []string
	maxWindow                   time.Duration
}

// Shape only: no signature equation, issuing-root authority, current binding or freshness is established here.
func evidenceSignedBody(body map[string]any, kind string) bool {
	if body["type"] != kind {
		return false
	}
	if !evidenceKey(body["issuer"]) {
		return false
	}
	switch kind {
	case "attestation/1":
		return evidenceAttestationBody(body)
	case "revocation/1":
		return evidenceRevocationBody(body)
	default:
		return false
	}
}
func evidenceAttestationBody(body map[string]any) bool {
	if _, closed := exactEvidenceObject(body, "type issuer subject key_class purpose roles actions iat exp binding"); !closed {
		return false
	}
	profiles := map[string]evidenceAttestationProfile{
		"agent":           {"Ed25519", "swarma-msg", "agent", []string{"author"}, []string{"message.sign"}, 24 * time.Hour},
		"operator-device": {"P-256", "operator-device", "owner", []string{"act", "approver"}, []string{"act.sign", "grant.sign", "message.approve"}, 0},
		"service":         {"Ed25519", "grant-service", "owner", []string{"author"}, []string{"grant.sign"}, 24 * time.Hour},
	}
	class, _ := body["key_class"].(string)
	profile, exists := profiles[class]
	if !exists {
		return false
	}
	if body["purpose"] != profile.purpose {
		return false
	}
	if !evidenceStringList(body["roles"], profile.roles) {
		return false
	}
	if !evidenceStringList(body["actions"], profile.actions) {
		return false
	}
	if !evidenceSubject(body["subject"], profile.algorithm) {
		return false
	}
	if !evidenceStamp(body["iat"]) {
		return false
	}
	if !evidenceStamp(body["exp"]) {
		return false
	}
	start, _ := time.Parse("2006-01-02T15:04:05Z", body["iat"].(string))
	end, _ := time.Parse("2006-01-02T15:04:05Z", body["exp"].(string))
	if !end.After(start) {
		return false
	}
	if profile.maxWindow > 0 && end.Sub(start) > profile.maxWindow {
		return false
	}
	if !evidenceAttestationBinding(body["binding"], profile.binding) {
		return false
	}
	return true
}
func evidenceStringList(value any, expected []string) bool {
	list, ok := value.([]any)
	if !ok || len(list) != len(expected) {
		return false
	}
	for i, s := range expected {
		if list[i] != s {
			return false
		}
	}
	return true
}
func evidenceSubject(value any, algorithm string) bool {
	subject, ok := value.(map[string]any)
	if !ok {
		return false
	}
	if _, closed := exactEvidenceObject(subject, "algorithm key_id public_bytes"); !closed {
		return false
	}
	if subject["algorithm"] != algorithm {
		return false
	}
	id, ok := subject["key_id"].(string)
	if !ok || !evidenceKey(id) {
		return false
	}
	prefix, n := "ed25519", 32
	if algorithm == "P-256" {
		prefix, n = "p256", 33
	}
	alg, key, e := record.KeyBytes(id)
	if e != nil || alg != prefix {
		return false
	}
	encoded, ok := subject["public_bytes"].(string)
	if !ok {
		return false
	}
	public, e := record.DecodeBase64(encoded, n)
	if e != nil {
		return false
	}
	if !bytes.Equal(public, key) {
		return false
	}
	return true
}
func evidenceAttestationBinding(value any, kind string) bool {
	binding, ok := value.(map[string]any)
	if !ok {
		return false
	}
	if kind == "owner" {
		if _, closed := exactEvidenceObject(binding, "owner"); !closed {
			return false
		}
		if !evidenceText(binding["owner"]) {
			return false
		}
		return true
	}
	if _, closed := exactEvidenceObject(binding, "uid generation registration_number master_epoch owner path"); !closed {
		return false
	}
	if !evidenceInteger(binding["uid"], 0, 4294967294) {
		return false
	}
	if !evidenceInteger(binding["registration_number"], 1, 9007199254740991) {
		return false
	}
	for _, field := range []string{"generation", "master_epoch", "owner", "path"} {
		if !evidenceText(binding[field]) {
			return false
		}
	}
	return true
}
func evidenceRevocationBody(body map[string]any) bool {
	if _, closed := exactEvidenceObject(body, "type issuer issued_at complete entries"); !closed {
		return false
	}
	if !evidenceStamp(body["issued_at"]) {
		return false
	}
	if body["complete"] != true {
		return false
	}
	entries, ok := body["entries"].([]any)
	if !ok || len(entries) > 64 {
		return false
	}
	for _, value := range entries {
		if !evidenceRevocationEntry(value) {
			return false
		}
	}
	return true
}

func evidenceRevocationEntry(value any) bool {
	entry, ok := value.(map[string]any)
	if !ok {
		return false
	}
	if _, closed := exactEvidenceObject(entry, "kind id from"); !closed {
		return false
	}
	kind, _ := entry["kind"].(string)
	if kind != "key" && kind != "record" {
		return false
	}
	if kind == "record" {
		id, ok := entry["id"].(string)
		if !ok || !record.IsContentID(id) {
			return false
		}
	} else if !evidenceKey(entry["id"]) {
		return false
	}
	if !evidenceStamp(entry["from"]) {
		return false
	}
	return true
}
