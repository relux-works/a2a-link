package cli

import (
	"encoding/json"
	"net/http"
)

// fakeE2EE is the in-memory key store behind the fake homeserver's
// /keys/upload, /keys/query, /keys/device_signing/upload and
// /keys/signatures/upload routes. Callers hold hs.mu.
type fakeE2EE struct {
	uia         bool                                  // device_signing/upload demands m.login.password
	failSigning int                                   // first N device_signing uploads answer HTTP 500
	deviceKeys  map[string]map[string]json.RawMessage // user -> device -> device_keys object
	master      map[string]json.RawMessage            // user -> master_key object
	self        map[string]json.RawMessage            // user -> self_signing_key object
	user        map[string]json.RawMessage            // user -> user_signing_key object
	auths       []string                              // auth stage types seen, "" for passwordless
	emptyAuth   int                                   // password stages that carried an empty password
}

func (hs *fakeHS) e2eeState() *fakeE2EE {
	s := &hs.e2ee
	if s.deviceKeys == nil {
		s.deviceKeys = map[string]map[string]json.RawMessage{}
		s.master = map[string]json.RawMessage{}
		s.self = map[string]json.RawMessage{}
		s.user = map[string]json.RawMessage{}
	}
	return s
}

func (hs *fakeHS) keysUpload(w http.ResponseWriter, r *http.Request, user string) {
	var req struct {
		DeviceKeys json.RawMessage `json:"device_keys"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || len(req.DeviceKeys) == 0 {
		writeErr(w, 400, "M_BAD_JSON", "bad upload")
		return
	}
	var keys struct {
		UserID   string `json:"user_id"`
		DeviceID string `json:"device_id"`
	}
	if json.Unmarshal(req.DeviceKeys, &keys) != nil || keys.UserID != user || keys.DeviceID == "" {
		writeErr(w, 400, "M_INVALID_PARAM", "device keys do not match the access token")
		return
	}
	hs.mu.Lock()
	defer hs.mu.Unlock()
	s := hs.e2eeState()
	if s.deviceKeys[user] == nil {
		s.deviceKeys[user] = map[string]json.RawMessage{}
	}
	s.deviceKeys[user][keys.DeviceID] = req.DeviceKeys
	writeJSON(w, 200, map[string]any{"one_time_key_counts": map[string]int{}})
}

func (hs *fakeHS) keysQuery(w http.ResponseWriter, r *http.Request, _ string) {
	var req struct {
		DeviceKeys map[string][]string `json:"device_keys"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		writeErr(w, 400, "M_BAD_JSON", "bad query")
		return
	}
	hs.mu.Lock()
	defer hs.mu.Unlock()
	s := hs.e2eeState()
	out := map[string]any{"device_keys": map[string]any{}, "failures": map[string]any{}}
	devices := out["device_keys"].(map[string]any)
	for user := range req.DeviceKeys {
		byDevice := map[string]json.RawMessage{}
		for id, raw := range s.deviceKeys[user] {
			byDevice[id] = raw
		}
		devices[user] = byDevice
		for name, store := range map[string]map[string]json.RawMessage{"master_keys": s.master, "self_signing_keys": s.self, "user_signing_keys": s.user} {
			if raw, ok := store[user]; ok {
				section, _ := out[name].(map[string]any)
				if section == nil {
					section = map[string]any{}
					out[name] = section
				}
				section[user] = raw
			}
		}
	}
	writeJSON(w, 200, out)
}

func (hs *fakeHS) keysDeviceSigning(w http.ResponseWriter, r *http.Request, user string) {
	var req struct {
		Master json.RawMessage `json:"master_key"`
		Self   json.RawMessage `json:"self_signing_key"`
		User   json.RawMessage `json:"user_signing_key"`
		Auth   map[string]any  `json:"auth"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		writeErr(w, 400, "M_BAD_JSON", "bad upload")
		return
	}
	hs.mu.Lock()
	defer hs.mu.Unlock()
	s := hs.e2eeState()
	if s.failSigning > 0 {
		s.failSigning--
		writeErr(w, 500, "M_UNKNOWN", "transient failure")
		return
	}
	uia := map[string]any{"session": "xs-1", "flows": []any{map[string]any{"stages": []string{"m.login.password"}}}, "params": map[string]any{}}
	if s.uia {
		if req.Auth == nil {
			s.auths = append(s.auths, "")
			writeJSON(w, 401, uia)
			return
		}
		kind, _ := req.Auth["type"].(string)
		s.auths = append(s.auths, kind)
		password, _ := req.Auth["password"].(string)
		if password == "" {
			s.emptyAuth++
		}
		identifier, _ := req.Auth["identifier"].(map[string]any)
		if kind != "m.login.password" || identifier["user"] != user || req.Auth["session"] != "xs-1" || password == "" || password != hs.passwords[user] {
			uia["errcode"], uia["error"] = "M_FORBIDDEN", "Invalid password"
			uia["completed"] = []string{}
			writeJSON(w, 401, uia)
			return
		}
	} else {
		s.auths = append(s.auths, "")
	}
	for _, raw := range []json.RawMessage{req.Master, req.Self, req.User} {
		var key struct {
			UserID string `json:"user_id"`
		}
		if json.Unmarshal(raw, &key) != nil || key.UserID != user {
			writeErr(w, 400, "M_INVALID_PARAM", "key user mismatch")
			return
		}
	}
	s.master[user], s.self[user], s.user[user] = req.Master, req.Self, req.User
	writeJSON(w, 200, map[string]any{})
}

func (hs *fakeHS) keysSignatures(w http.ResponseWriter, r *http.Request, user string) {
	var req map[string]map[string]json.RawMessage
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		writeErr(w, 400, "M_BAD_JSON", "bad upload")
		return
	}
	hs.mu.Lock()
	defer hs.mu.Unlock()
	s := hs.e2eeState()
	failures := map[string]any{}
	for target, byKey := range req {
		for keyOrDevice, raw := range byKey {
			var signed struct {
				Signatures map[string]map[string]string `json:"signatures"`
			}
			if json.Unmarshal(raw, &signed) != nil || signed.Signatures[user] == nil {
				failures[target+"/"+keyOrDevice] = map[string]string{"errcode": "M_INVALID_SIGNATURE"}
				continue
			}
			existing, ok := s.deviceKeys[target][keyOrDevice]
			if !ok {
				failures[target+"/"+keyOrDevice] = map[string]string{"errcode": "M_NOT_FOUND"}
				continue
			}
			s.deviceKeys[target][keyOrDevice] = mergeSignatures(existing, user, signed.Signatures[user])
		}
	}
	writeJSON(w, 200, map[string]any{"failures": failures})
}

// mergeSignatures adds signer's signatures into a stored key object.
func mergeSignatures(raw json.RawMessage, signer string, keys map[string]string) json.RawMessage {
	var object map[string]any
	if json.Unmarshal(raw, &object) != nil {
		return raw
	}
	signatures, _ := object["signatures"].(map[string]any)
	if signatures == nil {
		signatures = map[string]any{}
	}
	bySigner, _ := signatures[signer].(map[string]any)
	if bySigner == nil {
		bySigner = map[string]any{}
	}
	for id, sig := range keys {
		bySigner[id] = sig
	}
	signatures[signer] = bySigner
	object["signatures"] = signatures
	out, _ := json.Marshal(object)
	return out
}

// --- setup helpers (called by tests, not over HTTP) --------------------------

// signAgentMaster records signer's signature under keyID on user's published
// master key, as the owner's Element ceremony does through /keys/signatures/upload.
func (hs *fakeHS) signAgentMaster(user, signer, keyID, signature string) {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	s := hs.e2eeState()
	raw, ok := s.master[user]
	if !ok {
		hs.t.Fatal("no published master key to sign")
	}
	s.master[user] = mergeSignatures(raw, signer, map[string]string{keyID: signature})
}

// plantMaster publishes an arbitrary master key object for user.
func (hs *fakeHS) plantMaster(user string, raw json.RawMessage) {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	hs.e2eeState().master[user] = raw
}

// plantDeviceKeys publishes an arbitrary device_keys object for user/device.
func (hs *fakeHS) plantDeviceKeys(user, device string, raw json.RawMessage) {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	s := hs.e2eeState()
	if s.deviceKeys[user] == nil {
		s.deviceKeys[user] = map[string]json.RawMessage{}
	}
	s.deviceKeys[user][device] = raw
}

func (hs *fakeHS) publishedMaster(user string) json.RawMessage {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	return hs.e2eeState().master[user]
}

func (hs *fakeHS) publishedDevice(user, device string) json.RawMessage {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	return hs.e2eeState().deviceKeys[user][device]
}

func (hs *fakeHS) signingAuths() ([]string, int) {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	s := hs.e2eeState()
	return append([]string(nil), s.auths...), s.emptyAuth
}

func (hs *fakeHS) setE2EE(fn func(*fakeE2EE)) {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	fn(hs.e2eeState())
}

func (hs *fakeHS) setPassword(user, password string) {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	hs.passwords[user] = password
}
