package matrix

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

// --- device and cross-signing keys (U2a) ---------------------------------------
//
// These methods carry already-signed public key objects to the homeserver and
// read the agent's own published material back. They hold no key material,
// perform no sync and never retry a mutation on their own. Responses are read
// through the strict control reader so a duplicate or malformed member refuses
// the whole answer rather than silently selecting one spelling.

// maxKeyResponse bounds every key endpoint response.
const maxKeyResponse = 1 << 20

// ErrUIARequired: the server demanded user-interactive authentication and no
// supported stage with a non-empty stored password could satisfy it. Nothing was
// uploaded. The caller keeps its local keys and stays awaiting-uia.
var ErrUIARequired = errors.New("matrix: cross-signing upload requires user-interactive authentication")

// ErrUIARejected: the server refused the supplied password stage.
var ErrUIARejected = errors.New("matrix: user-interactive authentication rejected")

// ErrKeyQueryIncomplete: the query reported failures or answered for another user.
var ErrKeyQueryIncomplete = errors.New("matrix: key query incomplete")

// ErrSignatureUploadFailed: the server reported per-key signature failures.
var ErrSignatureUploadFailed = errors.New("matrix: signature upload reported failures")

// OwnKeys is the agent's own published material as returned by POST /keys/query
// for exactly one user. Nil members are unpublished. Objects are the exact
// server JSON for later signature verification over their canonical form.
type OwnKeys struct {
	DeviceKeys     map[string]json.RawMessage
	MasterKey      json.RawMessage
	SelfSigningKey json.RawMessage
	UserSigningKey json.RawMessage
}

// uiaPasswordGuard refuses an empty stored password before any UIA stage is
// sent. It is a variable only so controls can plant its removal and prove the
// empty-password negative detects the bypass; production never reassigns it.
var uiaPasswordGuard = func(password string) error {
	if password == "" {
		return ErrUIARequired
	}
	return nil
}

func (c *Client) controlPost(ctx context.Context, path string, body any) (*controlValue, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	resp, err := c.WithoutRedirects().send(ctx, http.MethodPost, path, nil, bytes.NewReader(data), "application/json", int64(len(data)))
	if err != nil {
		return nil, err
	}
	v, err := readControl(ctx, resp, maxKeyResponse+1)
	if err != nil {
		return nil, err
	}
	if err = v.consume(ctx, nil); err != nil {
		return nil, err
	}
	return v, nil
}

func rawObject(v any) (json.RawMessage, error) {
	object, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("matrix: key object malformed")
	}
	raw, err := json.Marshal(object)
	if err != nil {
		return nil, errors.New("matrix: key object malformed")
	}
	return raw, nil
}

// QueryOwnKeys asks for userID's device and cross-signing keys. Any reported
// failure or an answer naming another user is incomplete: only a complete
// query can establish that keys are absent.
func (c *Client) QueryOwnKeys(ctx context.Context, userID string) (OwnKeys, error) {
	var out OwnKeys
	v, err := c.controlPost(ctx, v3+"/keys/query", map[string]any{"device_keys": map[string][]string{userID: {}}})
	if err != nil {
		return out, err
	}
	if failures, ok := v.value["failures"].(map[string]any); ok && len(failures) > 0 {
		return out, ErrKeyQueryIncomplete
	} else if !ok && v.value["failures"] != nil {
		return out, ErrKeyQueryIncomplete
	}
	for _, section := range []struct {
		name string
		dst  *json.RawMessage
	}{{"master_keys", &out.MasterKey}, {"self_signing_keys", &out.SelfSigningKey}, {"user_signing_keys", &out.UserSigningKey}} {
		raw, present := v.value[section.name]
		if !present {
			continue
		}
		users, ok := raw.(map[string]any)
		if !ok {
			return OwnKeys{}, ErrKeyQueryIncomplete
		}
		for user, object := range users {
			if user != userID {
				return OwnKeys{}, ErrKeyQueryIncomplete
			}
			*section.dst, err = rawObject(object)
			if err != nil {
				return OwnKeys{}, err
			}
		}
	}
	out.DeviceKeys = map[string]json.RawMessage{}
	if raw, present := v.value["device_keys"]; present {
		users, ok := raw.(map[string]any)
		if !ok {
			return OwnKeys{}, ErrKeyQueryIncomplete
		}
		for user, devices := range users {
			if user != userID {
				return OwnKeys{}, ErrKeyQueryIncomplete
			}
			byDevice, ok := devices.(map[string]any)
			if !ok {
				return OwnKeys{}, ErrKeyQueryIncomplete
			}
			for device, object := range byDevice {
				if device == "" || len(device) > 255 {
					return OwnKeys{}, ErrKeyQueryIncomplete
				}
				out.DeviceKeys[device], err = rawObject(object)
				if err != nil {
					return OwnKeys{}, err
				}
			}
		}
	}
	return out, nil
}

// UploadDeviceKeys publishes the signed device-key object of the authenticated
// device. No one-time or fallback keys are uploaded here (U3).
func (c *Client) UploadDeviceKeys(ctx context.Context, deviceKeys json.RawMessage) error {
	if len(deviceKeys) == 0 || !json.Valid(deviceKeys) {
		return errors.New("matrix: invalid device keys")
	}
	_, err := c.controlPost(ctx, v3+"/keys/upload", map[string]json.RawMessage{"device_keys": deviceKeys})
	return err
}

// CrossSigningUpload is the body of POST /keys/device_signing/upload.
type CrossSigningUpload struct {
	MasterKey      json.RawMessage `json:"master_key"`
	SelfSigningKey json.RawMessage `json:"self_signing_key"`
	UserSigningKey json.RawMessage `json:"user_signing_key"`
	Auth           map[string]any  `json:"auth,omitempty"`
}

// UploadCrossSigningKeys uploads the three signed key objects passwordless
// first. When the server answers with a UIA challenge offering m.login.password,
// password is consulted exactly once and the stage is completed with it; the
// callback is never invoked otherwise, and an empty password is never sent.
// Any UIA shortfall is ErrUIARequired or ErrUIARejected with nothing uploaded.
func (c *Client) UploadCrossSigningKeys(ctx context.Context, userID string, keys CrossSigningUpload, password func(context.Context) (string, error)) error {
	for _, raw := range []json.RawMessage{keys.MasterKey, keys.SelfSigningKey, keys.UserSigningKey} {
		if len(raw) == 0 || !json.Valid(raw) {
			return errors.New("matrix: invalid cross-signing keys")
		}
	}
	keys.Auth = nil
	path := v3 + "/keys/device_signing/upload"
	_, err := c.controlPost(ctx, path, keys)
	if interrupted := ctx.Err(); interrupted != nil {
		return interrupted
	}
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrAuth) {
		return err
	}
	var me *Error
	if !errors.As(err, &me) || me.Status != http.StatusUnauthorized {
		return err
	}
	var uia uiaResponse
	if !me.uia(&uia) {
		return err
	}
	if !hasFlow(uia, "m.login.password") || password == nil {
		return ErrUIARequired
	}
	secret, err := password(ctx)
	if err != nil {
		return err
	}
	if err = uiaPasswordGuard(secret); err != nil {
		return err
	}
	keys.Auth = map[string]any{
		"type":       "m.login.password",
		"identifier": userIdentifier(userID),
		"password":   secret,
		"session":    uia.Session,
	}
	_, err = c.controlPost(ctx, path, keys)
	if interrupted := ctx.Err(); interrupted != nil {
		return interrupted
	}
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrAuth) {
		return err
	}
	if IsStatus(err, http.StatusUnauthorized) {
		return ErrUIARejected
	}
	return err
}

// UploadSignatures publishes additional signatures (here the self-signing key's
// signature over this device) for userID's device. Reported failures refuse.
func (c *Client) UploadSignatures(ctx context.Context, userID, deviceID string, signed json.RawMessage) error {
	if len(signed) == 0 || !json.Valid(signed) || userID == "" || deviceID == "" {
		return errors.New("matrix: invalid signature upload")
	}
	v, err := c.controlPost(ctx, v3+"/keys/signatures/upload", map[string]map[string]json.RawMessage{userID: {deviceID: signed}})
	if err != nil {
		return err
	}
	if raw, present := v.value["failures"]; present {
		failures, ok := raw.(map[string]any)
		if !ok || len(failures) > 0 {
			return ErrSignatureUploadFailed
		}
	}
	return nil
}
