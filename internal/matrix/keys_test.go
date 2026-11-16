package matrix

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

type keyRequest struct {
	path string
	body map[string]any
}

// keyServer records every key-endpoint request and answers from the table.
type keyServer struct {
	mu       sync.Mutex
	requests []keyRequest
	handle   func(path string, body map[string]any) (int, string)
}

func newKeyServer(t *testing.T, handle func(path string, body map[string]any) (int, string)) (*keyServer, *Client) {
	t.Helper()
	s := &keyServer{handle: handle}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		s.mu.Lock()
		s.requests = append(s.requests, keyRequest{r.URL.Path, body})
		s.mu.Unlock()
		status, reply := s.handle(r.URL.Path, body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	return s, New(srv.URL, "token")
}

func (s *keyServer) count(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.requests {
		if r.path == path {
			n++
		}
	}
	return n
}

func (s *keyServer) last() keyRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests[len(s.requests)-1]
}

const signingPath = "/_matrix/client/v3/keys/device_signing/upload"
const uiaChallenge = `{"session":"xs","flows":[{"stages":["m.login.password"]}],"params":{}}`

var sampleKeys = CrossSigningUpload{MasterKey: json.RawMessage(`{"user_id":"@a:s","usage":["master"],"keys":{"ed25519:m":"m"}}`), SelfSigningKey: json.RawMessage(`{"user_id":"@a:s","usage":["self_signing"],"keys":{"ed25519:s":"s"}}`), UserSigningKey: json.RawMessage(`{"user_id":"@a:s","usage":["user_signing"],"keys":{"ed25519:u":"u"}}`)}

// checkEmptyPasswordNeverSent is the killer assertion shared by the
// empty-password negative and its plant control: with a UIA challenge and an
// empty stored password, the upload must refuse ErrUIARequired after exactly
// one request, so no auth stage carrying an empty password reaches the server.
func checkEmptyPasswordNeverSent(t *testing.T) error {
	t.Helper()
	s, c := newKeyServer(t, func(path string, body map[string]any) (int, string) {
		if body["auth"] != nil {
			return 200, `{}`
		}
		return 401, uiaChallenge
	})
	err := c.UploadCrossSigningKeys(context.Background(), "@a:s", sampleKeys, func(context.Context) (string, error) { return "", nil })
	if !errors.Is(err, ErrUIARequired) {
		return fmt.Errorf("empty password upload returned %v", err)
	}
	if n := s.count(signingPath); n != 1 {
		return fmt.Errorf("%d requests: an auth stage was sent with an empty password", n)
	}
	return nil
}

// Cross-signing upload is passwordless first; a UIA challenge offering
// m.login.password is completed once with the stored password; beside it, a
// challenge without a password flow, a nil provider, an empty stored password
// and a rejected password all refuse with their typed error and send no
// further stage (empty password: not even one).
func TestUploadCrossSigningKeysUIA(t *testing.T) {
	t.Run("passwordless", func(t *testing.T) {
		s, c := newKeyServer(t, func(string, map[string]any) (int, string) { return 200, `{}` })
		called := false
		if err := c.UploadCrossSigningKeys(context.Background(), "@a:s", sampleKeys, func(context.Context) (string, error) { called = true; return "generated-password-1", nil }); err != nil || called || s.count(signingPath) != 1 || s.last().body["auth"] != nil {
			t.Fatal("passwordless upload", err, called)
		}
	})
	t.Run("password-fallback", func(t *testing.T) {
		s, c := newKeyServer(t, func(path string, body map[string]any) (int, string) {
			if auth, ok := body["auth"].(map[string]any); ok && auth["password"] == "generated-password-1" && auth["session"] == "xs" && auth["type"] == "m.login.password" {
				return 200, `{}`
			}
			return 401, uiaChallenge
		})
		if err := c.UploadCrossSigningKeys(context.Background(), "@a:s", sampleKeys, func(context.Context) (string, error) { return "generated-password-1", nil }); err != nil || s.count(signingPath) != 2 {
			t.Fatal("password fallback", err)
		}
		identifier := s.last().body["auth"].(map[string]any)["identifier"].(map[string]any)
		if identifier["type"] != "m.id.user" || identifier["user"] != "@a:s" {
			t.Fatal("identifier")
		}
	})
	t.Run("no-password-flow", func(t *testing.T) {
		s, c := newKeyServer(t, func(string, map[string]any) (int, string) {
			return 401, `{"session":"xs","flows":[{"stages":["m.login.sso"]}],"params":{}}`
		})
		if err := c.UploadCrossSigningKeys(context.Background(), "@a:s", sampleKeys, func(context.Context) (string, error) { return "generated-password-1", nil }); !errors.Is(err, ErrUIARequired) || s.count(signingPath) != 1 {
			t.Fatal("unsupported flow", err)
		}
	})
	t.Run("no-provider", func(t *testing.T) {
		s, c := newKeyServer(t, func(string, map[string]any) (int, string) { return 401, uiaChallenge })
		if err := c.UploadCrossSigningKeys(context.Background(), "@a:s", sampleKeys, nil); !errors.Is(err, ErrUIARequired) || s.count(signingPath) != 1 {
			t.Fatal("nil provider", err)
		}
	})
	t.Run("empty-password", func(t *testing.T) {
		if err := checkEmptyPasswordNeverSent(t); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("provider-error", func(t *testing.T) {
		sentinel := errors.New("section unavailable")
		s, c := newKeyServer(t, func(string, map[string]any) (int, string) { return 401, uiaChallenge })
		if err := c.UploadCrossSigningKeys(context.Background(), "@a:s", sampleKeys, func(context.Context) (string, error) { return "", sentinel }); !errors.Is(err, sentinel) || s.count(signingPath) != 1 {
			t.Fatal("provider error", err)
		}
	})
	t.Run("rejected-password", func(t *testing.T) {
		s, c := newKeyServer(t, func(path string, body map[string]any) (int, string) {
			if body["auth"] != nil {
				return 401, `{"errcode":"M_FORBIDDEN","error":"bad","session":"xs","flows":[{"stages":["m.login.password"]}],"completed":[]}`
			}
			return 401, uiaChallenge
		})
		if err := c.UploadCrossSigningKeys(context.Background(), "@a:s", sampleKeys, func(context.Context) (string, error) { return "generated-password-1", nil }); !errors.Is(err, ErrUIARejected) || s.count(signingPath) != 2 {
			t.Fatal("rejected password", err)
		}
	})
	t.Run("server-error", func(t *testing.T) {
		_, c := newKeyServer(t, func(string, map[string]any) (int, string) { return 500, `{"errcode":"M_UNKNOWN"}` })
		var me *Error
		if err := c.UploadCrossSigningKeys(context.Background(), "@a:s", sampleKeys, nil); !errors.As(err, &me) || me.Status != 500 {
			t.Fatal("server error passthrough", err)
		}
	})
}

// Plant control: with the empty-password guard removed, the empty stored
// password would be sent as a password stage and the killer assertion fails.
func TestEmptyPasswordGuardPlantKilled(t *testing.T) {
	if err := checkEmptyPasswordNeverSent(t); err != nil {
		t.Fatal("killer assertion must pass before the plant:", err)
	}
	original := uiaPasswordGuard
	uiaPasswordGuard = func(string) error { return nil }
	defer func() { uiaPasswordGuard = original }()
	if checkEmptyPasswordNeverSent(t) == nil {
		t.Fatal("plant survived: an empty UIA password was accepted without detection")
	}
}

// QueryOwnKeys returns exactly the requested user's objects; failures, an
// answer for another user and malformed sections are incomplete, never absence.
func TestQueryOwnKeys(t *testing.T) {
	query := "/_matrix/client/v3/keys/query"
	t.Run("complete", func(t *testing.T) {
		s, c := newKeyServer(t, func(string, map[string]any) (int, string) {
			return 200, `{"device_keys":{"@a:s":{"DEV":{"user_id":"@a:s","device_id":"DEV","keys":{}}}},"master_keys":{"@a:s":{"user_id":"@a:s","usage":["master"],"keys":{"ed25519:m":"m"}}},"failures":{}}`
		})
		own, err := c.QueryOwnKeys(context.Background(), "@a:s")
		if err != nil || len(own.DeviceKeys) != 1 || own.MasterKey == nil || own.SelfSigningKey != nil {
			t.Fatal("complete query", err)
		}
		var master map[string]any
		if json.Unmarshal(own.MasterKey, &master) != nil || master["user_id"] != "@a:s" {
			t.Fatal("master object")
		}
		requested := s.last().body["device_keys"].(map[string]any)
		if _, ok := requested["@a:s"]; !ok || len(requested) != 1 {
			t.Fatal("request shape")
		}
	})
	t.Run("absent", func(t *testing.T) {
		_, c := newKeyServer(t, func(string, map[string]any) (int, string) { return 200, `{"device_keys":{"@a:s":{}}}` })
		own, err := c.QueryOwnKeys(context.Background(), "@a:s")
		if err != nil || len(own.DeviceKeys) != 0 || own.MasterKey != nil {
			t.Fatal("absent keys", err)
		}
	})
	for name, body := range map[string]string{
		"failures":      `{"device_keys":{},"failures":{"s":{"status":503}}}`,
		"other-user":    `{"device_keys":{"@b:s":{}}}`,
		"other-master":  `{"device_keys":{},"master_keys":{"@b:s":{"user_id":"@b:s"}}}`,
		"malformed":     `{"device_keys":{"@a:s":[]}}`,
		"duplicate-key": `{"device_keys":{"@a:s":{}},"device_keys":{"@a:s":{}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, c := newKeyServer(t, func(string, map[string]any) (int, string) { return 200, body })
			if _, err := c.QueryOwnKeys(context.Background(), "@a:s"); err == nil {
				t.Fatal("incomplete query admitted")
			}
		})
	}
	_ = query
}

// Device-key and signature uploads carry the exact objects; reported signature
// failures refuse, an empty failures map succeeds.
func TestUploadDeviceKeysAndSignatures(t *testing.T) {
	device := json.RawMessage(`{"user_id":"@a:s","device_id":"DEV","algorithms":[],"keys":{},"signatures":{}}`)
	t.Run("device-keys", func(t *testing.T) {
		s, c := newKeyServer(t, func(string, map[string]any) (int, string) { return 200, `{"one_time_key_counts":{}}` })
		if err := c.UploadDeviceKeys(context.Background(), device); err != nil {
			t.Fatal(err)
		}
		if s.last().path != "/_matrix/client/v3/keys/upload" || s.last().body["device_keys"].(map[string]any)["device_id"] != "DEV" {
			t.Fatal("upload shape")
		}
		if err := c.UploadDeviceKeys(context.Background(), json.RawMessage(`{`)); err == nil {
			t.Fatal("invalid object admitted")
		}
	})
	t.Run("signatures", func(t *testing.T) {
		s, c := newKeyServer(t, func(string, map[string]any) (int, string) { return 200, `{"failures":{}}` })
		if err := c.UploadSignatures(context.Background(), "@a:s", "DEV", device); err != nil {
			t.Fatal(err)
		}
		if s.last().path != "/_matrix/client/v3/keys/signatures/upload" || s.last().body["@a:s"].(map[string]any)["DEV"] == nil {
			t.Fatal("signature upload shape")
		}
	})
	t.Run("signature-failures", func(t *testing.T) {
		_, c := newKeyServer(t, func(string, map[string]any) (int, string) {
			return 200, `{"failures":{"@a:s":{"DEV":{"errcode":"M_INVALID_SIGNATURE"}}}}`
		})
		if err := c.UploadSignatures(context.Background(), "@a:s", "DEV", device); !errors.Is(err, ErrSignatureUploadFailed) {
			t.Fatal("failures admitted", err)
		}
	})
}
