package config

import (
	"encoding/json"
	"strings"
	"testing"
)

const validExplicitSelection = `{"identity":{"domain":"example","kind":"explicit","name":"fixture-a","origin":null},"session_mode":"registered"}`
const validSyntheticSelection = `{"identity":{"domain":"example","kind":"synthetic","name":"syn1:09155b1290b5e9bc09a1a929ad8d9fffcb21002e553fdf849acda156d6b74bb7","origin":{"host_id":"host-fixture-01","project_id":"project-fixture-01","profile_id":"profile-fixture-01"}},"session_mode":"direct"}`

func vaultMetadata(selection string) []byte {
	return []byte(`{"connection_binding":{"connection":{"connection_id":"fixture-a","homeserver_url":"https://matrix-a.example.invalid","server_name":"a.example.invalid","credential_store":{"backend":"vault-v1","access_token_service":"","password_service":""}},"user_id":"@fixture:a.example.invalid","class":"agents"},"user_id":"@fixture:a.example.invalid","device_id":"dev","homeserver":"https://matrix-a.example.invalid","vault_selection":` + selection + `}`)
}

// Claim: strict named decoding admits exactly the closed vault_selection
// shape (explicit null origin and synthetic triple, byte-exact non-ASCII) and
// refuses missing, unknown, duplicate, wrong-type, invalid-UTF-8 and lone
// surrogate variants without filling the destination. Semantic validation is
// out of scope here (vaultv1 owns it), so a bad session mode still decodes.
func TestVaultSelectionStrictDecode(t *testing.T) {
	for _, sel := range []string{validExplicitSelection, validSyntheticSelection, strings.Replace(validSyntheticSelection, "host-fixture-01", "hôst 01 \U0001F600", 1)} {
		var c Credentials
		if err := DecodeConnectionJSON(vaultMetadata(sel), &c); err != nil || c.VaultSelection == nil {
			t.Fatalf("valid selection refused: %v", err)
		}
	}
	var c Credentials
	_ = DecodeConnectionJSON(vaultMetadata(strings.Replace(validSyntheticSelection, "host-fixture-01", "hôst \U0001F600", 1)), &c)
	if c.VaultSelection.Identity.Origin.HostID != "hôst \U0001F600" || c.VaultSelection.Identity.Kind != "synthetic" || c.VaultSelection.SessionMode != "direct" {
		t.Fatal("decoded bytes changed")
	}
	if err := DecodeConnectionJSON(vaultMetadata(strings.Replace(validExplicitSelection, `"registered"`, `"Registered"`, 1)), &c); err != nil {
		t.Fatal("shape decode must not own session-mode semantics")
	}
	for _, tc := range []struct{ label, sel string }{
		{"missing session_mode", `{"identity":{"domain":"example","kind":"explicit","name":"fixture-a","origin":null}}`},
		{"missing origin", `{"identity":{"domain":"example","kind":"explicit","name":"fixture-a"},"session_mode":"registered"}`},
		{"unknown top field", strings.Replace(validExplicitSelection, `"session_mode"`, `"trust":true,"session_mode"`, 1)},
		{"unknown identity field", strings.Replace(validExplicitSelection, `"origin":null`, `"origin":null,"account":"@x:y"`, 1)},
		{"unknown origin field", strings.Replace(validSyntheticSelection, `"profile_id"`, `"pid":"1","profile_id"`, 1)},
		{"missing origin field", strings.Replace(validSyntheticSelection, `,"profile_id":"profile-fixture-01"`, ``, 1)},
		{"duplicate session_mode", strings.Replace(validExplicitSelection, `"session_mode":"registered"`, `"session_mode":"registered","session_mode":"direct"`, 1)},
		{"duplicate name", strings.Replace(validExplicitSelection, `"name":"fixture-a"`, `"name":"fixture-a","name":"fixture-b"`, 1)},
		{"session_mode number", strings.Replace(validExplicitSelection, `"registered"`, `1`, 1)},
		{"session_mode null", strings.Replace(validExplicitSelection, `"registered"`, `null`, 1)},
		{"name array", strings.Replace(validExplicitSelection, `"fixture-a"`, `["fixture-a"]`, 1)},
		{"origin string", strings.Replace(validExplicitSelection, `"origin":null`, `"origin":"null"`, 1)},
		{"identity null", `{"identity":null,"session_mode":"registered"}`},
		{"selection array", `[]`},
		{"selection string", `"vault"`},
		{"lone surrogate escape", strings.Replace(validExplicitSelection, `fixture-a`, `fixture-a\ud800`, 1)},
		{"invalid UTF-8", strings.Replace(validExplicitSelection, `fixture-a`, "fixture-a\xff", 1)},
		{"nested key case variant", strings.Replace(validExplicitSelection, `"session_mode"`, `"Session_Mode"`, 1)},
	} {
		var c Credentials
		if err := DecodeConnectionJSON(vaultMetadata(tc.sel), &c); err == nil {
			t.Fatalf("%s admitted", tc.label)
		}
		var s VaultSelection
		if err := json.Unmarshal([]byte(tc.sel), &s); err == nil || s != (VaultSelection{}) {
			t.Fatalf("%s: type-level decode admitted or partially filled", tc.label)
		}
	}
}

// Claim: a case-variant top-level key cannot shadow vault_selection in strict
// named decoding (encoding/json matches keys case-insensitively), beside the
// canonical single key that decodes.
func TestVaultSelectionCaseShadow(t *testing.T) {
	canonical := vaultMetadata(validExplicitSelection)
	var c Credentials
	if err := DecodeConnectionJSON(canonical, &c); err != nil || c.VaultSelection == nil {
		t.Fatalf("canonical refused: %v", err)
	}
	shadow := []byte(strings.TrimSuffix(string(canonical), "}") + `,"Vault_Selection":` + strings.Replace(validExplicitSelection, "registered", "direct", 1) + `}`)
	if err := DecodeConnectionJSON(shadow, &c); err == nil {
		t.Fatal("case-variant shadow vault_selection admitted")
	}
}

// Claim: legacy metadata without vault_selection keeps the exact serialized
// bytes and ConnectionBinding fingerprints computed at base 5515495 (pinned
// literals produced by the unmodified source), and an explicit null decodes
// as absence.
func TestVaultSelectionLegacyCompatibility(t *testing.T) {
	for _, tc := range []struct{ backend, fingerprint, credentials string }{
		{"file", "93e267bbbee81eb1c974f1296654f23ea930d3f34b68bbe544176bb56d9c6366", `{"connection_binding":{"connection":{"connection_id":"fixture-a","homeserver_url":"https://matrix-a.example.invalid","server_name":"a.example.invalid","credential_store":{"backend":"file","access_token_service":"","password_service":""}},"user_id":"@fixture:a.example.invalid","class":"agents"},"user_id":"@fixture:a.example.invalid","device_id":"dev","homeserver":"https://matrix-a.example.invalid"}`},
		{"keychain", "946e6251a0a1d6015aaefeb8d8f215cedbee12ed40a699d21b6337298616c86a", `{"connection_binding":{"connection":{"connection_id":"fixture-a","homeserver_url":"https://matrix-a.example.invalid","server_name":"a.example.invalid","credential_store":{"backend":"keychain","access_token_service":"test.a.token","password_service":"test.a.password"}},"user_id":"@fixture:a.example.invalid","class":"agents"},"user_id":"@fixture:a.example.invalid","device_id":"dev","homeserver":"https://matrix-a.example.invalid"}`},
	} {
		c := Connection{ID: "fixture-a", URL: "https://matrix-a.example.invalid", ServerName: "a.example.invalid", Store: CredentialStore{Backend: tc.backend}}
		if tc.backend == "keychain" {
			c.Store.AccessTokenService, c.Store.PasswordService = "test.a.token", "test.a.password"
		}
		b, err := c.Binding("fixture", false)
		if err != nil || b.Fingerprint() != tc.fingerprint {
			t.Fatalf("%s fingerprint changed: %v", tc.backend, err)
		}
		out, _ := json.Marshal(Credentials{UserID: b.UserID, DeviceID: "dev", Homeserver: c.URL, ConnectionBinding: &b})
		if string(out) != tc.credentials {
			t.Fatalf("%s legacy serialization changed", tc.backend)
		}
		var back Credentials
		if err := DecodeConnectionJSON(out, &back); err != nil || back.VaultSelection != nil || ValidateBoundCredentials(back, b) != nil {
			t.Fatalf("%s legacy round trip: %v", tc.backend, err)
		}
		withNull := []byte(strings.TrimSuffix(string(out), "}") + `,"vault_selection":null}`)
		if err := DecodeConnectionJSON(withNull, &back); err != nil || back.VaultSelection != nil {
			t.Fatalf("%s explicit null is not absence", tc.backend)
		}
	}
}

// Claim: vault-v1 is admitted only as a release-only named backend (no
// Keychain services, registration_token_ref or admin_registration), and
// ValidateBoundCredentials requires vault_selection for vault-v1 and forbids
// it for file/keychain, beside unchanged legacy positives.
func TestVaultBackendValidation(t *testing.T) {
	base := Connection{ID: "fixture-a", URL: "https://matrix-a.example.invalid", ServerName: "a.example.invalid", Store: CredentialStore{Backend: BackendVaultV1}}
	if err := base.Validate(); err != nil {
		t.Fatalf("release-only vault-v1 refused: %v", err)
	}
	for label, mut := range map[string]func(*Connection){
		"token service":    func(c *Connection) { c.Store.AccessTokenService = "test.a.token" },
		"password service": func(c *Connection) { c.Store.PasswordService = "test.a.password" },
		"registration_token_ref": func(c *Connection) {
			c.RegistrationTokenRef = &SecretReference{Service: "test.a.bootstrap", Account: "x"}
		},
		"admin_registration": func(c *Connection) { c.AdminRegistration = &AdminRegistration{Method: "tuwunel-v1.9.4-admin-room"} },
		"unknown backend":    func(c *Connection) { c.Store.Backend = "vault-v2" },
		"case variant":       func(c *Connection) { c.Store.Backend = "Vault-V1" },
	} {
		c := base
		mut(&c)
		if c.Validate() == nil {
			t.Fatalf("%s admitted", label)
		}
	}
	vb, _ := base.Binding("fixture", false)
	sel := &VaultSelection{Identity: VaultIdentity{Domain: "example", Kind: "explicit", Name: "fixture-a"}, SessionMode: "registered"}
	creds := Credentials{UserID: vb.UserID, Homeserver: base.URL, ConnectionBinding: &vb, VaultSelection: sel}
	if err := ValidateBoundCredentials(creds, vb); err != nil {
		t.Fatalf("vault metadata refused: %v", err)
	}
	creds.VaultSelection = nil
	if ValidateBoundCredentials(creds, vb) == nil {
		t.Fatal("vault-v1 without vault_selection admitted")
	}
	creds.VaultSelection, creds.AccessToken = sel, "x"
	if ValidateBoundCredentials(creds, vb) == nil {
		t.Fatal("vault-v1 metadata with access_token admitted")
	}
	file := base
	file.Store.Backend = "file"
	fb, _ := file.Binding("fixture", false)
	legacy := Credentials{UserID: fb.UserID, Homeserver: file.URL, ConnectionBinding: &fb, AccessToken: "x"}
	if err := ValidateBoundCredentials(legacy, fb); err != nil {
		t.Fatalf("legacy file metadata refused: %v", err)
	}
	legacy.VaultSelection = sel
	if ValidateBoundCredentials(legacy, fb) == nil {
		t.Fatal("legacy backend with vault_selection admitted")
	}
}
