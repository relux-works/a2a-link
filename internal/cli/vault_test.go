//go:build unix

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/a2a-swarm/internal/config"
)

const vaultSelectionJSON = `{"identity":{"domain":"fixture-domain","kind":"explicit","name":"fixture-alpha","origin":null},"session_mode":"registered"}`

// vaultFixture extends the named keychain fixture with a vault-v1 profile
// whose selected account equals alpha's. alpha's valid Keychain item and a
// valid legacy file token stay planted as tempting alternate sources.
type vaultFixture struct {
	*namedFixture
	vault    *cliVault
	keychain int
	legacy   int
	provider *vaultFixtureProvider
}

func newVaultFixture(t *testing.T, selection string) *vaultFixture {
	t.Helper()
	f := &vaultFixture{namedFixture: newNamedFixture(t, true), vault: &cliVault{token: []byte("isolated-alpha")}}
	alpha := f.r.Profiles["alpha"]
	f.r.Profiles["vault"] = config.Connection{ID: "vault-id", URL: alpha.URL, ServerName: alpha.ServerName, Store: config.CredentialStore{Backend: config.BackendVaultV1}}
	f.save()
	f.writeMetadata(t, selection, nil)
	legacy := config.Paths{Base: f.root}
	if err := os.MkdirAll(filepath.Dir(legacy.AgentFile("alice")), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy.AgentFile("alice"), []byte(`{"user_id":"@alice:alpha.invalid","access_token":"isolated-alpha","device_id":"d","homeserver":"`+alpha.URL+`"}`), 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

// writeMetadata writes the vault profile's named agent metadata. mut may edit
// the raw JSON text; selection "" omits the field.
func (f *vaultFixture) writeMetadata(t *testing.T, selection string, mut func(string) string) {
	t.Helper()
	c := f.r.Profiles["vault"]
	b, err := c.Binding("alice", false)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(config.Credentials{UserID: b.UserID, DeviceID: "d", Homeserver: c.URL, ConnectionBinding: &b})
	if err != nil {
		t.Fatal(err)
	}
	// The selection is spliced in as raw text so malformed values are planted exactly.
	raw := string(data)
	if selection != "" {
		raw = strings.TrimSuffix(raw, "}") + `,"vault_selection":` + selection + `}`
	}
	p := f.paths("vault", false)
	if mut != nil {
		raw = mut(raw)
	}
	if err := os.MkdirAll(filepath.Dir(p.AgentFile("alice")), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.AgentFile("alice"), []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
}

func (f *vaultFixture) app(dep bool) *App {
	a := f.namedFixture.app()
	a.beforeLegacyCredentialRead = func() { f.legacy++ }
	a.lookupEnv = func(k string) (string, bool) { v, ok := f.env[k]; return v, ok }
	// Counting trap with an isolated fake backend: a correct vault path never
	// constructs it, and a mutant that does reaches no platform Keychain.
	a.keychain = func(p config.Paths) *keychainStore {
		f.keychain++
		var calls []opRecord
		return &keychainStore{paths: p, fixture: filepath.Join(f.root, "trap.keychain-db"), hostID: "isolated-host", timeout: time.Second, probeCommand: unlockedProbe, backend: routingBackend{&calls}}
	}
	if dep {
		// Snapshot explicitly qualified logical context; normal runtime metadata
		// loading/admission/client are exercised by the real credential path.
		c := f.r.Profiles["vault"]
		b, _ := c.Binding("alice", false)
		raw, _ := os.ReadFile(f.paths("vault", false).AgentFile("alice"))
		var creds config.Credentials
		if config.DecodeConnectionJSON(raw, &creds) == nil {
			if sel, e := creds.VaultSelection.Selection(); e == nil {
				if o, r := vaultObserve(sel, "alice", b); r == nil {
					f.provider = &vaultFixtureProvider{value: vaultFixtureContext(o)}
					a.vaultContext = f.provider
				}
			}
		}
		a.vaultDependency = func(vaultCredentialSelection) (*vaultDependency, error) { f.vault.factory++; return f.vault.dep(), nil }
	}

	return a
}

// snapshot captures every byte the vault path must never change.
func (f *vaultFixture) snapshot(t *testing.T) string {
	t.Helper()
	var out []string
	for _, p := range []string{filepath.Join(f.root, "connections.json"), f.paths("vault", false).AgentFile("alice"), config.Paths{Base: f.root}.AgentFile("alice"), f.paths("alpha", false).AgentFile("alice")} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string(b))
	}
	f.store.mu.Lock()
	out = append(out, f.store.items[config.SecretReference{Service: "test.alpha.token", Account: "@alice:alpha.invalid"}])
	f.store.mu.Unlock()
	return strings.Join(out, "\x00")
}

// zero asserts no vault discovery/driver call and no legacy secret read.
func (f *vaultFixture) zero(t *testing.T, label string) {
	t.Helper()
	f.store.mu.Lock()
	reads := len(f.store.reads) + len(f.store.creates)
	f.store.mu.Unlock()
	if f.legacy != 0 || (f.provider != nil && f.provider.calls != 0) || f.vault.factory != 0 || len(f.vault.events) != 0 || reads != 0 || f.keychain != 0 || f.httpCalls.Load() != 0 {
		t.Fatalf("%s: factory=%d events=%v store=%d keychain=%d http=%d", label, f.vault.factory, f.vault.events, reads, f.keychain, f.httpCalls.Load())
	}
}

func vaultErrorCode(err error) string {
	var r *vaultFailure
	if errors.As(err, &r) {
		return string(r.Outcome) + " " + string(r.Code) + string(r.Diagnosis)
	}
	return ""
}

// Claim: the explicit named vault-v1 profile authenticates through the
// dependency only (factory once; open, verify, register, release, close in
// that order) and the Matrix request carries exactly the vault token, with
// zero Keychain/file secret reads beside planted valid legacy items. The
// direct mode submits only a release. Nearby legacy control: the keychain
// profile in the same registry still reads its Keychain item and never
// touches the vault seam.
func TestVaultV1CredentialFlow(t *testing.T) {
	for _, tc := range []struct{ mode, events string }{
		{"registered", "open,verify:before_operation,prepare:register,verify:before_operation,invoke:register,verify:after_reply,discard:register,verify:before_operation,prepare:release,verify:before_operation,invoke:release,verify:after_reply,discard:release,close"},
		{"direct", "open,verify:before_operation,prepare:release,verify:before_operation,invoke:release,verify:after_reply,discard:release,close"},
	} {
		f := newVaultFixture(t, strings.Replace(vaultSelectionJSON, "registered", tc.mode, 1))
		a := f.app(true)
		if a.Run(context.Background(), []string{"--profile", "vault", "whoami"}) != 0 {
			t.Fatalf("%s: %s", tc.mode, f.err.String())
		}
		f.store.mu.Lock()
		reads := len(f.store.reads)
		f.store.mu.Unlock()
		if f.vault.factory != 1 || strings.Join(f.vault.events, ",") != tc.events || reads != 0 || f.keychain != 0 || f.httpCalls.Load() != 1 {
			t.Fatalf("%s: factory=%d events=%v reads=%d keychain=%d http=%d", tc.mode, f.vault.factory, f.vault.events, reads, f.keychain, f.httpCalls.Load())
		}
		if strings.Contains(f.out.String()+f.err.String(), "isolated-alpha") {
			t.Fatal("token printed")
		}
	}
	f := newVaultFixture(t, vaultSelectionJSON)
	a := f.app(true)
	if a.Run(context.Background(), []string{"--profile", "alpha", "whoami"}) != 0 {
		t.Fatal(f.err.String())
	}
	f.store.mu.Lock()
	reads := len(f.store.reads)
	f.store.mu.Unlock()
	if reads != 1 || f.vault.factory != 0 || len(f.vault.events) != 0 {
		t.Fatalf("legacy keychain control: reads=%d factory=%d", reads, f.vault.factory)
	}
}

// Claim: with the production default (no qualified native dependency), a
// valid vault-v1 selection refuses NOT_SUBMITTED E_CONTEXT before any
// vault, network or legacy secret call, and changes no file or item. The
// positive neighbour is TestVaultV1CredentialFlow with the same fixture.
func TestVaultV1ProductionDefaultUnavailable(t *testing.T) {
	f := newVaultFixture(t, vaultSelectionJSON)
	before := f.snapshot(t)
	a := f.app(false)
	if a.vaultDependency != nil {
		t.Fatal("production App has a vault dependency")
	}
	if NewApp().vaultDependency != nil {
		t.Fatal("NewApp installs a vault dependency")
	}
	if a.Run(context.Background(), []string{"--profile", "vault", "whoami"}) == 0 || !strings.Contains(f.err.String(), "vault-v1 NOT_SUBMITTED E_CONTEXT") {
		t.Fatalf("production default did not refuse: %s", f.err.String())
	}
	f.zero(t, "production default")
	if f.snapshot(t) != before {
		t.Fatal("state changed")
	}
}

// Claim: metadataOnly validates the same vault selection (valid admitted,
// invalid refused with its r4 code) with ZERO dependency factory, driver,
// verifier, legacy-store and network calls, and yields no secret. The
// credential-flow control on the same fixture uses the dependency once.
func TestVaultV1MetadataOnlyZeroCalls(t *testing.T) {
	f := newVaultFixture(t, vaultSelectionJSON)
	a := f.app(true)
	a.profile = "vault"
	s, err := a.sessionMetadata()
	if err != nil {
		t.Fatalf("valid metadata session refused: %v", err)
	}
	if s.creds.AccessToken != "" || !s.creds.VaultSelection.Present() {
		t.Fatal("metadata session carries a secret or lost its selection")
	}
	f.zero(t, "metadata-only valid")
	f.writeMetadata(t, strings.Replace(vaultSelectionJSON, `"registered"`, `"auto"`, 1), nil)
	b := f.app(true)
	b.profile = "vault"
	if _, err := b.sessionMetadata(); vaultErrorCode(err) != "NOT_SUBMITTED E_FORMAT" {
		t.Fatalf("invalid metadata session: %v", err)
	}
	f.zero(t, "metadata-only invalid")
	// Credential-flow control: the same seam is used when a secret is needed.
	f.writeMetadata(t, vaultSelectionJSON, nil)
	c := f.app(true)
	c.profile = "vault"
	if _, err := c.session(); err != nil || f.vault.factory != 1 || f.vault.effects != 2 {
		t.Fatalf("credential control: %v factory=%d events=%v", err, f.vault.factory, f.vault.events)
	}
}

// Claim: every malformed, conflicting or secret-bearing selection refuses
// with a named error before any vault or legacy secret call, without
// rewriting metadata, registry or legacy items. The first case is the
// valid positive control on the identical fixture.
func TestVaultV1SelectionRefusals(t *testing.T) {
	syn := `{"identity":{"domain":"fixture-domain","kind":"synthetic","name":"syn1:09155b1290b5e9bc09a1a929ad8d9fffcb21002e553fdf849acda156d6b74bb7","origin":{"host_id":"host-fixture-01","project_id":"project-fixture-01","profile_id":"profile-fixture-01"}},"session_mode":"direct"}`
	for _, tc := range []struct {
		label   string
		sel     string
		mut     func(string) string
		env     map[string]string
		profile string
		want    string // vault outcome+code, or a source-owned diagnostic substring
	}{
		{"valid synthetic control", syn, nil, nil, "vault", ""},
		{"null selection", "null", nil, nil, "vault", "NOT_SUBMITTED E_FORMAT"},
		{"invalid JSON selection escape", strings.Replace(vaultSelectionJSON, "fixture-alpha", `fixture-\uZZZZ`, 1), nil, nil, "vault", "NOT_SUBMITTED E_FORMAT"},
		{"incomplete JSON selection", strings.TrimSuffix(vaultSelectionJSON, "}"), nil, nil, "vault", "NOT_SUBMITTED E_FORMAT"},
		{"missing vault_selection", "", nil, nil, "vault", "NOT_SUBMITTED E_BACKEND_CONFIG"},
		{"unknown selection field", strings.Replace(vaultSelectionJSON, `"session_mode"`, `"trust":true,"session_mode"`, 1), nil, nil, "vault", "NOT_SUBMITTED E_FORMAT"},
		{"wrong-type mode", strings.Replace(vaultSelectionJSON, `"registered"`, `true`, 1), nil, nil, "vault", "NOT_SUBMITTED E_FORMAT"},
		{"duplicate selection key", strings.Replace(vaultSelectionJSON, `"session_mode":"registered"`, `"session_mode":"direct","session_mode":"registered"`, 1), nil, nil, "vault", "NOT_SUBMITTED E_FORMAT"},
		{"unknown session mode", strings.Replace(vaultSelectionJSON, `"registered"`, `"auto"`, 1), nil, nil, "vault", "NOT_SUBMITTED E_FORMAT"},
		{"empty session mode", strings.Replace(vaultSelectionJSON, `"registered"`, `""`, 1), nil, nil, "vault", "NOT_SUBMITTED E_FORMAT"},
		{"invalid explicit name", strings.Replace(vaultSelectionJSON, "fixture-alpha", "Fixture-Alpha", 1), nil, nil, "vault", "NOT_SUBMITTED E_IDENTITY"},
		{"oversized explicit name", strings.Replace(vaultSelectionJSON, "fixture-alpha", strings.Repeat("a", 513), 1), nil, nil, "vault", "NOT_SUBMITTED E_LIMIT"},
		{"invalid domain", strings.Replace(vaultSelectionJSON, "fixture-domain", "alpha.invalid:443", 1), nil, nil, "vault", "NOT_SUBMITTED E_CONTEXT"},
		{"origin mismatch", strings.Replace(syn, "project-fixture-01", "project-fixture-02", 1), nil, nil, "vault", "NOT_SUBMITTED E_IDENTITY_CONFLICT"},
		{"access_token in metadata", vaultSelectionJSON, func(s string) string {
			return strings.Replace(s, `"device_id"`, `"access_token":"isolated-alpha","device_id"`, 1)
		}, nil, "vault", "named metadata must not contain secrets"},
		{"password in metadata", vaultSelectionJSON, func(s string) string { return strings.Replace(s, `"device_id"`, `"password":"x","device_id"`, 1) }, nil, "vault", "named metadata must not contain secrets"},
		{"cross-connection binding", vaultSelectionJSON, func(s string) string {
			return strings.Replace(s, `"connection_id":"vault-id"`, `"connection_id":"alpha-id"`, 1)
		}, nil, "vault", "named credential binding mismatch"},
		{"user mismatch", vaultSelectionJSON, func(s string) string {
			return strings.Replace(s, `"user_id":"@alice:alpha.invalid","device_id"`, `"user_id":"@bob:alpha.invalid","device_id"`, 1)
		}, nil, "vault", "named credential binding mismatch"},
		{"empty present ambient with vault profile", vaultSelectionJSON, nil, map[string]string{envSecretStore: ""}, "vault", "NOT_SUBMITTED E_BACKEND_CONFIG"},
		{"ambient keychain with vault profile", vaultSelectionJSON, nil, map[string]string{envSecretStore: "keychain"}, "vault", "NOT_SUBMITTED E_BACKEND_CONFIG"},
		{"ambient vault-v1 with vault profile", vaultSelectionJSON, nil, map[string]string{envSecretStore: "vault-v1"}, "vault", "NOT_SUBMITTED E_BACKEND_CONFIG"},
		{"ambient vault-v1 with keychain profile", vaultSelectionJSON, nil, map[string]string{envSecretStore: "vault-v1"}, "alpha", "NOT_SUBMITTED E_BACKEND_CONFIG"},
	} {
		f := newVaultFixture(t, tc.sel)
		if tc.mut != nil {
			f.writeMetadata(t, tc.sel, tc.mut)
		}
		for k, v := range tc.env {
			f.env[k] = v
		}
		before := f.snapshot(t)
		a := f.app(true)
		a.profile = tc.profile
		_, err := a.sessionMetadata()
		if tc.want == "" {
			if err != nil {
				t.Fatalf("%s: positive control refused: %v", tc.label, err)
			}
			continue
		}
		if err == nil || (vaultErrorCode(err) != tc.want && !strings.Contains(err.Error(), tc.want)) {
			t.Fatalf("%s: got %v want %s", tc.label, err, tc.want)
		}
		// The credential path refuses identically and still makes no call.
		b := f.app(true)
		b.profile = tc.profile
		if _, err := b.session(); err == nil {
			t.Fatalf("%s: credential path admitted", tc.label)
		}
		f.zero(t, tc.label)
		if f.snapshot(t) != before {
			t.Fatalf("%s: state changed", tc.label)
		}
	}
}

// Claim: a profile cannot carry identity (unknown field refuses the whole
// registry), a legacy keychain profile cannot carry vault_selection, a human
// cannot use vault-v1, and legacy unnamed metadata cannot carry it either;
// each refuses before any vault or secret call, beside the valid control.
func TestVaultV1SelectionPlacement(t *testing.T) {
	f := newVaultFixture(t, vaultSelectionJSON)
	raw, _ := os.ReadFile(filepath.Join(f.root, "connections.json"))
	bad := strings.Replace(string(raw), `"connection_id":"vault-id"`, `"connection_id":"vault-id","vault_selection":`+vaultSelectionJSON, 1)
	if err := os.WriteFile(filepath.Join(f.root, "connections.json"), []byte(bad), 0600); err != nil {
		t.Fatal(err)
	}
	a := f.app(true)
	a.profile = "vault"
	if _, err := a.sessionMetadata(); err == nil {
		t.Fatal("identity in profile admitted")
	}
	f.zero(t, "identity in profile")

	f = newVaultFixture(t, vaultSelectionJSON)
	alpha := f.paths("alpha", false).AgentFile("alice")
	meta, _ := os.ReadFile(alpha)
	withSel := strings.TrimSuffix(strings.TrimSpace(string(meta)), "}") + `,"vault_selection":` + vaultSelectionJSON + "}\n"
	if err := os.WriteFile(alpha, []byte(withSel), 0600); err != nil {
		t.Fatal(err)
	}
	a = f.app(true)
	a.profile = "alpha"
	if _, err := a.session(); vaultErrorCode(err) != "NOT_SUBMITTED E_BACKEND_CONFIG" {
		t.Fatalf("vault_selection on keychain profile: %v", err)
	}
	f.zero(t, "selection on legacy profile")

	f = newVaultFixture(t, vaultSelectionJSON)
	a = f.app(true)
	a.profile, a.human = "vault", true
	if _, err := a.namedMetadata(f.paths("vault", false), "alice"); vaultErrorCode(err) != "NOT_SUBMITTED E_BACKEND_CONFIG" {
		t.Fatalf("human vault use: %v", err)
	}
	f.zero(t, "human")

	// Legacy unnamed mode: a vault_selection in the legacy file refuses.
	legacy := t.TempDir()
	lp := config.Paths{Base: legacy}
	_ = os.MkdirAll(filepath.Dir(lp.AgentFile("alice")), 0700)
	_ = os.WriteFile(lp.AgentFile("alice"), []byte(`{"user_id":"@alice:alpha.invalid","access_token":"isolated-alpha","device_id":"d","homeserver":"https://alpha.invalid","vault_selection":`+vaultSelectionJSON+`}`), 0600)
	l := NewApp()
	l.Getenv = func(k string) string {
		if k == config.EnvConfigDir {
			return legacy
		}
		return ""
	}
	if _, err := l.loadCredentials(context.Background(), lp, "alice"); vaultErrorCode(err) != "NOT_SUBMITTED E_BACKEND_CONFIG" {
		t.Fatalf("legacy unnamed vault_selection: %v", err)
	}
	if _, err := l.credentialMetadata(lp, "alice"); vaultErrorCode(err) != "NOT_SUBMITTED E_BACKEND_CONFIG" {
		t.Fatalf("legacy unnamed metadata: %v", err)
	}
	// Legacy unnamed control without the field still loads its file token.
	_ = os.WriteFile(lp.AgentFile("alice"), []byte(`{"user_id":"@alice:alpha.invalid","access_token":"isolated-alpha","device_id":"d","homeserver":"https://alpha.invalid"}`), 0600)
	if c, err := l.loadCredentials(context.Background(), lp, "alice"); err != nil || c.AccessToken != "isolated-alpha" {
		t.Fatalf("legacy file control: %v", err)
	}
}

// Claim: once vault-v1 is selected, unavailability, verifier rejection, an
// authenticated refusal, an UNKNOWN reply and cancellation each fail without
// reading the planted valid Keychain/file tokens, contacting Matrix, changing
// the selected backend/identity or writing any file. The honest dependency on
// the same fixture succeeds.
func TestVaultV1NoLegacyFallback(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		label string
		setup func(*cliVault)
		ctx   context.Context
		want  string
	}{
		{"honest control", nil, context.Background(), ""},
		{"unavailable", func(v *cliVault) { v.openErr = errors.New("isolated-alpha") }, context.Background(), "NOT_SUBMITTED E_UNAVAILABLE"},
		{"verifier rejects", func(v *cliVault) { v.verifyErr = errors.New("isolated-alpha") }, context.Background(), "NOT_SUBMITTED E_SERVER_UNTRUSTED"},
		{"authenticated refusal", func(v *cliVault) {
			v.release = func(req vaultRequest) (vaultValue, error) {
				return vaultDict(vaultF("v", vaultUint(2)), vaultF("request_id", vaultString(req.id)), vaultF("op", vaultString("release")), vaultF("ok", vaultBool(false)), vaultF("error", vaultDict(vaultF("code", vaultString("E_REVOKED"))))), nil
			}
		}, context.Background(), "REFUSED E_REVOKED"},
		{"unknown after submit", func(v *cliVault) {
			v.release = func(vaultRequest) (vaultValue, error) { return vaultValue{}, errors.New("isolated-alpha") }
		}, context.Background(), "UNKNOWN transport_lost"},
		{"cancelled", nil, cancelled, "NOT_SUBMITTED E_UNAVAILABLE"},
	} {
		f := newVaultFixture(t, vaultSelectionJSON)
		if tc.setup != nil {
			tc.setup(f.vault)
		}
		before := f.snapshot(t)
		a := f.app(true)
		a.profile = "vault"
		p := f.paths("vault", false)
		creds, err := a.loadCredentials(tc.ctx, p, "alice")
		f.store.mu.Lock()
		reads := len(f.store.reads) + len(f.store.creates)
		f.store.mu.Unlock()
		if tc.want == "" {
			if err != nil || creds.AccessToken != "isolated-alpha" {
				t.Fatalf("control: %v", err)
			}
		} else if vaultErrorCode(err) != tc.want || creds.AccessToken != "" {
			t.Fatalf("%s: got %v want %s", tc.label, err, tc.want)
		}
		if err != nil && strings.Contains(err.Error(), "isolated-alpha") {
			t.Fatalf("%s: raw dependency error leaked", tc.label)
		}
		if reads != 0 || f.legacy != 0 || f.keychain != 0 || f.httpCalls.Load() != 0 || a.profile != "vault" || f.snapshot(t) != before {
			t.Fatalf("%s: fallback or effect: reads=%d legacy=%d keychain=%d http=%d profile=%s", tc.label, reads, f.legacy, f.keychain, f.httpCalls.Load(), a.profile)
		}
	}
}

// Claim: registration and daemon custody migration refuse on a vault-v1
// profile before any secret store, vault or network effect (release-only
// role, no a2ad custody move).
func TestVaultV1ReleaseOnlyCommands(t *testing.T) {
	f := newVaultFixture(t, vaultSelectionJSON)
	a := f.app(true)
	a.profile, a.authorizeRegistration = "vault", true
	if _, _, err := a.registerNamedAgentDestination(context.Background(), "alice", nil, nil); vaultErrorCode(err) != "NOT_SUBMITTED E_OPERATION_DENIED" {
		t.Fatalf("registration: %v", err)
	}
	f.zero(t, "registration")
	b := f.app(true)
	code := b.Run(context.Background(), []string{"--profile", "vault", "daemon", "migrate", "alice", "--to", filepath.Join(t.TempDir(), "daemon")})
	if code == 0 || !strings.Contains(f.err.String(), "vault-v1 NOT_SUBMITTED E_OPERATION_DENIED") {
		t.Fatalf("daemon migrate: %d %s", code, f.err.String())
	}
	f.zero(t, "daemon migrate")
}

// Claim: a live vault session refuses later effects when the per-agent
// selection changes (no live retargeting), while an unchanged selection keeps
// passing the existing connection check.
func TestVaultV1SelectionChangeRefusesLiveSession(t *testing.T) {
	f := newVaultFixture(t, vaultSelectionJSON)
	a := f.app(true)
	a.profile = "vault"
	s, err := a.session()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.checkConnection(); err != nil {
		t.Fatalf("unchanged selection refused: %v", err)
	}
	f.writeMetadata(t, strings.Replace(vaultSelectionJSON, "registered", "direct", 1), nil)
	if err := s.checkConnection(); vaultErrorCode(err) != "NOT_SUBMITTED E_IDENTITY_CONFLICT" {
		t.Fatalf("changed selection: %v", err)
	}
}

// Claim: independent admitted context is required before factory/open. A
// grammar-valid public selection alone grants nothing; explicitly mapped
// identity names may differ from the source selector. Actual CLI loading,
// admission and client run on the matching fixture, never a release stub.
func TestVaultAdmissionContext(t *testing.T) {
	for _, kind := range []string{"missing", "zero", "unissued", "domain", "declared", "mapping_missing", "mapping_wrong", "binding", "connection", "provider_error", ""} {
		t.Run(kind, func(t *testing.T) {
			f := newVaultFixture(t, vaultSelectionJSON)
			a := f.app(true)
			a.profile = "vault"
			before := f.snapshot(t)
			want := vaultEIdentityConflict
			switch kind {
			case "missing":
				a.vaultContext = nil
				want = vaultEContext
			case "zero":
				f.provider.value = vaultAdmittedContext{}
				want = vaultEContext
			case "unissued":
				f.provider.value.issuer = nil
				want = vaultEContext
			case "domain":
				f.provider.value.installDomain = "other-domain"
			case "declared":
				f.provider.value.declared.Name = "other-enrolled"
			case "mapping_missing":
				f.provider.value.mappedIdentity = vaultIdentity{}
				want = vaultEContext
			case "mapping_wrong":
				f.provider.value.mappedIdentity.Name = "other-enrolled"
			case "binding":
				f.provider.value.binding.HomeserverURL = "https://other.invalid"
			case "connection":
				f.provider.value.local.Connection.URL = "https://other.invalid"
			case "provider_error":
				f.provider.err = errors.New("isolated-alpha")
				want = vaultEContext
			}
			_, err := a.session()
			if kind == "" {
				if err != nil || f.vault.factory != 1 || f.vault.effects != 2 {
					t.Fatalf("admitted CLI neighbor: %v", err)
				}
				return
			}
			var failure *vaultFailure
			if !errors.As(err, &failure) || failure.Outcome != vaultNotSubmitted || failure.Code != want || f.vault.factory != 0 || len(f.vault.events) != 0 || f.keychain != 0 || f.legacy != 0 || f.httpCalls.Load() != 0 || f.snapshot(t) != before {
				t.Fatalf("context %s: %v factory=%d events=%v", kind, err, f.vault.factory, f.vault.events)
			}
		})
	}
	// Qualified context with absent driver reaches only local E_UNAVAILABLE;
	// production without context stops earlier as E_CONTEXT.
	f := newVaultFixture(t, vaultSelectionJSON)
	a := f.app(true)
	a.profile = "vault"
	a.vaultDependency = nil
	if _, e := a.session(); vaultErrorCode(e) != "NOT_SUBMITTED E_UNAVAILABLE" || len(f.vault.events) != 0 {
		t.Fatal("absent driver order")
	}
}

// Claim: origin scalar spelling is byte-preserving across metadata decode and
// observation, using a literal independent public derivation pin. Limits use
// decoded UTF-8 bytes (256 admitted, 257 refused) with a valid astral scalar.
func TestVaultSelectionUnicode(t *testing.T) {
	const pinned = "syn1:e694f628e0b9cd8261616a446ceabee4d0ab16aeffb12f2cb9655f6f9da35ff0"
	var reference vaultIdentity
	for _, spelling := range []string{"h😀", `h\uD83D\uDE00`} {
		raw := `{"identity":{"domain":"fixture-domain","kind":"synthetic","name":"` + pinned + `","origin":{"host_id":"` + spelling + `","project_id":"p","profile_id":"r"}},"session_mode":"direct"}`
		f := newVaultFixture(t, raw)
		a := f.app(true)
		a.profile = "vault"
		c := f.r.Profiles["vault"]
		creds, e := a.namedMetadata(f.paths("vault", false), "alice")
		if e != nil {
			t.Fatal("valid Unicode metadata refused")
		}
		o, e := a.observeVaultSelection(&c, "alice", creds)
		if e != nil {
			t.Fatal("valid Unicode observation refused")
		}
		if o.identity.Name != pinned || o.identity.Origin.HostID != "h😀" {
			t.Fatal("independent derivation/decoded bytes")
		}
		if reference.Name != "" && !reference.Equal(o.Identity()) {
			t.Fatal("pair/raw identity differs")
		}
		reference = o.Identity()
		f.zero(t, "Unicode observation")
	}
	for _, n := range []int{256, 257} {
		origin := config.VaultOrigin{HostID: strings.Repeat("a", n-4) + "😀", ProjectID: "p", ProfileID: "r"}
		syn := vaultSyntheticContext{HostID: origin.HostID, ProjectID: origin.ProjectID, ProfileID: origin.ProfileID}
		name := "syn1:" + strings.Repeat("0", 64)
		if n == 256 {
			name, _ = vaultSyntheticName(syn)
		}
		c := config.Connection{ID: "fixture-a", URL: "https://a.invalid", ServerName: "a.invalid", Store: config.CredentialStore{Backend: config.BackendVaultV1}}
		b, _ := c.Binding("fixture", false)
		_, r := vaultObserve(config.VaultSelection{Identity: config.VaultIdentity{Domain: "fixture-domain", Kind: vaultKindSynthetic, Name: name, Origin: &origin}, SessionMode: vaultSessionDirect}, "fixture", b)
		if n == 256 && r != nil {
			t.Fatal("256 decoded bytes refused")
		}
		if n == 257 && (r == nil || r.Code != vaultELimit) {
			t.Fatal("257 decoded bytes admitted")
		}
	}
}

// Claim: a differently spelled valid synthetic launch origin cannot replace
// the separately admitted origin; late cancellation after native success has
// zero fallback and no Matrix handoff, without relabeling the native effect.
func TestVaultContextOriginAndLateCancellation(t *testing.T) {
	syn := `{"identity":{"domain":"fixture-domain","kind":"synthetic","name":"syn1:09155b1290b5e9bc09a1a929ad8d9fffcb21002e553fdf849acda156d6b74bb7","origin":{"host_id":"host-fixture-01","project_id":"project-fixture-01","profile_id":"profile-fixture-01"}},"session_mode":"direct"}`
	f := newVaultFixture(t, syn)
	a := f.app(true)
	a.profile = "vault"
	f.provider.value.declared.Origin.HostID = "other-host"
	f.provider.value.declared.Name, _ = vaultSyntheticName(*f.provider.value.declared.Origin)
	if _, e := a.session(); vaultErrorCode(e) != "NOT_SUBMITTED E_IDENTITY_CONFLICT" || f.vault.factory != 0 || f.vault.effects != 0 || f.legacy != 0 || f.keychain != 0 {
		t.Fatal("admitted origin mismatch reached seam")
	}
	f = newVaultFixture(t, vaultSelectionJSON)
	a = f.app(true)
	a.profile = "vault"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.vault.afterReply = func(r vaultRequest) {
		if r.op == vaultOpRelease {
			cancel()
		}
	}
	before := f.snapshot(t)
	if _, e := a.loadCredentials(ctx, f.paths("vault", false), "alice"); e == nil || !strings.Contains(e.Error(), "SUCCEEDED handoff_cancelled") || f.vault.effects != 2 || f.legacy != 0 || f.keychain != 0 || f.httpCalls.Load() != 0 || f.snapshot(t) != before {
		t.Fatal("late cancellation changed outcome/backend/state")
	}
}
