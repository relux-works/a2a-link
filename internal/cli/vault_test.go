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
	"github.com/relux-works/a2a-swarm/internal/vaultv1"
)

// cliVault is a TEST-ONLY logical double behind the private vaultDependency
// seam. It counts the factory (discovery) and every driver/verifier call and
// answers with the runner's synthetic token. It is not native verification.
type cliVault struct {
	factory   int
	events    []string
	token     []byte
	openErr   error
	verifyErr error
	release   func(req vaultv1.Request) (vaultv1.Value, error) // nil: honest
}

type cliVaultConn struct{ v *cliVault }

func (v *cliVault) Open(context.Context) (vaultv1.Conn, error) {
	v.events = append(v.events, "open")
	if v.openErr != nil {
		return nil, v.openErr
	}
	return cliVaultConn{v}, nil
}

func (v *cliVault) VerifyService(context.Context, vaultv1.Conn) (vaultv1.ServiceProof, error) {
	v.events = append(v.events, "verify")
	if v.verifyErr != nil {
		return vaultv1.ServiceProof{}, v.verifyErr
	}
	return vaultv1.ServiceProof{Role: vaultv1.RoleVaultServer, CodeID: "fixture.vault.server", LeafSHA256: strings.Repeat("cd", 32), PinsetVersion: 1}, nil
}

func field(v vaultv1.Value, key string) vaultv1.Value {
	for _, f := range v.Fields() {
		if f.Key == key {
			return f.Value
		}
	}
	return vaultv1.Value{}
}

func ok(req vaultv1.Request, result vaultv1.Value) vaultv1.Value {
	return vaultv1.Dict(vaultv1.F("v", vaultv1.Uint(2)), vaultv1.F("request_id", vaultv1.String(req.ID)), vaultv1.F("op", vaultv1.String(string(req.Op))), vaultv1.F("ok", vaultv1.Bool(true)), vaultv1.F("result", result))
}

func (c cliVaultConn) Submit(_ context.Context, req vaultv1.Request) (vaultv1.Value, error) {
	c.v.events = append(c.v.events, "submit:"+string(req.Op))
	if req.Op == vaultv1.OpRegister {
		return ok(req, vaultv1.Dict(vaultv1.F("identity", field(req.Body, "identity")),
			vaultv1.F("session", vaultv1.Dict(vaultv1.F("epoch", vaultv1.String(strings.Repeat("e", 32))), vaultv1.F("session_id", vaultv1.String(strings.Repeat("5", 32))), vaultv1.F("generation", vaultv1.Uint(1)))),
			vaultv1.F("lifetime_ms", vaultv1.Uint(900000)))), nil
	}
	if c.v.release != nil {
		return c.v.release(req)
	}
	return ok(req, vaultv1.Dict(vaultv1.F("identity", field(req.Body, "identity")), vaultv1.F("consumer_binding", field(req.Body, "expected_binding")),
		vaultv1.F("record_revision", vaultv1.Uint(1)), vaultv1.F("secret", vaultv1.Bytes(append([]byte(nil), c.v.token...))))), nil
}

func (c cliVaultConn) Close() error {
	c.v.events = append(c.v.events, "close")
	return nil
}

const vaultSelectionJSON = `{"identity":{"domain":"fixture-domain","kind":"explicit","name":"fixture-alpha","origin":null},"session_mode":"registered"}`

// vaultFixture extends the named keychain fixture with a vault-v1 profile
// whose selected account equals alpha's. alpha's valid Keychain item and a
// valid legacy file token stay planted as tempting alternate sources.
type vaultFixture struct {
	*namedFixture
	vault    *cliVault
	keychain int
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
	// Counting trap with an isolated fake backend: a correct vault path never
	// constructs it, and a mutant that does reaches no platform Keychain.
	a.keychain = func(p config.Paths) *keychainStore {
		f.keychain++
		var calls []opRecord
		return &keychainStore{paths: p, fixture: filepath.Join(f.root, "trap.keychain-db"), hostID: "isolated-host", timeout: time.Second, probeCommand: unlockedProbe, backend: routingBackend{&calls}}
	}
	if dep {
		a.vaultDependency = func() *vaultv1.Dependency {
			f.vault.factory++
			return &vaultv1.Dependency{Driver: f.vault, Verifier: f.vault}
		}
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
	if f.vault.factory != 0 || len(f.vault.events) != 0 || reads != 0 || f.keychain != 0 || f.httpCalls.Load() != 0 {
		t.Fatalf("%s: factory=%d events=%v store=%d keychain=%d http=%d", label, f.vault.factory, f.vault.events, reads, f.keychain, f.httpCalls.Load())
	}
}

func vaultCode(err error) string {
	var r *vaultv1.Refusal
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
		{"registered", "open,verify,submit:register,submit:release,close"},
		{"direct", "open,verify,submit:release,close"},
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
// valid vault-v1 selection refuses NOT_SUBMITTED E_UNAVAILABLE before any
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
	if a.Run(context.Background(), []string{"--profile", "vault", "whoami"}) == 0 || !strings.Contains(f.err.String(), "vault-v1 NOT_SUBMITTED E_UNAVAILABLE") {
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
	if s.creds.AccessToken != "" || s.creds.VaultSelection == nil {
		t.Fatal("metadata session carries a secret or lost its selection")
	}
	f.zero(t, "metadata-only valid")
	f.writeMetadata(t, strings.Replace(vaultSelectionJSON, `"registered"`, `"auto"`, 1), nil)
	b := f.app(true)
	b.profile = "vault"
	if _, err := b.sessionMetadata(); vaultCode(err) != "NOT_SUBMITTED E_FORMAT" {
		t.Fatalf("invalid metadata session: %v", err)
	}
	f.zero(t, "metadata-only invalid")
	// Credential-flow control: the same seam is used when a secret is needed.
	f.writeMetadata(t, vaultSelectionJSON, nil)
	c := f.app(true)
	c.profile = "vault"
	if _, err := c.session(); err != nil || f.vault.factory != 1 || !strings.Contains(strings.Join(f.vault.events, ","), "verify,submit:register,submit:release") {
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
		if err == nil || (vaultCode(err) != tc.want && !strings.Contains(err.Error(), tc.want)) {
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
	if _, err := a.session(); vaultCode(err) != "NOT_SUBMITTED E_BACKEND_CONFIG" {
		t.Fatalf("vault_selection on keychain profile: %v", err)
	}
	f.zero(t, "selection on legacy profile")

	f = newVaultFixture(t, vaultSelectionJSON)
	a = f.app(true)
	a.profile, a.human = "vault", true
	if _, err := a.namedMetadata(f.paths("vault", false), "alice"); vaultCode(err) != "NOT_SUBMITTED E_BACKEND_CONFIG" {
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
	if _, err := l.loadCredentials(context.Background(), lp, "alice"); vaultCode(err) != "NOT_SUBMITTED E_BACKEND_CONFIG" {
		t.Fatalf("legacy unnamed vault_selection: %v", err)
	}
	if _, err := l.credentialMetadata(lp, "alice"); vaultCode(err) != "NOT_SUBMITTED E_BACKEND_CONFIG" {
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
			v.release = func(req vaultv1.Request) (vaultv1.Value, error) {
				return vaultv1.Dict(vaultv1.F("v", vaultv1.Uint(2)), vaultv1.F("request_id", vaultv1.String(req.ID)), vaultv1.F("op", vaultv1.String("release")), vaultv1.F("ok", vaultv1.Bool(false)), vaultv1.F("error", vaultv1.Dict(vaultv1.F("code", vaultv1.String("E_REVOKED"))))), nil
			}
		}, context.Background(), "REFUSED E_REVOKED"},
		{"unknown after submit", func(v *cliVault) {
			v.release = func(vaultv1.Request) (vaultv1.Value, error) { return vaultv1.Value{}, errors.New("isolated-alpha") }
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
		} else if vaultCode(err) != tc.want || creds.AccessToken != "" {
			t.Fatalf("%s: got %v want %s", tc.label, err, tc.want)
		}
		if err != nil && strings.Contains(err.Error(), "isolated-alpha") {
			t.Fatalf("%s: raw dependency error leaked", tc.label)
		}
		if reads != 0 || f.keychain != 0 || f.httpCalls.Load() != 0 || a.profile != "vault" || f.snapshot(t) != before {
			t.Fatalf("%s: fallback or effect: reads=%d keychain=%d http=%d profile=%s", tc.label, reads, f.keychain, f.httpCalls.Load(), a.profile)
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
	if _, _, err := a.registerNamedAgentDestination(context.Background(), "alice", nil, nil); vaultCode(err) != "NOT_SUBMITTED E_OPERATION_DENIED" {
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
	if err := s.checkConnection(); vaultCode(err) != "NOT_SUBMITTED E_IDENTITY_CONFLICT" {
		t.Fatalf("changed selection: %v", err)
	}
}
