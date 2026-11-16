package cli

import (
	"context"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/a2a-swarm/internal/config"
)

// Claim: the actual admitted CLI rejects a changed backend or operational
// binding before opening the alternate named leaf, before factory/store/Matrix
// effects. These Linux kernel observations cover isolated fixtures only;
// Keychain is the portable fake store, not an OS Keychain qualification.
// TestVaultV1CredentialFlow is the unchanged real CLI success neighbor.
func TestVaultSelectionGuardRetarget(t *testing.T) {
	for _, backend := range []string{"file", "keychain", config.BackendVaultV1} {
		t.Run(backend, func(t *testing.T) {
			f := newVaultFixture(t, vaultSelectionJSON)
			a := f.app(true)
			replacement := f.r.Profiles["vault"]
			replacement.ID = "retarget-" + backend
			replacement.Store = config.CredentialStore{Backend: backend}
			if backend == "keychain" {
				replacement.Store = f.r.Profiles["alpha"].Store
			}
			b, err := replacement.Binding("alice", false)
			if err != nil {
				t.Fatal(err)
			}
			creds := config.Credentials{UserID: b.UserID, DeviceID: "d", Homeserver: replacement.URL, ConnectionBinding: &b}
			switch backend {
			case "file":
				// A valid matching token, not a malformed/missing-file shortcut.
				creds.AccessToken = "isolated-alpha"
			case config.BackendVaultV1:
				var original config.Credentials
				if err := config.DecodeConnectionJSON([]byte(`{"vault_selection":`+vaultSelectionJSON+`}`), &original); err != nil {
					t.Fatal(err)
				}
				creds.VaultSelection = original.VaultSelection
			}
			if err := config.ValidateBoundCredentials(creds, b); err != nil {
				t.Fatal(err)
			}
			p, err := replacement.Paths(config.Paths{Base: f.root}, "alice", false)
			if err != nil {
				t.Fatal(err)
			}
			leaf := p.AgentFile("alice")
			raw, err := json.Marshal(creds)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(leaf), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(leaf, raw, 0600); err != nil {
				t.Fatal(err)
			}

			// Pin the entire persistent fixture, allowing only our registry edit.
			expected := availabilitySnapshot(t, f.root)
			next := f.r
			next.Profiles = maps.Clone(f.r.Profiles)
			next.Profiles["vault"] = replacement
			if err := next.Validate(); err != nil {
				t.Fatal(err)
			}
			registry, err := json.Marshal(next)
			if err != nil {
				t.Fatal(err)
			}
			expected["connections.json"] = "-rw-------:" + string(registry)
			f.store.mu.Lock()
			items := maps.Clone(f.store.items)
			f.store.mu.Unlock()

			// Initial metadata observation has already selected the old vault
			// when admission calls the provider. Do not relatch that authority.
			f.provider.beforeReturn = func(call int) {
				if call == 1 {
					f.r = next
					f.save()
				}
			}
			collect := availabilityIOGuard(t, filepath.Dir(leaf))
			code := a.Run(context.Background(), []string{"--profile", "vault", "whoami"})
			// Drain BEFORE post-run snapshots: the assertions must not observe
			// their own reads. IN_OPEN observes the actual named-file boundary.
			if events := collect(); len(events) != 0 {
				t.Fatalf("alternate named credential leaf was accessed: %v", events)
			}
			if code == 0 || !strings.Contains(f.err.String(), "NOT_SUBMITTED E_IDENTITY_CONFLICT") {
				t.Fatalf("retarget diagnosis: code=%d error=%s", code, f.err.String())
			}
			f.store.mu.Lock()
			storeCalls := len(f.store.reads) + len(f.store.creates)
			sameItems := maps.Equal(f.store.items, items)
			f.store.mu.Unlock()
			if f.provider.calls != 1 || f.vault.factory != 0 || len(f.vault.events) != 0 || f.keychain != 0 || f.legacy != 0 || storeCalls != 0 || f.httpCalls.Load() != 0 {
				t.Fatalf("retarget effects: provider=%d factory=%d events=%v keychain=%d legacy=%d store=%d http=%d", f.provider.calls, f.vault.factory, f.vault.events, f.keychain, f.legacy, storeCalls, f.httpCalls.Load())
			}
			if !sameItems || !maps.Equal(availabilitySnapshot(t, f.root), expected) {
				t.Fatal("retarget changed persistent state beyond deliberate registry edit")
			}
			if strings.Contains(f.out.String()+f.err.String(), "isolated-alpha") {
				t.Fatal("planted token printed")
			}
		})
	}
}

// Claim: the actual file-open observer detects a bounded synthetic named-leaf
// read and stays clear for its no-read neighbor. This controls the instrument,
// independently of callbacks or the vault's refusal diagnosis.
func TestVaultNamedLeafObserverControl(t *testing.T) {
	for _, read := range []bool{false, true} {
		label := "unopened"
		if read {
			label = "opened"
		}
		t.Run(label, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "alice.json")
			if err := os.WriteFile(path, []byte(`{"access_token":"isolated-observer-token"}`), 0600); err != nil {
				t.Fatal(err)
			}
			collect := availabilityIOGuard(t, dir)
			if read {
				if _, err := os.ReadFile(path); err != nil {
					t.Fatal(err)
				}
			}
			events := strings.Join(collect(), "\n")
			if read && !strings.Contains(events, "SECRET_FILE_GUARD:alice.json") {
				t.Fatal("named-leaf observer missed planted open")
			}
			if !read && events != "" {
				t.Fatalf("unopened neighbor: %s", events)
			}
		})
	}
}
