//go:build unix

package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

// Claim: a final guard panic/error suppresses an unentered consumer after an
// authenticated release, preserving success, revision and cleanup. Cancellation
// and unchanged success are neighbors. These are producer-authored equivalents
// of the reported reviewer witnesses, not copies of unavailable reviewer bytes.
func TestVaultGuardPanicDoesNotInventHandoff(t *testing.T) {
	for _, mode := range []string{"guard_panic", "guard_error", "cancelled", "unchanged"} {
		t.Run(mode, func(t *testing.T) {
			f := vaultNewFake(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancelled" {
				f.afterReply = func(vaultRequest) { cancel() }
			}
			guard := vaultSelectionGuardFunc(func(context.Context, vaultCredentialSelection) *vaultFailure {
				// Discard runs after reply admission and before the final guard.
				if f.discards == 1 {
					switch mode {
					case "guard_panic":
						panic(string(f.token))
					case "guard_error":
						return vaultLocalFailure(vaultEIdentityConflict)
					}
				}
				return nil
			})
			c, failure := vaultNewClient(vaultFixtureAdmitted(t, vaultFixtureObserved(t, vaultSessionDirect)), f.dep())
			if failure != nil {
				t.Fatal(failure)
			}
			entries := 0
			var borrowed []byte
			r := c.Release(ctx, guard, func(b []byte) error { entries++; borrowed = b; return nil })
			if r.Release == nil || r.Release.Outcome != vaultSucceeded || r.Release.Invocation != vaultInvoked || r.Revision != 1 || r.Failure != nil || r.Cleanup != vaultCleanupClosed || f.effects != 1 || f.invocations != 1 || f.discards != 1 || f.closes != 1 {
				t.Fatalf("known release or cleanup changed: %+v", r)
			}
			wantHandoff, wantDiagnosis, wantEntries := vaultHandoffNotEntered, vaultDeliverySelection, 0
			if mode == "cancelled" {
				wantDiagnosis = vaultDeliveryCancelled
			} else if mode == "unchanged" {
				wantHandoff, wantDiagnosis, wantEntries = vaultHandoffReturned, "", 1
			}
			if r.Handoff != wantHandoff || r.DeliveryDiagnosis != wantDiagnosis || entries != wantEntries {
				t.Fatalf("INVENTED_HANDOFF: entries=%d handoff=%s diagnosis=%s", entries, r.Handoff, r.DeliveryDiagnosis)
			}
			if r.acquisitionOK() != (mode == "unchanged") {
				t.Fatal("guard failure silently admitted acquisition")
			}
			if mode != "unchanged" {
				if e := r.diagnostic(); e == nil || e.Error() != "vault-v1 SUCCEEDED "+string(wantDiagnosis) {
					t.Fatal("wrong guard/cancellation diagnosis")
				}
			}
			for _, b := range append(f.buffers, borrowed) {
				if bytes.Count(b, []byte{0}) != len(b) {
					t.Fatal("observable owned buffer not wiped")
				}
			}
		})
	}
}

// Claim: only a real callback panic records consumer_panicked, with one actual
// entry and known native success retained in direct and registered modes.
// Observable reply buffers and the borrowed consumer buffer are wiped.
func TestVaultCallbackPanicIsConsumerPanic(t *testing.T) {
	for _, mode := range []string{vaultSessionDirect, vaultSessionRegistered} {
		t.Run(mode, func(t *testing.T) {
			f := vaultNewFake(t)
			entries := 0
			var borrowed []byte
			r := vaultTestRun(t, f, mode, func(b []byte) error {
				entries++
				borrowed = b
				panic(string(f.token))
			})
			wantEffects := 1
			if mode == vaultSessionRegistered {
				wantEffects = 2
			}
			if r.Release == nil || r.Release.Outcome != vaultSucceeded || r.Revision != 1 || r.Failure != nil || r.Handoff != vaultHandoffPanicked || r.DeliveryDiagnosis != vaultDeliveryPanicked || entries != 1 || f.effects != wantEffects || f.closes != 1 || r.Cleanup != vaultCleanupClosed || r.acquisitionOK() {
				t.Fatalf("real callback panic misattributed: %+v entries=%d", r, entries)
			}
			if e := r.diagnostic(); e == nil || e.Error() != "vault-v1 SUCCEEDED consumer_panicked" {
				t.Fatal("callback panic diagnosis changed")
			}
			for _, b := range append(f.buffers, borrowed) {
				if bytes.Count(b, []byte{0}) != len(b) {
					t.Fatal("callback panic left observable owned bytes")
				}
			}
		})
	}
}

// Claim: the actual App.Run credential path reports a final context guard
// panic/error separately, with zero Matrix calls or token-redaction acquisition.
// The unchanged neighbor authenticates once. Only external logical dependencies
// are doubles; normal metadata/admission/client/consumer orchestration runs.
func TestVaultCLIGuardPanicDoesNotBlameConsumer(t *testing.T) {
	for _, mode := range []string{"guard_panic", "guard_error", "unchanged"} {
		t.Run(mode, func(t *testing.T) {
			f := newVaultFixture(t, vaultSelectionJSON)
			a := f.app(true)
			finalChecks := 0
			f.provider.beforeReturn = func(int) {
				if f.vault.discards == 2 {
					finalChecks++
					switch mode {
					case "guard_panic":
						panic(string(f.vault.token))
					case "guard_error":
						f.provider.err = errors.New(string(f.vault.token))
					}
				}
			}
			before := f.snapshot(t)
			code := a.Run(context.Background(), []string{"--profile", "vault", "whoami"})
			if f.vault.effects != 2 || f.vault.invocations != 2 || f.vault.discards != 2 || f.vault.closes != 1 || finalChecks != 1 {
				t.Fatal("CLI known native operations/cleanup changed")
			}
			token := string(f.vault.token)
			if mode == "unchanged" {
				if code != 0 || f.httpCalls.Load() != 1 || a.secrets.Scrub(token) == token {
					t.Fatal("unchanged CLI acquisition refused")
				}
			} else {
				if code == 0 || !strings.Contains(f.err.String(), "vault-v1 SUCCEEDED selection_unavailable_after_success") || strings.Contains(f.err.String(), "consumer_panicked") {
					t.Fatalf("CLI_FALSE_CONSUMER_DIAGNOSIS: code=%d %s", code, f.err.String())
				}
				if f.httpCalls.Load() != 0 || a.secrets.Scrub(token) != token {
					t.Fatal("guard failure entered Matrix or token consumer")
				}
			}
			if f.legacy != 0 || f.keychain != 0 || f.effects() != int(f.httpCalls.Load()) || f.snapshot(t) != before || strings.Contains(f.out.String()+f.err.String(), token) {
				t.Fatal("CLI guard path changed store/state or leaked payload")
			}
			for _, b := range f.vault.buffers {
				if bytes.Count(b, []byte{0}) != len(b) {
					t.Fatal("CLI reply buffer not wiped")
				}
			}
		})
	}
}
