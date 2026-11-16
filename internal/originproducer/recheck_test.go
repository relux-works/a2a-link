package originproducer

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/a2a-swarm/internal/cg1"
	"github.com/relux-works/a2a-swarm/internal/config"
	"github.com/relux-works/a2a-swarm/runorigin"
)

// Claim: a tip-only change is retryable without a Result, while an unchanged tip validates and a spent grant still refuses.
func TestValidateTipOnlyChange(t *testing.T) {
	f := newFixture(t)
	control, _ := f.session()
	prepared, err := control.Prepare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if again, err := control.Validate(context.Background()); err != nil || again != prepared {
		t.Fatal("unchanged control did not validate", err)
	}
	s, checker := f.session()
	if _, err = s.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	checker.set(func(c *fakeChecker) { c.facts.TipHash = strings.Repeat("d", 64) })
	result, err := s.Validate(context.Background())
	refused(t, result, err, ReasonTipMoved, runorigin.ErrUnavailable)
	checker.set(func(c *fakeChecker) { c.code = cg1.OriginSealSpent })
	result, err = s.Validate(context.Background())
	refused(t, result, err, ReasonSealSpent, runorigin.ErrRefused)
}

// Claim: a public connection must bind both the mapped Matrix user and named store before Open builds a checker; a matching entry opens.
func TestOpenBindsConnection(t *testing.T) {
	for _, mode := range []string{"another-account", "another-store", "unknown-connection", "registry-absent", "registry-unprotected"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			control, _ := f.session()
			control.Close()
			switch mode {
			case "another-account", "another-store":
				connection := config.Connection{ID: "other", URL: "http://127.0.0.1", ServerName: strings.SplitN(fixtureUser, ":", 2)[1], Store: config.CredentialStore{Backend: "file"}}
				if mode == "another-account" {
					connection.ServerName = "127.0.0.1"
				}
				registry := config.ConnectionRegistry{SchemaVersion: 1, Current: "other", Profiles: map[string]config.Connection{"other": connection}}
				raw, err := json.Marshal(registry)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(f.root, "connections.json"), raw, 0600); err != nil {
					t.Fatal(err)
				}
				f.mapping.Agents[0].Connection = "other"
				f.saveMapping()
			case "unknown-connection":
				f.mapping.Agents[0].Connection = "missing"
				f.saveMapping()
			case "registry-absent":
				if err := os.Remove(filepath.Join(f.root, "connections.json")); err != nil {
					t.Fatal(err)
				}
			case "registry-unprotected":
				if err := os.Chmod(filepath.Join(f.root, "connections.json"), 0666); err != nil {
					t.Fatal(err)
				}
			}
			s, err := f.producer.Open(context.Background(), f.selection)
			f.notOpened(s, err, ReasonMappingInvalid, 1)
			if len(f.scopeDirs()) != 0 {
				t.Fatal("connection refusal created a scope")
			}
		})
	}
}

// Claim: registry removal after Prepare refuses Validate without a Result; an unchanged registry validates.
func TestValidateRechecksConnection(t *testing.T) {
	f := newFixture(t)
	s, _ := f.session()
	prepared, err := s.Prepare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result, err := s.Validate(context.Background()); err != nil || result != prepared {
		t.Fatal("unchanged registry did not validate", err)
	}
	if err = os.Remove(filepath.Join(f.root, "connections.json")); err != nil {
		t.Fatal(err)
	}
	result, err := s.Validate(context.Background())
	refused(t, result, err, ReasonMappingInvalid, runorigin.ErrRefused)
}

// Claim: a non-event mailbox entry with valid message bytes refuses at the entry-kind gate before checker construction; an event entry opens.
func TestOpenRefusesNonEventEntry(t *testing.T) {
	f := newFixture(t)
	control, _ := f.session()
	control.Close()
	entries := f.mailbox().InOrder([]string{fixtureEvent})
	if len(entries) != 1 {
		t.Fatal("missing control entry")
	}
	entry := entries[0]
	entry.ID, entry.Kind = "$invite-entry", config.MailInvite
	if n, err := f.mailbox().Append([]config.MailEntry{entry}); err != nil || n != 1 {
		t.Fatal("non-event fixture not stored", err)
	}
	sel := f.selection
	sel.Event.EventID = entry.ID
	s, err := f.producer.Open(context.Background(), sel)
	f.notOpened(s, err, ReasonEventAbsent, 1)
}

// Claim: replacing retained content after Open or after Prepare refuses as changed_since_prepare without a Result or another checker call; unchanged content validates.
func TestRetainedContentReplacement(t *testing.T) {
	for _, phase := range []string{"before-prepare", "before-validate"} {
		t.Run(phase, func(t *testing.T) {
			f := newFixture(t)
			control, _ := f.session()
			prepared, err := control.Prepare(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if result, err := control.Validate(context.Background()); err != nil || result != prepared {
				t.Fatal("unchanged content did not validate", err)
			}
			s, checker := f.session()
			if phase == "before-validate" {
				if _, err = s.Prepare(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := checker.counts()
			f.replaceContent(map[string]any{"msgtype": "m.text", "body": "replacement"})
			var result runorigin.Result
			if phase == "before-prepare" {
				result, err = s.Prepare(context.Background())
			} else {
				result, err = s.Validate(context.Background())
			}
			refused(t, result, err, ReasonChanged, runorigin.ErrRefused)
			if checks, _ := checker.counts(); checks != before {
				t.Fatal("replaced content reached the checker")
			}
		})
	}
}

// Claim: cancellation during checker construction returns no session, reports unavailable/cancelled, closes the checker and removes its scope; uncancelled Open succeeds.
func TestOpenCancellationDuringConstruction(t *testing.T) {
	f := newFixture(t)
	control, _ := f.session()
	if err := control.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.producer.open = func(scope cg1.OriginScope) (originChecker, error) {
		checker, err := f.open(scope)
		cancel()
		return checker, err
	}
	s, err := f.producer.Open(ctx, f.selection)
	if s != nil {
		s.Close()
		t.Fatal("cancelled construction returned a session")
	}
	if ReasonOf(err) != ReasonCancelled || !errors.Is(err, runorigin.ErrUnavailable) {
		t.Fatal("wrong cancellation class or reason", err)
	}
	all := f.checkers()
	if len(all) != 2 {
		t.Fatal("construction did not run")
	}
	if _, closes := all[1].counts(); closes != 1 || len(f.scopeDirs()) != 0 {
		t.Fatal("cancelled construction did not release checker and scope")
	}
}

// obstructScope makes RemoveAll fail with ENOTDIR even for a privileged test user.
func obstructScope(t *testing.T, f *fixture) func() {
	t.Helper()
	moved := f.scopes + "-held"
	if err := os.Rename(f.scopes, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.scopes, []byte("obstruction"), 0600); err != nil {
		t.Fatal(err)
	}
	return func() {
		t.Helper()
		if err := os.Remove(f.scopes); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(moved, f.scopes); err != nil {
			t.Fatal(err)
		}
	}
}

// Claim: failed scope removal returns a stable refused/closed error without OS text, closes the checker once, and leaves the session closed; successful Close removes its scope.
func TestCloseReportsScopeRemovalFailure(t *testing.T) {
	f := newFixture(t)
	control, _ := f.session()
	if err := control.Close(); err != nil || len(f.scopeDirs()) != 0 {
		t.Fatal("control close failed", err)
	}
	s, checker := f.session()
	restore := obstructScope(t, f)
	defer restore()
	err := s.Close()
	if ReasonOf(err) != ReasonClosed || !errors.Is(err, runorigin.ErrRefused) || err.Error() != "origin producer: closed" {
		t.Fatal("scope removal failure was not scrubbed", err)
	}
	if again := s.Close(); again != err {
		t.Fatal("idempotent Close lost its failure")
	}
	if _, closes := checker.counts(); closes != 1 {
		t.Fatal("checker not closed exactly once")
	}
	result, err := s.Prepare(context.Background())
	refused(t, result, err, ReasonClosed, runorigin.ErrRefused)
}
