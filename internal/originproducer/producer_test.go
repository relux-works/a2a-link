package originproducer

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/a2a-swarm/internal/cg1"
	"github.com/relux-works/a2a-swarm/runorigin"
)

// Claim: a mapped launcher and input principal, a retained event and a Live
// checker outcome produce the protected registration and the six-member origin
// whose event_id is the verified inner request ID, never the Matrix event ID.
// Validate checks again and returns the identical Result. Close releases the
// checker and removes the scope.
func TestPrepareAndValidateLive(t *testing.T) {
	f := newFixture(t)
	s, checker := f.session()
	result, err := s.Prepare(context.Background())
	if err != nil || result != wantResult() {
		t.Fatalf("prepare result=%+v err=%v", result.Origin, err)
	}
	if !result.Origin.Valid() || strings.HasPrefix(result.Origin.EventID, "$") || result.Origin.EventID == fixtureEvent {
		t.Fatal("origin event_id is not the verified inner request ID")
	}
	checker.mu.Lock()
	ev := checker.events[0]
	scope := checker.scope
	checker.mu.Unlock()
	if ev.RoomID != fixtureRoom || ev.EventID != fixtureEvent || ev.Sender != fixtureSender || !strings.Contains(string(ev.Content), `"hello"`) {
		t.Fatal("checker did not receive the event read from the agent's own store")
	}
	if scope.Identity != fixtureIdentity || scope.UserID != fixtureUser || scope.PolicyDir != f.policy || !strings.HasPrefix(scope.ScopeDir, f.scopes+string(os.PathSeparator)) {
		t.Fatal("checker scope does not come from the protected mapping")
	}
	again, err := s.Validate(context.Background())
	if err != nil || again != result {
		t.Fatalf("validate err=%v", err)
	}
	if checks, _ := checker.counts(); checks != 2 {
		t.Fatalf("validate did not check again: checks=%d", checks)
	}
	if _, err = s.Prepare(context.Background()); ReasonOf(err) != ReasonSessionState {
		t.Fatal("a session prepared twice")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, closes := checker.counts(); closes != 1 {
		t.Fatalf("checker closes=%d", closes)
	}
	if left := f.scopeDirs(); len(left) != 0 {
		t.Fatal("close left the state scope behind")
	}
}

// Claim: with no mapping file, no entry for the input principal or a missing
// fact, Open refuses with a typed reason and builds no checker and no scope.
// The launcher-supplied principal is never used as an identity. The same
// selection opens as the valid control before each negative.
func TestOpenRefusesMissingMapping(t *testing.T) {
	cases := []struct {
		name   string
		change func(f *fixture, sel *runorigin.Selection)
		want   Reason
	}{
		{"mapping-file-absent", func(f *fixture, _ *runorigin.Selection) {
			if err := os.Remove(f.mappingPath); err != nil {
				f.t.Fatal(err)
			}
		}, ReasonMappingInvalid},
		{"unmapped-input-principal", func(_ *fixture, sel *runorigin.Selection) { sel.Input.UID = fixtureInput.UID + 1 }, ReasonMappingMissing},
		{"another-input-generation", func(_ *fixture, sel *runorigin.Selection) { sel.Input.Generation = fixtureInput.Generation + 1 }, ReasonMappingMissing},
		{"missing-registration-fact", func(f *fixture, _ *runorigin.Selection) {
			tree := f.mappingObject()
			delete(tree["agents"].([]any)[0].(map[string]any), "keymaker_registration")
			f.writeTree(tree)
		}, ReasonMappingInvalid},
		{"empty-registration-fact", func(f *fixture, _ *runorigin.Selection) {
			f.mapping.Agents[0].Registration = ""
			f.saveMapping()
		}, ReasonMappingInvalid},
		{"missing-matrix-user-fact", func(f *fixture, _ *runorigin.Selection) {
			f.mapping.Agents[0].MatrixUserID = ""
			f.saveMapping()
		}, ReasonMappingInvalid},
		{"missing-policy-fact", func(f *fixture, _ *runorigin.Selection) {
			f.mapping.Agents[0].Policy = "none"
			f.saveMapping()
		}, ReasonMappingInvalid},
		{"missing-connection-fact", func(f *fixture, _ *runorigin.Selection) {
			f.mapping.Agents[0].Connection = ""
			f.saveMapping()
		}, ReasonMappingInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			control, _ := f.session()
			control.Close()
			sel := f.selection
			tc.change(f, &sel)
			s, err := f.producer.Open(context.Background(), sel)
			f.notOpened(s, err, tc.want, 1)
			if left := f.scopeDirs(); len(left) != 0 {
				t.Fatal("a refused open created a state scope")
			}
		})
	}
}

// Claim: a mapping pinned to another launcher UID or generation refuses every
// selection, including one whose input principal is mapped.
func TestOpenRefusesMappingForAnotherLauncher(t *testing.T) {
	for _, name := range []string{"another-launcher-uid", "another-launcher-generation"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			control, _ := f.session()
			control.Close()
			sel := f.selection
			if name == "another-launcher-uid" {
				sel.Launcher.UID++
			} else {
				sel.Launcher.Generation++
			}
			s, err := f.producer.Open(context.Background(), sel)
			f.notOpened(s, err, ReasonMappingLauncher, 1)
		})
	}
}

// Claim: an event that was never retained, was retained in another room, has
// already been received or is not a message refuses as event_absent before any
// checker exists. The reference is the only launcher input; no bytes are.
func TestOpenRefusesAbsentRetainedEvent(t *testing.T) {
	cases := []struct {
		name   string
		change func(f *fixture, sel *runorigin.Selection)
	}{
		{"never-retained", func(_ *fixture, sel *runorigin.Selection) { sel.Event.EventID = "$unknown-event" }},
		{"another-room", func(_ *fixture, sel *runorigin.Selection) { sel.Event.RoomID = "!elsewhere:fixture.invalid" }},
		{"already-received", func(f *fixture, _ *runorigin.Selection) { f.receive(fixtureEvent) }},
		{"not-a-message", func(f *fixture, sel *runorigin.Selection) {
			f.retain("$state-event", fixtureRoom, "m.room.topic")
			sel.Event.EventID = "$state-event"
		}},
		{"malformed-reference", func(_ *fixture, sel *runorigin.Selection) { sel.Event.EventID = "retained-event" }},
		{"store-absent", func(f *fixture, _ *runorigin.Selection) {
			if err := os.RemoveAll(f.store); err != nil {
				f.t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			control, _ := f.session()
			control.Close()
			sel := f.selection
			tc.change(f, &sel)
			s, err := f.producer.Open(context.Background(), sel)
			f.notOpened(s, err, ReasonEventAbsent, 1)
		})
	}
}

// Claim: a scope root that is missing or not private, and a checker that cannot
// be built, refuse as scope_unavailable and leave no scope behind.
func TestOpenRefusesWithoutPrivateScope(t *testing.T) {
	for _, name := range []string{"scope-root-permissive", "scope-root-absent", "checker-construction-fails"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			control, _ := f.session()
			control.Close()
			switch name {
			case "scope-root-permissive":
				if err := os.Chmod(f.scopes, 0755); err != nil {
					t.Fatal(err)
				}
			case "scope-root-absent":
				if err := os.Remove(f.scopes); err != nil {
					t.Fatal(err)
				}
			case "checker-construction-fails":
				f.failOpen = true
			}
			s, err := f.producer.Open(context.Background(), f.selection)
			f.notOpened(s, err, ReasonScope, 1)
			if name != "scope-root-absent" {
				if left := f.scopeDirs(); len(left) != 0 {
					t.Fatal("a refused open left a state scope behind")
				}
			}
		})
	}
}

// Claim: every checker outcome other than Live maps to its typed refusal with
// no Result, even when the checker hands facts back beside the refusal. Stale
// and moved tips are the retryable class. A Live session beside each negative
// prepares.
func TestPrepareRefusalsCarryNoResult(t *testing.T) {
	cases := []struct {
		name  string
		code  cg1.OriginCode
		want  Reason
		class error
	}{
		{"inner-signature-invalid", cg1.OriginInnerInvalid, ReasonInnerInvalid, runorigin.ErrRefused},
		{"inner-request-for-another-agent", cg1.OriginRecipientMismatch, ReasonInnerRecipient, runorigin.ErrRefused},
		{"no-grant", cg1.OriginGrantAbsent, ReasonGrantAbsent, runorigin.ErrRefused},
		{"grant-expired", cg1.OriginGrantExpired, ReasonGrantExpired, runorigin.ErrRefused},
		{"seal-spent", cg1.OriginSealSpent, ReasonSealSpent, runorigin.ErrRefused},
		{"landlord-changed", cg1.OriginLandlordChanged, ReasonLandlordChanged, runorigin.ErrRefused},
		{"terms-invalid", cg1.OriginTermsInvalid, ReasonTermsInvalid, runorigin.ErrRefused},
		{"binding-mismatch", cg1.OriginBindingMismatch, ReasonBindingMismatch, runorigin.ErrRefused},
		{"grant-refused", cg1.OriginGrantRefused, ReasonGrantRefused, runorigin.ErrRefused},
		{"policy-invalid", cg1.OriginPolicyInvalid, ReasonPolicyInvalid, runorigin.ErrRefused},
		{"stale-tip", cg1.OriginTipStale, ReasonTipStale, runorigin.ErrUnavailable},
		{"tip-moved", cg1.OriginTipMoved, ReasonTipMoved, runorigin.ErrUnavailable},
		{"dependency-unavailable", cg1.OriginUnavailable, ReasonUnavailable, runorigin.ErrUnavailable},
		{"unknown-outcome", cg1.OriginCode("future"), ReasonGrantRefused, runorigin.ErrRefused},
		{"empty-outcome", cg1.OriginCode(""), ReasonGrantRefused, runorigin.ErrRefused},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			control, _ := f.session()
			if result, err := control.Prepare(context.Background()); err != nil || result != wantResult() {
				t.Fatal("valid control did not prepare", err)
			}
			s, checker := f.session()
			checker.set(func(c *fakeChecker) { c.code = tc.code })
			result, err := s.Prepare(context.Background())
			refused(t, result, err, tc.want, tc.class)
			result, err = s.Validate(context.Background())
			refused(t, result, err, ReasonSessionState, runorigin.ErrRefused)
		})
	}
}

// Claim: a Live outcome whose facts are not three lowercase 64-hex values, or
// whose event ID is a Matrix ID, produces no Result.
func TestPrepareRefusesMalformedFacts(t *testing.T) {
	for _, name := range []string{"matrix-event-id", "short-grant-id", "uppercase-tip", "empty-facts"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			control, _ := f.session()
			if _, err := control.Prepare(context.Background()); err != nil {
				t.Fatal("valid control did not prepare", err)
			}
			s, checker := f.session()
			checker.set(func(c *fakeChecker) {
				switch name {
				case "matrix-event-id":
					c.facts.RequestID = fixtureEvent
				case "short-grant-id":
					c.facts.GrantID = strings.Repeat("b", 63)
				case "uppercase-tip":
					c.facts.TipHash = strings.Repeat("C", 64)
				case "empty-facts":
					c.facts = cg1.OriginFacts{}
				}
			})
			result, err := s.Prepare(context.Background())
			refused(t, result, err, ReasonInnerInvalid, runorigin.ErrRefused)
		})
	}
}

// Claim: Validate is a fresh admission, not the prepared verdict. A grant that
// stops being Live between Prepare and Validate refuses with its typed reason
// and no Result, after a second check. An unchanged session validates.
func TestValidateRefusesChangedGrantState(t *testing.T) {
	cases := []struct {
		name  string
		code  cg1.OriginCode
		want  Reason
		class error
	}{
		{"seal-spent", cg1.OriginSealSpent, ReasonSealSpent, runorigin.ErrRefused},
		{"grant-expired", cg1.OriginGrantExpired, ReasonGrantExpired, runorigin.ErrRefused},
		{"landlord-changed", cg1.OriginLandlordChanged, ReasonLandlordChanged, runorigin.ErrRefused},
		{"no-grant", cg1.OriginGrantAbsent, ReasonGrantAbsent, runorigin.ErrRefused},
		{"stale-tip", cg1.OriginTipStale, ReasonTipStale, runorigin.ErrUnavailable},
		{"inner-request-no-longer-valid", cg1.OriginInnerInvalid, ReasonInnerInvalid, runorigin.ErrRefused},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			control, _ := f.session()
			prepared, err := control.Prepare(context.Background())
			if err != nil {
				t.Fatal("valid control did not prepare", err)
			}
			if again, err := control.Validate(context.Background()); err != nil || again != prepared {
				t.Fatal("unchanged control did not validate", err)
			}
			s, checker := f.session()
			if _, err = s.Prepare(context.Background()); err != nil {
				t.Fatal(err)
			}
			checker.set(func(c *fakeChecker) { c.code = tc.code })
			result, err := s.Validate(context.Background())
			refused(t, result, err, tc.want, tc.class)
			if checks, _ := checker.counts(); checks != 2 {
				t.Fatalf("validate did not check again: checks=%d", checks)
			}
		})
	}
}

// Claim: Validate returns only a Result exactly equal to the prepared one. A
// fresh Live outcome with a different non-tip member, a changed registration,
// a rotated launcher pin, a vanished retained event or terms that stopped
// being valid refuses; nothing is silently replaced.
func TestValidateRefusesDifferentOrigin(t *testing.T) {
	cases := []struct {
		name   string
		change func(f *fixture, c *fakeChecker)
		want   Reason
	}{
		{"different-tip-and-grant", func(_ *fixture, c *fakeChecker) {
			c.set(func(c *fakeChecker) {
				c.facts.TipHash = strings.Repeat("d", 64)
				c.facts.GrantID = strings.Repeat("e", 64)
			})
		}, ReasonChanged},
		{"different-grant", func(_ *fixture, c *fakeChecker) {
			c.set(func(c *fakeChecker) { c.facts.GrantID = strings.Repeat("e", 64) })
		}, ReasonChanged},
		{"different-inner-request", func(_ *fixture, c *fakeChecker) {
			c.set(func(c *fakeChecker) { c.facts.RequestID = strings.Repeat("f", 64) })
		}, ReasonChanged},
		{"registration-changed", func(f *fixture, _ *fakeChecker) {
			f.mapping.Agents[0].Registration = "fixture-registration-0002"
			f.saveMapping()
		}, ReasonChanged},
		{"matrix-user-changed", func(f *fixture, _ *fakeChecker) {
			f.mapping.Agents[0].MatrixUserID = "@other:fixture.invalid"
			f.saveMapping()
		}, ReasonChanged},
		{"launcher-generation-rotated", func(f *fixture, _ *fakeChecker) {
			f.mapping.Launcher.Generation++
			f.saveMapping()
		}, ReasonMappingLauncher},
		{"mapping-removed", func(f *fixture, _ *fakeChecker) {
			if err := os.Remove(f.mappingPath); err != nil {
				f.t.Fatal(err)
			}
		}, ReasonMappingInvalid},
		{"retained-event-gone", func(f *fixture, _ *fakeChecker) { f.receive(fixtureEvent) }, ReasonEventAbsent},
		{"terms-no-longer-valid", func(_ *fixture, c *fakeChecker) {
			c.set(func(c *fakeChecker) { c.terms = map[string][]byte{strings.Repeat("0", 64): []byte(`{"version":1}`)} })
		}, ReasonProfile},
		{"policy-changed", func(_ *fixture, c *fakeChecker) {
			c.set(func(c *fakeChecker) { c.termsCode = cg1.OriginPolicyInvalid })
		}, ReasonPolicyInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			control, _ := f.session()
			prepared, err := control.Prepare(context.Background())
			if err != nil {
				t.Fatal("valid control did not prepare", err)
			}
			if again, err := control.Validate(context.Background()); err != nil || again != prepared {
				t.Fatal("unchanged control did not validate", err)
			}
			s, checker := f.session()
			if _, err = s.Prepare(context.Background()); err != nil {
				t.Fatal(err)
			}
			tc.change(f, checker)
			result, err := s.Validate(context.Background())
			refused(t, result, err, tc.want, runorigin.ErrRefused)
		})
	}
}

// Claim: Close during a running Prepare returns promptly without waiting for
// it, cancels it, and the Prepare yields no Result even if the checker still
// answers Live. The checker is closed once and the scope is removed.
func TestCloseDuringPrepare(t *testing.T) {
	f := newFixture(t)
	control, _ := f.session()
	if _, err := control.Prepare(context.Background()); err != nil {
		t.Fatal("valid control did not prepare", err)
	}
	control.Close()
	s, checker := f.session()
	entered := make(chan struct{})
	checker.set(func(c *fakeChecker) { c.entered = entered })
	type outcome struct {
		result runorigin.Result
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := s.Prepare(context.Background())
		done <- outcome{result, err}
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("prepare never reached the checker")
	}
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("close waited for the running prepare")
	}
	select {
	case got := <-done:
		refused(t, got.result, got.err, ReasonClosed, runorigin.ErrRefused)
	case <-time.After(10 * time.Second):
		t.Fatal("prepare did not stop after close")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, closes := checker.counts(); closes != 1 {
		t.Fatalf("checker closes=%d", closes)
	}
	if left := f.scopeDirs(); len(left) != 0 {
		t.Fatal("close left the state scope behind")
	}
	result, err := s.Validate(context.Background())
	refused(t, result, err, ReasonSessionState, runorigin.ErrRefused)
}

// Claim: a cancelled context stops Open, Prepare and Validate with the
// retryable class and no Result; a closed session refuses; the control works.
func TestContextCancellationAndClosedSession(t *testing.T) {
	f := newFixture(t)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	s, err := f.producer.Open(cancelled, f.selection)
	if s != nil || ReasonOf(err) != ReasonCancelled || !errors.Is(err, runorigin.ErrUnavailable) || len(f.checkers()) != 0 || len(f.scopeDirs()) != 0 {
		t.Fatal("cancelled open built a session", err)
	}
	live, checker := f.session()
	result, err := live.Prepare(cancelled)
	refused(t, result, err, ReasonCancelled, runorigin.ErrUnavailable)
	if checks, _ := checker.counts(); checks != 0 {
		t.Fatal("cancelled prepare reached the checker")
	}
	if result, err = live.Prepare(context.Background()); err != nil || result != wantResult() {
		t.Fatal("valid control did not prepare", err)
	}
	result, err = live.Validate(cancelled)
	refused(t, result, err, ReasonCancelled, runorigin.ErrUnavailable)
	if result, err = live.Validate(context.Background()); err != nil || result != wantResult() {
		t.Fatal("valid control did not validate", err)
	}
	live.Close()
	result, err = live.Validate(context.Background())
	refused(t, result, err, ReasonClosed, runorigin.ErrRefused)
}

// Claim: two sessions opened at the same time for the same event never share a
// checker or a state scope, and closing one leaves the other usable.
func TestConcurrentSessionsOwnDistinctCheckers(t *testing.T) {
	f := newFixture(t)
	sessions := make([]runorigin.Session, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range sessions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sessions[i], errs[i] = f.producer.Open(context.Background(), f.selection)
		}()
	}
	wg.Wait()
	for i := range sessions {
		if errs[i] != nil || sessions[i] == nil {
			t.Fatal("valid control did not open", errs[i])
		}
		defer sessions[i].Close()
	}
	checkers := f.checkers()
	if len(checkers) != 2 || checkers[0] == checkers[1] {
		t.Fatalf("sessions share a checker: built=%d", len(checkers))
	}
	first, second := checkers[0].scope.ScopeDir, checkers[1].scope.ScopeDir
	if first == second || first == "" || second == "" {
		t.Fatal("sessions share a state scope")
	}
	for _, scope := range []string{first, second} {
		st, err := os.Lstat(scope)
		if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 || !strings.HasPrefix(scope, f.scopes+string(os.PathSeparator)) {
			t.Fatal("session has no private state scope of its own")
		}
	}
	results := make([]runorigin.Result, 2)
	for i := range sessions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = sessions[i].Prepare(context.Background())
		}()
	}
	wg.Wait()
	for i := range sessions {
		if errs[i] != nil || results[i] != wantResult() {
			t.Fatal("concurrent prepare failed", errs[i])
		}
		if checks, _ := checkers[i].counts(); checks != 1 {
			t.Fatal("a session used another session's checker")
		}
	}
	// Find which checker belongs to the first session by closing it.
	sessions[0].Close()
	closedFirst, open := checkers[0], checkers[1]
	if _, closes := closedFirst.counts(); closes != 1 {
		closedFirst, open = checkers[1], checkers[0]
	}
	if _, closes := closedFirst.counts(); closes != 1 {
		t.Fatal("close did not release the session's own checker")
	}
	if _, closes := open.counts(); closes != 0 {
		t.Fatal("closing one session closed another session's checker")
	}
	if _, err := os.Lstat(closedFirst.scope.ScopeDir); !os.IsNotExist(err) {
		t.Fatal("closed session kept its scope")
	}
	if _, err := os.Lstat(open.scope.ScopeDir); err != nil {
		t.Fatal("closing one session removed another session's scope")
	}
	if result, err := sessions[1].Validate(context.Background()); err != nil || result != wantResult() {
		t.Fatal("the other session stopped working", err)
	}
}
