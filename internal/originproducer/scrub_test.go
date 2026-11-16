package originproducer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/relux-works/a2a-swarm/internal/cg1"
	"github.com/relux-works/a2a-swarm/runorigin"
)

var refusalText = regexp.MustCompile(`^origin producer: [a-z_]+$`)

// Claim: no refusal, in any formatting, contains the registration value, an
// identity, a Matrix ID, an event reference, a principal number or a host
// path. Every error is a Refusal whose text is a fixed prefix and a reason
// name. The valid control beside the negatives returns the registration only
// inside its Result.
func TestErrorsCarryNoProtectedValue(t *testing.T) {
	f := newFixture(t)
	control, _ := f.session()
	result, err := control.Prepare(context.Background())
	if err != nil || result.IdentityRegistrationNumber != fixtureRegistration {
		t.Fatal("valid control did not return the registration in its result", err)
	}
	var collected []error
	add := func(err error) {
		t.Helper()
		if err == nil {
			t.Fatal("scenario did not refuse")
		}
		collected = append(collected, err)
	}
	// Session refusals for every checker outcome.
	for _, code := range []cg1.OriginCode{cg1.OriginPolicyInvalid, cg1.OriginInnerInvalid, cg1.OriginRecipientMismatch, cg1.OriginGrantAbsent, cg1.OriginGrantExpired, cg1.OriginSealSpent, cg1.OriginLandlordChanged, cg1.OriginGrantRefused, cg1.OriginTermsInvalid, cg1.OriginBindingMismatch, cg1.OriginTipStale, cg1.OriginTipMoved, cg1.OriginUnavailable, cg1.OriginClosed, cg1.OriginCode(fixtureRegistration)} {
		s, checker := f.session()
		checker.set(func(c *fakeChecker) { c.code = code })
		_, err = s.Prepare(context.Background())
		add(err)
		_, err = s.Validate(context.Background())
		add(err)
	}
	// Validate refusals.
	s, checker := f.session()
	if _, err = s.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	checker.set(func(c *fakeChecker) { c.facts.TipHash = strings.Repeat("d", 64) })
	_, err = s.Validate(context.Background())
	add(err)
	s.Close()
	_, err = s.Validate(context.Background())
	add(err)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = f.producer.Open(cancelled, f.selection)
	add(err)
	// Cleanup failures use the same scrubbed closed vocabulary.
	cleanup, _ := f.session()
	restore := obstructScope(t, f)
	add(cleanup.Close())
	restore()
	// Open refusals.
	open := func(change func(sel *runorigin.Selection)) {
		sel := f.selection
		change(&sel)
		session, err := f.producer.Open(context.Background(), sel)
		if session != nil {
			session.Close()
		}
		add(err)
	}
	open(func(sel *runorigin.Selection) { sel.Input.UID++ })
	open(func(sel *runorigin.Selection) { sel.Launcher.Generation++ })
	open(func(sel *runorigin.Selection) { sel.Event.EventID = "$unknown-event" })
	open(func(sel *runorigin.Selection) { sel.Event.RoomID = "!elsewhere:fixture.invalid" })
	registry := filepath.Join(f.root, "connections.json")
	if err = os.Chmod(registry, 0666); err != nil {
		t.Fatal(err)
	}
	open(func(*runorigin.Selection) {})
	if err = os.Chmod(registry, 0600); err != nil {
		t.Fatal(err)
	}
	f.failOpen = true
	open(func(*runorigin.Selection) {})
	f.failOpen = false
	f.mapping.Agents[0].TermsProfile = "unknown"
	f.saveMapping()
	open(func(*runorigin.Selection) {})
	f.writeMapping([]byte(`{"keymaker_registration":"` + fixtureRegistration + `"}`))
	open(func(*runorigin.Selection) {})
	_, err = newProducer(f.mappingPath, uint32(os.Getuid()))
	add(err)
	if err = os.Remove(f.mappingPath); err != nil {
		t.Fatal(err)
	}
	open(func(*runorigin.Selection) {})

	protected := []string{fixtureRegistration, fixtureIdentity, fixtureUser, fixtureSender, fixtureRoom, fixtureEvent, "fixture.invalid",
		f.root, f.mappingPath, f.store, f.policy, f.scopes, filepath.Base(f.mappingPath),
		strconv.Itoa(int(fixtureLauncher.UID)), strconv.Itoa(int(fixtureInput.UID))}
	reasons := map[Reason]bool{}
	for _, err := range collected {
		refusal, ok := err.(*Refusal)
		if !ok {
			t.Fatalf("error is not a typed refusal: %T", err)
		}
		reasons[refusal.Reason] = true
		if !refusalText.MatchString(err.Error()) {
			t.Fatal("refusal text is not a fixed prefix and a reason name")
		}
		for _, text := range []string{err.Error(), fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err), fmt.Sprintf("%q", err), fmt.Sprintf("%v", err.(interface{ Unwrap() error }).Unwrap())} {
			for _, value := range protected {
				if strings.Contains(text, value) {
					t.Fatalf("a refusal of reason %s contains a protected value", refusal.Reason)
				}
			}
		}
	}
	if len(reasons) < 15 {
		t.Fatalf("scrubbing covered only %d reasons", len(reasons))
	}
}

// Claim: the package has no logging or printing route at all: its non-test
// sources import no log, fmt or slog package and never name a standard stream.
func TestPackageHasNoLogRoute(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatal("package sources not found", err)
	}
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for _, banned := range []string{`"log"`, `"log/slog"`, `"fmt"`, "os.Stderr", "os.Stdout", "println(", "print("} {
			if strings.Contains(string(raw), banned) {
				t.Fatalf("%s has an output route: %s", name, banned)
			}
		}
	}
	if checked < 5 {
		t.Fatalf("only %d source files were checked", checked)
	}
}
