package originproducer

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/a2a-swarm/internal/cg1"
	"github.com/relux-works/a2a-swarm/internal/config"
	"github.com/relux-works/a2a-swarm/runorigin"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// All fixture values are public test data. No key here controls anything.
const (
	fixtureIdentity     = "alice"
	fixtureUser         = "@alice:fixture.invalid"
	fixtureSender       = "@bob:fixture.invalid"
	fixtureRoom         = "!pair:fixture.invalid"
	fixtureEvent        = "$retained-event"
	fixtureRegistration = "fixture-registration-0001"
)

var (
	fixtureLauncher = runorigin.Principal{UID: 7001, Generation: 3}
	fixtureInput    = runorigin.Principal{UID: 4242, Generation: 19}
	fixtureFacts    = cg1.OriginFacts{RequestID: strings.Repeat("a", 64), GrantID: strings.Repeat("b", 64), TipHash: strings.Repeat("c", 64)}
)

// fakeChecker stands in for the owned cg1 checker. The real signature, grant
// and tip gates are tested in internal/cg1; this fake lets the producer tests
// control the outcome those gates report.
type fakeChecker struct {
	mu        sync.Mutex
	scope     cg1.OriginScope
	facts     cg1.OriginFacts
	code      cg1.OriginCode
	terms     map[string][]byte
	termsCode cg1.OriginCode
	checks    int
	closes    int
	events    []cg1.OriginEvent
	entered   chan struct{}
}

func (c *fakeChecker) Check(ctx context.Context, ev cg1.OriginEvent) (cg1.OriginFacts, cg1.OriginCode) {
	c.mu.Lock()
	c.checks++
	c.events = append(c.events, ev)
	facts, code, entered := c.facts, c.code, c.entered
	c.entered = nil
	c.mu.Unlock()
	if entered != nil {
		close(entered)
		<-ctx.Done()
		// A checker that still claims Live after cancellation must be ignored.
		return facts, cg1.OriginLive
	}
	// Facts are returned even beside a refusal; the session must drop them.
	return facts, code
}
func (c *fakeChecker) Terms() (map[string][]byte, cg1.OriginCode) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.terms, c.termsCode
}
func (c *fakeChecker) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closes++
	return nil
}
func (c *fakeChecker) set(change func(*fakeChecker)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	change(c)
}
func (c *fakeChecker) counts() (checks, closes int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.checks, c.closes
}

type fixture struct {
	t                     *testing.T
	root, mappingPath     string
	store, policy, scopes string
	mapping               mappingFile
	producer              *Producer
	mu                    sync.Mutex
	opened                []*fakeChecker
	failOpen              bool
	selection             runorigin.Selection
}

func privateDir(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func xonlyKey(n byte) string {
	b := make([]byte, 32)
	b[31] = n
	_, p := btcec.PrivKeyFromBytes(b)
	return hex.EncodeToString(schnorr.SerializePubKey(p))
}

func payTerms(t *testing.T) []byte {
	t.Helper()
	raw, err := rental.EncodePayTermsV2(rental.PayTermsV2{Version: 2, Service: "wallet.nmc", ExecutorKey: xonlyKey(9), Network: "regtest", Genesis: su.RegtestGenesis, RecipientMode: "any", Recipients: []string{}, SpendCap: 1000000, TransferCap: 100000, DayCap: 1000000, DayCountCap: 10, FeeCap: 1000, DayBasis: "utc-calendar"})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	privateDir(t, root)
	f := &fixture{t: t, root: root}
	f.mappingPath = filepath.Join(privateDir(t, filepath.Join(root, "protected")), "origin-mapping.json")
	f.store = privateDir(t, filepath.Join(root, "store"))
	f.policy = privateDir(t, filepath.Join(root, "policy"))
	f.scopes = privateDir(t, filepath.Join(root, "scopes"))
	f.mapping = mappingFile{Version: 1, Launcher: fixtureLauncher, Agents: []agentEntry{{Input: fixtureInput, Identity: fixtureIdentity, Connection: "fixture", MatrixUserID: fixtureUser, Policy: cg1.MatrixPolicy, TermsProfile: "pay", Registration: fixtureRegistration, StoreBase: f.store, PolicyDir: f.policy, ScopeRoot: f.scopes}}}
	f.saveMapping()
	f.producer = &Producer{mappingPath: f.mappingPath, owner: uint32(os.Getuid()), store: mailboxStore{}, open: f.open}
	f.selection = runorigin.Selection{Launcher: fixtureLauncher, Event: runorigin.EventRef{RoomID: fixtureRoom, EventID: fixtureEvent}, Input: fixtureInput}
	f.retain(fixtureEvent, fixtureRoom, "m.room.message")
	return f
}

func (f *fixture) writeMapping(raw []byte) {
	f.t.Helper()
	if err := os.WriteFile(f.mappingPath, raw, 0600); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Chmod(f.mappingPath, 0600); err != nil {
		f.t.Fatal(err)
	}
}
func (f *fixture) saveMapping() {
	f.t.Helper()
	raw, err := json.Marshal(f.mapping)
	if err != nil {
		f.t.Fatal(err)
	}
	f.writeMapping(raw)
}

// mappingObject returns the saved mapping as a generic tree for shape plants.
func (f *fixture) mappingObject() map[string]any {
	f.t.Helper()
	raw, err := json.Marshal(f.mapping)
	if err != nil {
		f.t.Fatal(err)
	}
	var tree map[string]any
	if err = json.Unmarshal(raw, &tree); err != nil {
		f.t.Fatal(err)
	}
	return tree
}
func (f *fixture) writeTree(tree map[string]any) {
	f.t.Helper()
	raw, err := json.Marshal(tree)
	if err != nil {
		f.t.Fatal(err)
	}
	f.writeMapping(raw)
}

func (f *fixture) mailbox() *config.Mailbox {
	f.t.Helper()
	mailbox, err := config.OpenMailbox(config.Paths{Base: f.store}, fixtureIdentity)
	if err != nil {
		f.t.Fatal(err)
	}
	return mailbox
}

// retain stores an event the way admission does: in the agent's own mailbox.
func (f *fixture) retain(id, room, kind string) {
	f.t.Helper()
	event, err := json.Marshal(map[string]any{"type": kind, "sender": fixtureSender, "content": map[string]any{"msgtype": "m.text", "body": "hello"}})
	if err != nil {
		f.t.Fatal(err)
	}
	n, err := f.mailbox().Append([]config.MailEntry{{ID: id, Kind: config.MailEvent, Room: room, Sender: fixtureSender, TS: 1, Event: event}})
	if err != nil || n != 1 {
		f.t.Fatal("fixture event was not retained", err)
	}
}
func (f *fixture) receive(id string) {
	f.t.Helper()
	n, err := f.mailbox().Receive([]string{id})
	if err != nil || n != 1 {
		f.t.Fatal("fixture event was not received", err)
	}
}

func (f *fixture) open(scope cg1.OriginScope) (originChecker, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failOpen {
		return nil, errors.New("fixture open failure")
	}
	raw := payTerms(f.t)
	c := &fakeChecker{scope: scope, facts: fixtureFacts, code: cg1.OriginLive, terms: map[string][]byte{rental.Hash(raw): raw}, termsCode: cg1.OriginLive}
	f.opened = append(f.opened, c)
	return c, nil
}
func (f *fixture) checkers() []*fakeChecker {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*fakeChecker(nil), f.opened...)
}
func (f *fixture) scopeDirs() []string {
	f.t.Helper()
	entries, err := os.ReadDir(f.scopes)
	if err != nil {
		f.t.Fatal(err)
	}
	var out []string
	for _, entry := range entries {
		out = append(out, filepath.Join(f.scopes, entry.Name()))
	}
	return out
}

// session opens the valid control and returns it with its checker.
func (f *fixture) session() (runorigin.Session, *fakeChecker) {
	f.t.Helper()
	before := len(f.checkers())
	s, err := f.producer.Open(context.Background(), f.selection)
	if err != nil || s == nil {
		f.t.Fatal("valid control did not open", err)
	}
	f.t.Cleanup(func() { s.Close() })
	all := f.checkers()
	if len(all) != before+1 {
		f.t.Fatal("valid control did not build exactly one checker")
	}
	return s, all[before]
}

func wantResult() runorigin.Result {
	return runorigin.Result{IdentityRegistrationNumber: fixtureRegistration, Origin: runorigin.Origin{Kind: "admission", EventID: fixtureFacts.RequestID, GrantID: fixtureFacts.GrantID, TipHash: fixtureFacts.TipHash, Mode: "enforcing"}}
}

// refused asserts a typed refusal of the wanted class with no Result.
func refused(t *testing.T, result runorigin.Result, err error, reason Reason, class error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected refusal %s, got a result", reason)
	}
	if result != (runorigin.Result{}) {
		t.Fatalf("refusal %s carried a result", reason)
	}
	if ReasonOf(err) != reason || !errors.Is(err, class) {
		t.Fatalf("refusal=%v want reason=%s class=%v", err, reason, class)
	}
}

// notOpened asserts a typed Open refusal that built no session, checker or scope.
func (f *fixture) notOpened(s runorigin.Session, err error, reason Reason, checkers int) {
	f.t.Helper()
	if err == nil || s != nil {
		if s != nil {
			s.Close()
		}
		f.t.Fatalf("expected open refusal %s, got a session", reason)
	}
	if ReasonOf(err) != reason || !errors.Is(err, runorigin.ErrRefused) {
		f.t.Fatalf("open refusal=%v want reason=%s", err, reason)
	}
	if len(f.checkers()) != checkers {
		f.t.Fatal("a refused open built a checker")
	}
}
