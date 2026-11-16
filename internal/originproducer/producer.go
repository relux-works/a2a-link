package originproducer

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/relux-works/a2a-swarm/internal/cg1"
	"github.com/relux-works/a2a-swarm/runorigin"
)

// originChecker is the owned cg1 checker of one session.
type originChecker interface {
	Check(context.Context, cg1.OriginEvent) (cg1.OriginFacts, cg1.OriginCode)
	Terms() (map[string][]byte, cg1.OriginCode)
	Close() error
}

type checkerFactory func(cg1.OriginScope) (originChecker, error)

// openOwnedChecker is the production factory: the existing cg1 construction.
func openOwnedChecker(s cg1.OriginScope) (originChecker, error) {
	c, err := cg1.OpenOriginChecker(s)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Producer implements runorigin.Producer. It holds no identity, no checker and
// no verdict between sessions: each Open resolves the protected mapping again.
type Producer struct {
	mappingPath string
	owner       uint32
	store       eventStore
	open        checkerFactory
}

// New returns a producer only for a complete protected mapping. The mapping
// owner, the event store and the checker construction are fixed here; no
// option can replace them.
func New(mappingPath string) (*Producer, error) {
	return newProducer(mappingPath, protectedOwner)
}

func newProducer(mappingPath string, owner uint32) (*Producer, error) {
	p := &Producer{mappingPath: mappingPath, owner: owner, store: mailboxStore{}, open: openOwnedChecker}
	if _, err := loadMapping(p.mappingPath, p.owner); err != nil {
		return nil, refuse(ReasonMappingInvalid)
	}
	return p, nil
}

// resolve reads the protected mapping and returns the entry of the input
// principal. The selection is only ever compared with protected values.
func (p *Producer) resolve(sel runorigin.Selection) (agentEntry, error) {
	m, err := loadMapping(p.mappingPath, p.owner)
	if err != nil {
		return agentEntry{}, refuse(ReasonMappingInvalid)
	}
	if m.Launcher != sel.Launcher {
		return agentEntry{}, refuse(ReasonMappingLauncher)
	}
	for _, agent := range m.Agents {
		if agent.Input == sel.Input {
			return agent, nil
		}
	}
	return agentEntry{}, refuse(ReasonMappingMissing) // mapping gate
}

// newScope creates one fresh private directory under the protected scope root.
// The root is never created, repaired or followed through a link.
func newScope(root string) (string, error) {
	if !protectedPath(root) {
		return "", errMapping
	}
	st, err := os.Lstat(root)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 || !ownedBy(st, uint32(os.Getuid())) {
		return "", errMapping
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return "", errMapping
	}
	dir := filepath.Join(root, "session-"+hex.EncodeToString(id[:]))
	if err = os.Mkdir(dir, 0700); err != nil {
		return "", errMapping
	}
	return dir, nil
}

// Open resolves every identity fact from the protected mapping, reads the
// retained event from the agent's own store and builds a checker that belongs
// to the returned session alone.
func (p *Producer) Open(ctx context.Context, sel runorigin.Selection) (runorigin.Session, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, unavailable(ReasonCancelled)
	}
	entry, err := p.resolve(sel)
	if err != nil {
		return nil, err
	}
	profile, ok := profileByName(entry.TermsProfile)
	if !ok {
		return nil, refuse(ReasonProfile)
	}
	if !entry.connectionBound(p.owner) {
		return nil, refuse(ReasonMappingInvalid)
	}
	event, err := p.store.retained(ctx, entry.StoreBase, entry.Identity, sel.Event)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, unavailable(ReasonCancelled)
	}
	scope, err := newScope(entry.ScopeRoot)
	if err != nil {
		return nil, refuse(ReasonScope)
	}
	owned := cg1.OriginScope{Identity: entry.Identity, UserID: entry.MatrixUserID, PolicyDir: entry.PolicyDir, ScopeDir: scope}
	checker, err := p.open(owned) // owned checker gate
	if ctx.Err() != nil {
		if checker != nil {
			_ = checker.Close()
		}
		_ = os.RemoveAll(scope)
		return nil, unavailable(ReasonCancelled)
	}
	if err != nil || checker == nil {
		if checker != nil {
			_ = checker.Close()
		}
		_ = os.RemoveAll(scope)
		return nil, refuse(ReasonScope)
	}
	life, cancel := context.WithCancel(context.Background())
	return &session{producer: p, selection: sel, entry: entry, profile: profile, event: event, digest: sha256.Sum256(event.Content), checker: checker, scope: scope, life: life, cancel: cancel}, nil
}

// session is one preparation. It owns its checker and its state scope.
type session struct {
	producer  *Producer
	selection runorigin.Selection
	entry     agentEntry
	profile   termsProfile
	event     retainedEvent
	digest    [sha256.Size]byte
	checker   originChecker
	scope     string

	mu       sync.Mutex // serializes Prepare and Validate, never Close
	prepared *runorigin.Result

	life      context.Context
	cancel    context.CancelFunc
	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

func (s *session) callContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(s.life, cancel)
	return ctx, func() { stop(); cancel() }
}

func (s *session) interrupted(ctx context.Context) error {
	if s.closed.Load() {
		return refuse(ReasonClosed)
	}
	if ctx.Err() != nil {
		return unavailable(ReasonCancelled)
	}
	return nil
}

// evaluate rechecks the mapping, retained event, contract profile, signed inner
// request, grant and tip. It does not read the ingest journal or its watermark.
func (s *session) evaluate(parent context.Context) (runorigin.Result, error) {
	var zero runorigin.Result
	if parent == nil {
		return zero, unavailable(ReasonCancelled)
	}
	ctx, done := s.callContext(parent)
	defer done()
	if err := s.interrupted(ctx); err != nil {
		return zero, err
	}
	entry, err := s.producer.resolve(s.selection)
	if err != nil {
		return zero, err
	}
	if entry != s.entry {
		return zero, refuse(ReasonChanged)
	}
	if !entry.connectionBound(s.producer.owner) {
		return zero, refuse(ReasonMappingInvalid)
	}
	event, err := s.producer.store.retained(ctx, entry.StoreBase, entry.Identity, s.selection.Event)
	if err != nil {
		return zero, err
	}
	if event.Sender != s.event.Sender || sha256.Sum256(event.Content) != s.digest {
		return zero, refuse(ReasonChanged)
	}
	terms, code := s.checker.Terms()
	if code != cg1.OriginLive {
		return zero, refusalFor(code)
	}
	if s.profile.admit(terms) != nil {
		return zero, refuse(ReasonProfile)
	}
	if err = s.interrupted(ctx); err != nil {
		return zero, err
	}
	facts, code := s.checker.Check(ctx, cg1.OriginEvent{RoomID: s.selection.Event.RoomID, EventID: s.selection.Event.EventID, Sender: event.Sender, Content: event.Content})
	if err = s.interrupted(ctx); err != nil {
		return zero, err
	}
	if code != cg1.OriginLive { // live gate
		return zero, refusalFor(code)
	}
	origin := runorigin.Origin{Kind: "admission", EventID: facts.RequestID, GrantID: facts.GrantID, TipHash: facts.TipHash, Mode: "enforcing", CommandID: ""}
	// The shape check also rejects a Matrix event ID in any origin member.
	if !origin.Valid() || origin.EventID == s.selection.Event.EventID {
		return zero, refuse(ReasonInnerInvalid)
	}
	return runorigin.Result{IdentityRegistrationNumber: entry.Registration, Origin: origin}, nil
}

// Prepare produces a Result only from a Live evaluation. A session prepares once.
func (s *session) Prepare(ctx context.Context) (runorigin.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.prepared != nil {
		return runorigin.Result{}, refuse(ReasonSessionState)
	}
	result, err := s.evaluate(ctx)
	if err != nil {
		return runorigin.Result{}, err
	}
	s.prepared = &result
	return result, nil
}

// Validate evaluates again from current facts and returns the prepared Result
// only when the fresh one is exactly equal to it.
func (s *session) Validate(ctx context.Context) (runorigin.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.prepared == nil {
		return runorigin.Result{}, refuse(ReasonSessionState)
	}
	want := *s.prepared
	fresh, err := s.evaluate(ctx) // fresh validation gate
	if err != nil {
		return runorigin.Result{}, err
	}
	if fresh != want {
		withoutTip := fresh
		withoutTip.Origin.TipHash = want.Origin.TipHash
		if withoutTip == want {
			return runorigin.Result{}, unavailable(ReasonTipMoved)
		}
		return runorigin.Result{}, refuse(ReasonChanged)
	}
	return want, nil
}

// Close is local, prompt and idempotent. It does not wait for a call in
// flight: it cancels it, then releases the checker and removes the scope.
func (s *session) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		s.cancel()
		checkerErr := s.checker.Close()
		removeErr := os.RemoveAll(s.scope)
		if checkerErr != nil || removeErr != nil {
			s.closeErr = refuse(ReasonClosed)
		}
	})
	return s.closeErr
}
