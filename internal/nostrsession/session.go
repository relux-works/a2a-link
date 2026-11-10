package nostrsession

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/relux-works/a2a-swarm/internal/admission"
	"github.com/relux-works/a2a-swarm/internal/config"
	tr "github.com/relux-works/a2a-swarm/transport"
	nt "github.com/relux-works/a2a-transport-nostr/nostrtransport"
)

type Session struct {
	mu               sync.Mutex
	adapter          *nt.Adapter
	policy           admission.Checker
	store            admission.Store
	paths            config.Paths
	name, self, root string
	settings         settings
	configBytes      []byte
	life             context.Context
	cancel           context.CancelFunc
	closed           bool
	// Fault seams are private, test-only, and cannot inject permission.
	beforeAppend, afterAppend func() error
}

func Open(ctx context.Context, base, identity string) (*Session, error) {
	if config.ValidateName(identity) != nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrConfiguration
	}
	// Selecting two transports under one local identity is ambiguous, not fallback.
	for _, path := range []string{filepath.Join(base, "agents", identity+".json"), filepath.Join(base, "humans", identity+".json")} {
		if _, e := os.Lstat(path); !os.IsNotExist(e) {
			return nil, ErrConfiguration
		}
	}
	root := Root(base, identity)
	raw, cfg, e := readSettings(root)
	if e != nil {
		return nil, e
	}
	if e := admission.PrivateDir(filepath.Join(root, "state")); e != nil {
		return nil, ErrConfiguration
	}
	a, e := nt.Open(tr.Config{StateDir: filepath.Join(root, "transport"), Settings: cfg.Settings})
	if e != nil {
		return nil, ErrConfiguration
	}
	self, e := a.Self(ctx)
	if e != nil {
		a.Close()
		return nil, ErrUnavailable
	}
	policyDir := filepath.Join(root, "admission")
	p, e := admission.Open(cfg.Policy, admission.Config{Identity: identity, StateDir: policyDir, Nostr: true, NostrPubkey: string(self.ID)})
	if e != nil {
		a.Close()
		return nil, e
	}
	life, cancel := context.WithCancel(context.Background())
	return &Session{adapter: a, policy: p, store: admission.Store{Dir: policyDir}, paths: config.Paths{Base: root}, name: identity, self: string(self.ID), root: root, settings: cfg, configBytes: bytes.Clone(raw), life: life, cancel: cancel}, nil
}

func (s *Session) Close() error {
	s.cancel() // interrupt an in-flight check before waiting for its operation lock
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	e := s.policy.Close()
	if x := s.adapter.Close(); e == nil {
		e = x
	}
	return e
}

func (s *Session) begin(ctx context.Context) (context.Context, func(), error) {
	s.mu.Lock()
	if s.closed || ctx == nil || ctx.Err() != nil || s.life.Err() != nil {
		s.mu.Unlock()
		return nil, nil, ErrUnavailable
	}
	raw, _, e := readSettings(s.root)
	if e != nil || !bytes.Equal(raw, s.configBytes) {
		s.mu.Unlock()
		return nil, nil, ErrConfiguration
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.life, cancel)
	return ctx, func() { stop(); cancel(); s.mu.Unlock() }, nil
}

func (s *Session) Self() string { return s.self }

// Conversation creation is local validation, never peer admission or discovery.
func (s *Session) Conversation(ctx context.Context, participants []tr.PrincipalID, subject string) (tr.ConversationID, error) {
	_, done, e := s.begin(ctx)
	if e != nil {
		return "", e
	}
	defer done()
	return s.adapter.ConversationFor(participants, subject)
}

func (s *Session) Send(ctx context.Context, req tr.SendRequest) (tr.SendResult, error) {
	ctx, done, e := s.begin(ctx)
	if e != nil {
		return tr.SendResult{}, e
	}
	defer done()
	if len(req.Message.Attachments) != 0 {
		return tr.SendResult{}, ErrUnsupported
	}
	// The host presentation cannot be overridden by user-authored Message fields.
	if _, ok := req.Message.Extensions[nt.GrantExtension]; ok {
		return tr.SendResult{}, ErrPresentation
	}
	members, e := s.adapter.Members(ctx, req.Conversation)
	if e != nil {
		return tr.SendResult{}, e
	}
	allowed := map[tr.PrincipalID]bool{}
	for _, member := range members {
		allowed[member.Principal] = true
	}
	targets := append([]tr.PrincipalID(nil), req.Message.To...)
	if len(targets) == 0 {
		for _, member := range members {
			targets = append(targets, member.Principal)
		}
	}
	for _, target := range targets {
		if !allowed[target] {
			return tr.SendResult{}, errors.New("nostr: invalid_recipient")
		}
	}
	seen := map[tr.PrincipalID]bool{}
	for _, target := range targets {
		// Only the exact authenticated local key is transport bookkeeping.
		if string(target) == s.self || seen[target] {
			continue
		}
		seen[target] = true
		d, e := s.policy.Outbound(ctx, admission.Outbound{Identity: s.name, RoomID: string(req.Conversation), TransactionID: req.IdempotencyKey, Kind: req.Message.Kind, Nostr: &admission.TrustedNostrOutbound{Recipient: string(target)}})
		d = admission.Normalize(d, e)
		if d.Verdict != admission.Live {
			if d.Verdict == admission.Exchange {
				d = admission.Decision{Verdict: admission.Refused, Reason: "exchange_outbound"}
			}
			if e := s.store.Count(ctx, d.Reason); e != nil {
				return tr.SendResult{}, admission.ErrStorage
			}
			return tr.SendResult{}, errors.New("admission: " + d.Reason)
		}
	}
	if ctx.Err() != nil {
		return tr.SendResult{}, ErrUnavailable
	}
	if s.settings.Presentation != nil {
		ext := make(map[string]json.RawMessage, len(req.Message.Extensions)+1)
		for k, v := range req.Message.Extensions {
			ext[k] = bytes.Clone(v)
		}
		ext[nt.GrantExtension] = bytes.Clone(s.settings.Presentation)
		req.Message.Extensions = ext
	}
	// This is the only production send boundary. Every retry reaches the checks above.
	return s.adapter.Send(ctx, req)
}

// Record contains only ordinary peer-visible data. Grant material never enters
// ordinary inbox output; the admission store retains private held inputs itself.
type Record struct {
	ID           string           `json:"id"`
	Conversation string           `json:"conversation"`
	Sender       string           `json:"sender,omitempty"`
	Time         time.Time        `json:"time,omitempty"`
	Kind         string           `json:"kind,omitempty"`
	Text         string           `json:"text,omitempty"`
	To           []tr.PrincipalID `json:"to,omitempty"`
	Re           tr.EventID       `json:"re,omitempty"`
	Thread       tr.EventID       `json:"thread,omitempty"`
	Gap          tr.GapReason     `json:"gap,omitempty"`
}

// Inbound is also used for rechecking held tuples. Its trusted fields come only
// from verified adapter Events and Self, never application text or Message.To.
type sessionChecker struct{ s *Session }

func (p sessionChecker) Inbound(ctx context.Context, in admission.Inbound) (admission.Decision, error) {
	s := p.s
	n := in.Nostr
	if n == nil || n.Recipient != s.self || n.Sender == s.self {
		return admission.Decision{Verdict: admission.Refused, Reason: "invalid_peer"}, nil
	}
	if n.Presentation != nil && (len(n.Presentation.Bytes) > nt.MaxGrantPresentationBytes || !uniqueJSON(n.Presentation.Bytes)) {
		return admission.Decision{Verdict: admission.Refused, Reason: "invalid_presentation"}, nil
	}
	return s.policy.Inbound(ctx, in)
}
func (p sessionChecker) Outbound(ctx context.Context, out admission.Outbound) (admission.Decision, error) {
	return p.s.policy.Outbound(ctx, out)
}
func (sessionChecker) Close() error { return nil }

func (s *Session) Sync(ctx context.Context) (tr.Batch, error) {
	ctx, done, e := s.begin(ctx)
	if e != nil {
		return tr.Batch{}, e
	}
	defer done()
	var batch tr.Batch
	_, e = config.UpdateStateContext(ctx, s.paths, s.name, time.Time{}, func(st *config.State) error {
		var e error
		batch, e = s.adapter.Sync(ctx, tr.Cursor(st.NextBatch), tr.SyncOptions{Initial: st.NextBatch == ""})
		if e != nil {
			return e
		}
		mb, e := config.OpenMailbox(s.paths, s.name)
		if e != nil {
			return admission.ErrStorage
		}
		items := []admission.Item{}
		for _, ev := range batch.Events {
			if string(ev.Sender) == s.self || mb.Has(string(ev.ID)) {
				continue
			}
			if len(ev.Message.Attachments) != 0 {
				if e := s.store.Count(ctx, "denied"); e != nil {
					return e
				}
				continue
			}
			n := &admission.TrustedNostrInbound{Sender: string(ev.Sender), Recipient: s.self, EventID: string(ev.ID), Time: ev.Time}
			if raw, ok := ev.Message.Extensions[nt.GrantExtension]; ok {
				p, e := presentation(raw)
				if e != nil {
					if e := s.store.Count(ctx, "invalid_presentation"); e != nil {
						return e
					}
					continue
				}
				n.Presentation = &admission.NostrPresentation{GrantID: p.GrantID, Bytes: p.Bytes}
			}
			record := Record{ID: string(ev.ID), Conversation: string(ev.Conversation), Sender: string(ev.Sender), Time: ev.Time, Kind: ev.Message.Kind, Text: ev.Message.Text, To: ev.Message.To, Re: ev.Message.Re, Thread: ev.Message.Thread}
			payload, _ := json.Marshal(record)
			items = append(items, admission.Item{Inbound: admission.Inbound{RoomID: record.Conversation, EventID: record.ID, Sender: record.Sender, Kind: record.Kind, Timestamp: ev.Time.UnixMilli(), Body: []byte(ev.Message.Text), Nostr: n}, Payload: payload})
		}
		if e := s.store.Process(ctx, sessionChecker{s}, time.Now(), items, func(live []admission.Item) error {
			entries := make([]config.MailEntry, 0, len(live))
			for _, item := range live {
				entries = append(entries, config.MailEntry{ID: item.Inbound.EventID, Kind: config.MailEvent, Room: item.Inbound.RoomID, Sender: item.Inbound.Sender, TS: item.Inbound.Timestamp, Event: item.Payload})
			}
			if s.beforeAppend != nil {
				if e := s.beforeAppend(); e != nil {
					return e
				}
			}
			if _, e := mb.Append(entries); e != nil {
				return admission.ErrStorage
			}
			if s.afterAppend != nil {
				return s.afterAppend()
			}
			return nil
		}); e != nil {
			return e
		}
		for _, gap := range batch.Gaps {
			if !gap.Reason.Valid() {
				return ErrUnavailable
			}
			hash := sha256.Sum256([]byte(st.NextBatch + string(batch.Next) + string(gap.Conversation) + string(gap.Reason)))
			r := Record{ID: "gap:" + hex.EncodeToString(hash[:]), Conversation: string(gap.Conversation), Gap: gap.Reason}
			raw, _ := json.Marshal(r)
			if _, e := mb.Append([]config.MailEntry{{ID: r.ID, Kind: config.MailGap, Room: r.Conversation, Event: raw}}); e != nil {
				return admission.ErrStorage
			}
		}
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		// Mailbox and private held/exchange state are durable before cursor movement.
		st.NextBatch = string(batch.Next)
		return nil
	})
	// Never let unadmitted Event payloads escape through a Sync return value.
	batch.Events = nil
	batch.Invites = nil
	return batch, e
}

// ReadInbox receipts exactly the records whose output callback succeeded. A
// failed/short output leaves them pending, including after process restart.
func (s *Session) ReadInbox(ctx context.Context, limit int, output func([]Record) error) error {
	ctx, done, e := s.begin(ctx)
	if e != nil {
		return e
	}
	defer done()
	if limit < 1 || limit > 50 || output == nil {
		return ErrUnsupported
	}
	_, e = config.UpdateStateContext(ctx, s.paths, s.name, time.Time{}, func(_ *config.State) error {
		mb, e := config.OpenMailbox(s.paths, s.name)
		if e != nil {
			return admission.ErrStorage
		}
		pending := mb.Pending()
		pending = pending[:min(limit, len(pending))]
		records := make([]Record, 0, len(pending))
		ids := make([]string, 0, len(pending))
		for _, entry := range pending {
			var r Record
			if json.Unmarshal(entry.Event, &r) != nil || r.ID != entry.ID {
				return admission.ErrStorage
			}
			records = append(records, r)
			ids = append(ids, r.ID)
		}
		if e := output(records); e != nil {
			return e
		}
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		_, e = mb.Receive(ids)
		return e
	})
	return e
}

type Status struct {
	Transport string            `json:"transport"`
	Identity  string            `json:"identity"`
	PublicKey string            `json:"public_key"`
	Policy    string            `json:"admission_policy"`
	Pending   int               `json:"pending"`
	Counts    map[string]uint64 `json:"counts"`
}

func (s *Session) Status(ctx context.Context) (Status, error) {
	ctx, done, e := s.begin(ctx)
	if e != nil {
		return Status{}, e
	}
	defer done()
	st := Status{Transport: "nostr", Identity: s.name, PublicKey: s.self, Policy: s.settings.Policy}
	_, e = config.UpdateStateContext(ctx, s.paths, s.name, time.Time{}, func(_ *config.State) error {
		mb, e := config.OpenMailbox(s.paths, s.name)
		if e != nil {
			return admission.ErrStorage
		}
		st.Pending = len(mb.Pending())
		st.Counts, e = s.store.Counts(ctx)
		return e
	})
	return st, e
}
