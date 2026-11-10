package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/relux-works/a2a-swarm/internal/config"
	"github.com/relux-works/a2a-swarm/internal/nostrsession"
	tr "github.com/relux-works/a2a-swarm/transport"
)

// Host namespace selection precedes Matrix connection construction.
// Missing Nostr metadata preserves the existing Matrix path byte for byte.
func (a *App) nostrInvocation(ctx context.Context, args []string) (bool, error) {
	if a.Getenv == nil {
		return false, nil
	}
	probe := &App{Getenv: a.Getenv, as: a.as, profile: a.profile, human: a.human, connectionFingerprint: a.connectionFingerprint}
	rest, e := probe.extractGlobal(args)
	if e != nil {
		return false, nil
	} // the existing global parser reports this error
	// Public routing inspections have no authenticated identity to select.
	if len(rest) > 0 && (rest[0] == "availability" || rest[0] == "connection") {
		return false, nil
	}
	p, e := config.ResolvePaths(a.Getenv)
	if e != nil {
		return false, nil
	}
	// Ordinary Matrix installations do not acquire an identity read just to
	// establish that the host has provisioned no Nostr namespace.
	if _, e := os.Lstat(filepath.Join(p.Base, "nostr")); os.IsNotExist(e) {
		return false, nil
	}
	name, e := probe.identity()
	if e != nil {
		return false, nil
	}
	selected, e := nostrsession.Selected(p.Base, name)
	if e != nil {
		return selected, e
	}
	if !selected {
		return false, nil
	}
	if probe.profile != "" || probe.human || probe.connectionFingerprint != "" {
		return true, nostrsession.ErrUnsupported
	}
	if len(rest) == 0 {
		return true, usagef("Nostr identity supports whoami, post, sync, inbox and status")
	}
	// Closed operation set, before any adapter, key, policy or Matrix session opens.
	switch rest[0] {
	case "whoami", "post", "sync", "inbox", "status":
	default:
		return true, nostrsession.ErrUnsupported
	}
	var req tr.SendRequest
	var peers []tr.PrincipalID
	var subject string
	limit, asJSON := 50, false
	switch rest[0] {
	case "post":
		fs := newFlagSet("nostr post")
		txn := fs.String("txn-id", "", "required stable idempotency key")
		to := fs.String("to", "", "comma-separated subset of conversation participants")
		kind := fs.String("kind", "", "application message kind")
		re := fs.String("re", "", "reply event ID")
		thread := fs.String("thread", "", "thread root event ID")
		sub := fs.String("subject", "", "conversation subject")
		pos, e := parseInterspersed(fs, rest[1:])
		if e != nil {
			return true, e
		}
		if len(pos) != 2 || *txn == "" {
			return true, usagef("usage: a2a post <peer[,peer]> --txn-id ID [--to peer[,peer]] [--kind K] [--re ID] [--thread ID] [--subject S] <text|@file|->")
		}
		for _, p := range strings.Split(pos[0], ",") {
			peers = append(peers, tr.PrincipalID(p))
		}
		body, e := a.readBody(pos[1])
		if e != nil {
			return true, e
		}
		req = tr.SendRequest{IdempotencyKey: *txn, Message: tr.Message{Text: body, Kind: *kind, Re: tr.EventID(*re), Thread: tr.EventID(*thread)}}
		if *to != "" {
			for _, p := range strings.Split(*to, ",") {
				req.Message.To = append(req.Message.To, tr.PrincipalID(p))
			}
		}
		subject = *sub
	case "inbox":
		fs := newFlagSet("nostr inbox")
		n := fs.Int("limit", 50, "maximum records (1..50)")
		j := fs.Bool("json", false, "JSON array of untrusted peer records")
		pos, e := parseInterspersed(fs, rest[1:])
		if e != nil {
			return true, e
		}
		if len(pos) != 0 || *n < 1 || *n > 50 {
			return true, usagef("usage: a2a inbox [--limit N] [--json]")
		}
		limit, asJSON = *n, *j
	case "sync":
		if len(rest) != 1 && !(len(rest) == 2 && rest[1] == "--json") {
			return true, nostrsession.ErrUnsupported
		}
	case "status":
		if len(rest) != 1 && !(len(rest) == 2 && rest[1] == "--json") && !(len(rest) == 3 && rest[1] == "admission" && rest[2] == "--json") {
			return true, nostrsession.ErrUnsupported
		}
	case "whoami":
		if len(rest) != 1 {
			return true, nostrsession.ErrUnsupported
		}
	}
	s, e := nostrsession.Open(ctx, p.Base, name)
	if e != nil {
		return true, e
	}
	defer s.Close()
	switch rest[0] {
	case "whoami":
		return true, writeCLIOutput(a.Stdout, s.Self()+"\n")
	case "post":
		req.Conversation, e = s.Conversation(ctx, peers, subject)
		if e != nil {
			return true, e
		}
		r, e := s.Send(ctx, req)
		if e != nil {
			return true, e
		}
		raw, _ := json.Marshal(struct {
			Outcome tr.Outcome `json:"outcome"`
			Event   tr.EventID `json:"event,omitempty"`
			Refusal tr.Refusal `json:"refusal,omitempty"`
		}{r.Outcome, r.Event, r.Refusal})
		if e := writeCLIOutput(a.Stdout, string(raw)+"\n"); e != nil {
			return true, e
		}
		if r.Outcome != tr.ACK {
			return true, errors.New("nostr: send_not_confirmed")
		}
		return true, nil
	case "sync":
		batch, e := s.Sync(ctx)
		if e != nil {
			return true, e
		}
		raw, _ := json.Marshal(struct {
			Dropped int      `json:"dropped"`
			Gaps    []tr.Gap `json:"gaps"`
		}{batch.Dropped, batch.Gaps})
		return true, writeCLIOutput(a.Stdout, string(raw)+"\n")
	case "status":
		st, e := s.Status(ctx)
		if e != nil {
			return true, e
		}
		raw, _ := json.Marshal(st)
		return true, writeCLIOutput(a.Stdout, string(raw)+"\n")
	case "inbox":
		if _, e := s.Sync(ctx); e != nil {
			return true, e
		}
		return true, s.ReadInbox(ctx, limit, func(records []nostrsession.Record) error {
			var out string
			if asJSON {
				raw, e := json.Marshal(records)
				if e != nil {
					return e
				}
				out = string(raw) + "\n"
			} else if len(records) == 0 {
				out = "no new peer events\n"
			} else {
				var b strings.Builder
				b.WriteString(inboxBegin + "\n")
				for i, r := range records {
					fmt.Fprintf(&b, "--- event %d/%d: nostr from=%s id=%s kind=%s\n", i+1, len(records), sanitizeLine(r.Sender), sanitizeLine(r.ID), sanitizeLine(r.Kind))
					text := r.Text
					if r.Gap != "" {
						text = "gap: " + string(r.Gap)
					}
					for _, line := range strings.Split(sanitizeText(text), "\n") {
						b.WriteString(inboxIndent + line + "\n")
					}
				}
				b.WriteString(inboxEnd + "\n")
				out = b.String()
			}
			if e := writeCLIOutput(a.Stdout, out); e != nil {
				return e
			}
			if a.afterPrint != nil {
				return a.afterPrint()
			}
			return nil
		})
	}
	return true, nostrsession.ErrUnsupported
}
