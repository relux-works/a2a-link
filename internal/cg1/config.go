// Package cg1 registers the fork's Nostr-only grant policy. It has no transport,
// signing, media upload or mailbox implementation; nostrsession owns that boundary.
package cg1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/relux-works/a2a-swarm/internal/admission"
	"github.com/relux-works/swarma-chain-lab/experiments/grantcheck"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

const Policy = "cg1"

var errConfig = errors.New("cg1: configuration")

// Provisioned by the host inside the engine-derived private identity namespace.
// RPC credentials are read-only and never reported. No ambient config fallback.
type settings struct {
	grantPolicy
	Version      int      `json:"version"`
	AgentName    string   `json:"agent_name"`
	LandlordName string   `json:"landlord_name"`
	IssuerPubkey string   `json:"issuer_pubkey"`
	TimeoutMS    int      `json:"timeout_ms"`
	RPC          su.Route `json:"rpc"`
}

func init() { admission.RegisterNostrOnly(Policy, open) }

func open(c admission.Config) (admission.Checker, error) {
	if !c.Nostr || !validKey(c.NostrPubkey) {
		return nil, errConfig
	}
	root, err := openPrivateRoot(c.StateDir)
	if err != nil {
		return nil, errConfig
	}
	defer root.Close()
	entry, err := root.Lstat("cg1.json")
	if err != nil || !entry.Mode().IsRegular() {
		return nil, errConfig
	}
	f, err := root.OpenFile("cg1.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errConfig
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !os.SameFile(entry, st) || !privateFile(st) || st.Size() > 8192 {
		return nil, errConfig
	}
	raw, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil || len(raw) > 8192 {
		return nil, errConfig
	}
	var cfg settings
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&cfg) != nil || d.Decode(new(any)) != io.EOF || (cfg.Version != 1 && cfg.Version != 2) || cfg.TimeoutMS < 1 || cfg.TimeoutMS > 5000 {
		return nil, errConfig
	}
	if !uniqueJSON(raw) || !nostrConfigNames(raw, cfg.Version) || !grantPolicyNames(raw, cfg.Version) {
		return nil, errConfig
	}
	_, _, err = cfg.grantPolicy.resolve()
	if err != nil {
		return nil, errConfig
	}
	node, err := newReadNode(cfg.RPC)
	if err != nil {
		return nil, errConfig
	}
	success := false
	defer func() {
		if !success {
			node.Close()
		}
	}()
	if err = root.Mkdir("cg1-state", 0700); err != nil && !os.IsExist(err) {
		return nil, errConfig
	}
	state := filepath.Join(c.StateDir, "cg1-state")
	sr, err := openPrivateRoot(state)
	if err != nil {
		return nil, errConfig
	}
	sr.Close()
	core, err := newPolicyChecker(cfg.grantPolicy, grantcheck.Config{ConstructionProfile: "W", Identity: c.Identity, AgentName: cfg.AgentName, LandlordName: cfg.LandlordName, IssuerPubkey: cfg.IssuerPubkey, StateDir: state, Node: node, CheckTimeout: time.Duration(cfg.TimeoutMS) * time.Millisecond}, grantcheck.NostrNIP17Seal)
	if err != nil {
		return nil, errConfig
	}
	success = true
	life, cancel := context.WithCancel(context.Background())
	return &checker{core: core, own: c.NostrPubkey, identity: c.Identity, timeout: time.Duration(cfg.TimeoutMS) * time.Millisecond, life: life, cancel: cancel, node: node}, nil
}

func openPrivateRoot(path string) (*os.Root, error) {
	actual, e := filepath.EvalSymlinks(path)
	if e != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || actual != path {
		return nil, errConfig
	}
	r, e := os.OpenRoot(path)
	if e != nil {
		return nil, errConfig
	}
	st, e := r.Stat(".")
	if e != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		r.Close()
		return nil, errConfig
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != uint32(os.Getuid()) {
		r.Close()
		return nil, errConfig
	}
	return r, nil
}
func privateFile(st os.FileInfo) bool {
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && st.Mode().IsRegular() && st.Mode().Perm() == 0600 && s.Nlink == 1 && s.Uid == uint32(os.Getuid())
}
func nostrConfigNames(raw []byte, version int) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return false
	}
	closed := func(object map[string]json.RawMessage, names string) bool {
		fields := strings.Fields(names)
		for name := range object {
			if !slices.Contains(fields, name) {
				return false
			}
		}
		return true
	}
	names := "version agent_name landlord_name issuer_pubkey timeout_ms rpc executor_key max_tip_age_seconds max_future_skew_seconds minimum_height terms"
	if version == 2 {
		names += " profile network genesis"
	}
	if !closed(object, names) {
		return false
	}
	var rpc map[string]json.RawMessage
	return json.Unmarshal(object["rpc"], &rpc) == nil && rpc != nil && closed(rpc, "host port username password")
}
func uniqueJSON(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	var value func() bool
	value = func() bool {
		t, e := d.Token()
		if e != nil || t == nil {
			return false
		}
		if delim, ok := t.(json.Delim); ok {
			if delim != '{' {
				return false
			}
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				s, ok := k.(string)
				if e != nil || !ok || seen[s] {
					return false
				}
				for name := range seen {
					if strings.EqualFold(name, s) {
						return false
					}
				}
				seen[s] = true
				if !value() {
					return false
				}
			}
			end, e := d.Token()
			return e == nil && end == json.Delim('}')
		}
		return true
	}
	return value()
}
