package cg1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/relux-works/a2a-swarm/internal/admission"
	"github.com/relux-works/a2a-swarm/internal/cg1cosign"
	"github.com/relux-works/a2a-swarm/internal/matrix"
	"github.com/relux-works/swarma-chain-lab/experiments/grantcheck"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

const MatrixPolicy = "cg1-matrix"
const matrixConfigName = "cg1-matrix.json"
const matrixConfigLimit = 256 << 10

type matrixPeer struct {
	Key    string `json:"key"`
	Author string `json:"author"`
}
type matrixSettings struct {
	Version             int                   `json:"version"`
	Identity            string                `json:"identity"`
	UserID              string                `json:"user_id"`
	Audience            string                `json:"audience"`
	ConstructionProfile string                `json:"construction_profile"`
	AgentName           string                `json:"agent_name"`
	LandlordName        string                `json:"landlord_name"`
	IssuerPubkey        string                `json:"issuer_pubkey"`
	TimeoutMS           int                   `json:"timeout_ms"`
	RPC                 su.Route              `json:"rpc"`
	Pins                map[string]matrixPeer `json:"pins"`
	// Host-authenticated snapshots only; never copied from an incoming event.
	Evidence         map[string]json.RawMessage `json:"envelope_evidence"`
	InitialWatermark string                     `json:"initial_watermark"`
}

func init() { admission.Register(MatrixPolicy, openMatrix) }

// Config is refreshed for every check; immutable trust pins cannot change within a state namespace.
func loadMatrixSettings(dir string) (matrixSettings, error) {
	var cfg matrixSettings
	root, e := openPrivateRoot(dir)
	if e != nil {
		return cfg, errConfig
	}
	defer root.Close()
	entry, e := root.Lstat(matrixConfigName)
	if e != nil || !entry.Mode().IsRegular() {
		return cfg, errConfig
	}
	f, e := root.OpenFile(matrixConfigName, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return cfg, errConfig
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !os.SameFile(entry, st) || st.Mode().Perm() != 0700 || st.Size() < 1 || st.Size() > matrixConfigLimit {
		return cfg, errConfig
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 {
		return cfg, errConfig
	}
	raw, e := io.ReadAll(io.LimitReader(f, matrixConfigLimit+1))
	if e != nil || len(raw) > matrixConfigLimit {
		return cfg, errConfig
	}
	value, e := matrix.ParseStrictJSON(raw)
	if e != nil {
		return cfg, errConfig
	}
	if !matrixConfigShape(value) {
		return cfg, errConfig
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&cfg) != nil || dec.Decode(new(any)) != io.EOF {
		return cfg, errConfig
	}
	if cfg.Version != 1 || cfg.Identity == "" || !matrix.ValidVerificationID(cfg.UserID, '@') || cfg.Audience == "" || cfg.ConstructionProfile != "W" || cfg.TimeoutMS < 1 || cfg.TimeoutMS > 5000 || len(cfg.Pins) == 0 || len(cfg.Pins) > 64 {
		return cfg, errConfig
	}
	if _, e = time.Parse("2006-01-02T15:04:05Z", cfg.InitialWatermark); e != nil {
		return cfg, errConfig
	}
	for id, p := range cfg.Pins {
		if !matrix.ValidVerificationID(id, '@') || !validKey(p.Key) || !validEdAuthor(p.Author) {
			return cfg, errConfig
		}
	}
	if _, ok := cfg.Pins[cfg.UserID]; !ok {
		return cfg, errConfig
	}
	return cfg, nil
}

// encoding/json accepts case aliases; protected configuration admits only its exact closed names.
func matrixConfigShape(value any) bool {
	exact := func(value any, names string) bool {
		m, ok := value.(map[string]any)
		fields := strings.Fields(names)
		if !ok || len(m) != len(fields) {
			return false
		}
		for _, name := range fields {
			if _, exists := m[name]; !exists {
				return false
			}
		}
		return true
	}
	if !exact(value, "version identity user_id audience construction_profile agent_name landlord_name issuer_pubkey timeout_ms rpc pins envelope_evidence initial_watermark") {
		return false
	}
	obj := value.(map[string]any)
	if !exact(obj["rpc"], "host port username password") {
		return false
	}
	pins, ok := obj["pins"].(map[string]any)
	if !ok {
		return false
	}
	for _, peer := range pins {
		if !exact(peer, "key author") {
			return false
		}
	}
	evidence, ok := obj["envelope_evidence"].(map[string]any)
	if !ok {
		return false
	}
	for _, name := range []string{"service_root", "agent_revocation_root", "attestations", "active_generations", "revocations", "time"} {
		if evidence[name] == nil {
			return false
		}
	}
	return true
}

func matrixBinding(cfg matrixSettings) string {
	// Evidence may refresh while its root keys, audience, routing and grant pins remain immutable.
	evidence := map[string]json.RawMessage{}
	for _, k := range []string{"service_root", "agent_revocation_root", "operator_root", "operator_owner"} {
		if x, ok := cfg.Evidence[k]; ok {
			evidence[k] = x
		}
	}
	cfg.Evidence = evidence
	raw, _ := json.Marshal(cfg)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func openMatrix(c admission.Config) (admission.Checker, error) {
	if c.Nostr || !matrix.ValidVerificationID(c.MatrixUserID, '@') {
		return nil, errConfig
	}
	cfg, e := loadMatrixSettings(c.StateDir)
	if e != nil || cfg.Identity != c.Identity || cfg.UserID != c.MatrixUserID {
		return nil, errConfig
	}
	node, e := newReadNode(cfg.RPC)
	if e != nil {
		return nil, errConfig
	}
	success := false
	defer func() {
		if !success {
			node.Close()
		}
	}()
	state := filepath.Join(c.StateDir, "matrix-cg1-state")
	if e = admission.PrivateDir(state); e != nil {
		return nil, errConfig
	}
	grantState := filepath.Join(c.StateDir, "matrix-grantcheck-state")
	if e = admission.PrivateDir(grantState); e != nil {
		return nil, errConfig
	}
	if _, je := os.Lstat(filepath.Join(state, matrixJournalName)); os.IsNotExist(je) {
		if _, ge := os.Lstat(filepath.Join(grantState, "grantcheck.json")); !os.IsNotExist(ge) {
			return nil, errConfig
		}
	}
	binding := matrixBinding(cfg)
	if e = initializeMatrixJournal(state, binding, cfg.InitialWatermark); e != nil {
		return nil, errConfig
	}
	core, e := grantcheck.NewForTransport(grantcheck.Config{ConstructionProfile: "W", Identity: c.Identity, AgentName: cfg.AgentName, LandlordName: cfg.LandlordName, IssuerPubkey: cfg.IssuerPubkey, StateDir: grantState, Node: node, CheckTimeout: time.Duration(cfg.TimeoutMS) * time.Millisecond}, grantcheck.SwarmEnvelopeV2)
	if e != nil {
		return nil, errConfig
	}
	life, cancel := context.WithCancel(context.Background())
	success = true
	return &matrixChecker{core: core, dir: c.StateDir, state: state, binding: binding, identity: c.Identity, userID: c.MatrixUserID, timeout: time.Duration(cfg.TimeoutMS) * time.Millisecond, now: time.Now, cosign: cg1cosign.BIP340{}, life: life, cancel: cancel, node: node}, nil
}

type matrixJournal struct {
	Version   int                       `json:"version"`
	Binding   string                    `json:"binding"`
	Watermark string                    `json:"watermark"`
	Entries   map[string]matrixDelivery `json:"entries"`
}
type matrixDelivery struct {
	Direction string `json:"direction"`
	Room      string `json:"room"`
	ID        string `json:"id"`
}

const matrixJournalName = "matrix-journal.json"

func initializeMatrixJournal(dir, binding, watermark string) error {
	s, e := durable.Open(dir, "matrix.lock")
	if e != nil {
		return e
	}
	defer s.Close()
	b, e := s.Read(matrixJournalName, 65536)
	if e != nil {
		return e
	}
	if len(b) == 0 {
		prior, e := s.Read("grantcheck.json", 65536)
		if e != nil || len(prior) != 0 {
			return errConfig
		}
		j := matrixJournal{Version: 1, Binding: binding, Watermark: watermark, Entries: map[string]matrixDelivery{}}
		b, _ = json.Marshal(j)
		return s.Write(matrixJournalName, b)
	}
	_, e = readMatrixJournal(s, binding)
	return e
}
func readMatrixJournal(s *durable.Store, binding string) (matrixJournal, error) {
	var j matrixJournal
	b, e := s.Read(matrixJournalName, 65536)
	if e != nil || len(b) == 0 {
		return j, errConfig
	}
	if _, e = matrix.ParseStrictJSON(b); e != nil {
		return j, errConfig
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&j) != nil || d.Decode(new(any)) != io.EOF || j.Version != 1 || j.Binding != binding || j.Entries == nil || len(j.Entries) > 256 {
		return j, errConfig
	}
	if _, e = time.Parse("2006-01-02T15:04:05Z", j.Watermark); e != nil {
		return j, errConfig
	}
	for id, rec := range j.Entries {
		if !validID(id) || (rec.Direction != "in" && rec.Direction != "out") || !matrix.ValidVerificationID(rec.Room, '!') || rec.ID == "" {
			return j, errConfig
		}
	}
	return j, nil
}
