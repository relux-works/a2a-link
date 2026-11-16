package originproducer

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/relux-works/a2a-swarm/internal/cg1"
	"github.com/relux-works/a2a-swarm/internal/config"
	"github.com/relux-works/a2a-swarm/internal/matrix"
	"github.com/relux-works/a2a-swarm/runorigin"
)

// protectedOwner is the only account whose mapping file is trusted.
const protectedOwner uint32 = 0

const mappingLimit = 256 << 10
const mappingAgentLimit = 64

var errMapping = errors.New("origin producer: mapping")

// agentEntry is everything the producer knows about one input principal. All
// of it is read from the protected mapping; none of it comes from a launcher.
type agentEntry struct {
	Input        runorigin.Principal `json:"input_principal"`
	Identity     string              `json:"identity"`
	Connection   string              `json:"connection"`
	MatrixUserID string              `json:"matrix_user_id"`
	Policy       string              `json:"policy"`
	TermsProfile string              `json:"terms_profile"`
	Registration string              `json:"keymaker_registration"`
	StoreBase    string              `json:"store_base"`
	PolicyDir    string              `json:"policy_dir"`
	ScopeRoot    string              `json:"scope_root"`
}

type mappingFile struct {
	Version  int                 `json:"version"`
	Launcher runorigin.Principal `json:"launcher"`
	Agents   []agentEntry        `json:"agents"`
}

func ownedBy(info os.FileInfo, owner uint32) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == owner
}

func protectedPath(path string) bool {
	actual, err := filepath.EvalSymlinks(path)
	return err == nil && filepath.IsAbs(path) && filepath.Clean(path) == path && actual == path
}

// readProtected applies the checks of the existing cg1 configuration loader
// (canonical path without links, regular single-link file, exact owner, bounded
// size, same file before and after open) with the owner fixed by the caller and
// no write access for anyone but that owner on the file or its directory.
func readProtected(path string, owner uint32) ([]byte, error) {
	if !protectedPath(path) {
		return nil, errMapping
	}
	dir, base := filepath.Dir(path), filepath.Base(path)
	parent, err := os.Lstat(dir)
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0022 != 0 || !ownedBy(parent, owner) {
		return nil, errMapping
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, errMapping
	}
	defer root.Close()
	entry, err := root.Lstat(base)
	if err != nil || !entry.Mode().IsRegular() {
		return nil, errMapping
	}
	f, err := root.OpenFile(base, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errMapping
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !os.SameFile(entry, st) || !st.Mode().IsRegular() || st.Mode().Perm()&^0644 != 0 || st.Mode().Perm()&0400 == 0 || st.Size() < 1 || st.Size() > mappingLimit {
		return nil, errMapping
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != owner || s.Nlink != 1 {
		return nil, errMapping
	}
	raw, err := io.ReadAll(io.LimitReader(f, mappingLimit+1))
	if err != nil || len(raw) > mappingLimit {
		return nil, errMapping
	}
	return raw, nil
}

// exactObject admits only the closed field names. encoding/json alone would
// accept case variants and silently ignore a missing field.
func exactObject(value any, names string) (map[string]any, bool) {
	m, ok := value.(map[string]any)
	fields := strings.Fields(names)
	if !ok || len(m) != len(fields) {
		return nil, false
	}
	for _, name := range fields {
		if _, exists := m[name]; !exists {
			return nil, false
		}
	}
	return m, true
}

func mappingShape(value any) bool {
	top, ok := exactObject(value, "version launcher agents")
	if !ok {
		return false
	}
	if _, ok = exactObject(top["launcher"], "uid generation"); !ok {
		return false
	}
	agents, ok := top["agents"].([]any)
	if !ok {
		return false
	}
	for _, agent := range agents {
		entry, ok := exactObject(agent, "input_principal identity connection matrix_user_id policy terms_profile keymaker_registration store_base policy_dir scope_root")
		if !ok {
			return false
		}
		if _, ok = exactObject(entry["input_principal"], "uid generation"); !ok {
			return false
		}
	}
	return true
}

func validRegistration(s string) bool {
	return len(s) >= 1 && len(s) <= 4096 && !strings.ContainsAny(s, "\x00\r\n")
}

func validHostPath(path string) bool {
	return len(path) <= 4096 && filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && !strings.ContainsAny(path, "\x00\r\n")
}

// validConnection matches the connection registry's identifier form.
func validConnection(s string) bool {
	if len(s) < 1 || len(s) > 64 || s[0] == '_' || s[0] == '-' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func (a agentEntry) valid() bool {
	return a.Input.UID != 0 && a.Input.Generation != 0 &&
		config.ValidateName(a.Identity) == nil && validConnection(a.Connection) &&
		matrix.ValidVerificationID(a.MatrixUserID, '@') && a.Policy == cg1.MatrixPolicy &&
		config.ValidateName(a.TermsProfile) == nil && validRegistration(a.Registration) &&
		validHostPath(a.StoreBase) && validHostPath(a.PolicyDir) && validHostPath(a.ScopeRoot)
}

// parseMapping accepts one exact, closed, duplicate-free document. Every fact
// is mandatory; a missing or malformed fact refuses the whole mapping.
func parseMapping(raw []byte) (mappingFile, error) {
	var m mappingFile
	value, err := matrix.ParseStrictJSON(raw)
	if err != nil || !mappingShape(value) {
		return m, errMapping
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&m) != nil || dec.Decode(new(any)) != io.EOF {
		return mappingFile{}, errMapping
	}
	if m.Version != 1 || m.Launcher.UID == 0 || m.Launcher.Generation == 0 || len(m.Agents) == 0 || len(m.Agents) > mappingAgentLimit {
		return mappingFile{}, errMapping
	}
	principals, identities := map[runorigin.Principal]bool{}, map[string]bool{}
	for _, a := range m.Agents {
		if !a.valid() || principals[a.Input] || identities[a.Identity] {
			return mappingFile{}, errMapping
		}
		principals[a.Input], identities[a.Identity] = true, true
	}
	return m, nil
}

func loadMapping(path string, owner uint32) (mappingFile, error) {
	raw, err := readProtected(path, owner)
	if err != nil {
		return mappingFile{}, err
	}
	return parseMapping(raw)
}
