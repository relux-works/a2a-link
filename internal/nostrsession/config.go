// Package nostrsession owns the authenticated adapter and its admission boundary.
// It never exposes a raw adapter, signer, upload method or admission bypass.
package nostrsession

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/relux-works/a2a-swarm/internal/config"
	nt "github.com/relux-works/a2a-transport-nostr/nostrtransport"
)

var (
	ErrConfiguration = errors.New("nostr: configuration")
	ErrUnsupported   = errors.New("nostr: unsupported_operation")
	ErrUnavailable   = errors.New("nostr: unavailable")
	ErrPresentation  = errors.New("nostr: invalid_presentation")
)

// Host file: <config root>/nostr/<identity>/session.json (0600).
// Policy is explicit, including "none"; no environment or peer may select it.
type settings struct {
	Version      int               `json:"version"`
	Policy       string            `json:"admission_policy"`
	Settings     map[string]string `json:"settings"`
	Presentation json.RawMessage   `json:"presentation,omitempty"`
}

func Root(base, identity string) string { return filepath.Join(base, "nostr", identity) }

// Selected checks the host namespace only. An existing but malformed namespace
// must fail closed in Open, never fall back to a Matrix identity of the same name.
func Selected(base, identity string) (bool, error) {
	if config.ValidateName(identity) != nil {
		return false, ErrConfiguration
	}
	_, e := os.Lstat(Root(base, identity))
	if os.IsNotExist(e) {
		return false, nil
	}
	if e != nil {
		return true, ErrConfiguration
	}
	return true, nil
}

func readSettings(root string) ([]byte, settings, error) {
	var cfg settings
	actual, e := filepath.EvalSymlinks(root)
	if e != nil || !filepath.IsAbs(root) || filepath.Clean(root) != root || actual != root {
		return nil, cfg, ErrConfiguration
	}
	st, e := os.Stat(root)
	if e != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return nil, cfg, ErrConfiguration
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Getuid()) {
		return nil, cfg, ErrConfiguration
	}
	r, e := os.OpenRoot(root)
	if e != nil {
		return nil, cfg, ErrConfiguration
	}
	defer r.Close()
	entry, e := r.Lstat("session.json")
	if e != nil || !entry.Mode().IsRegular() {
		return nil, cfg, ErrConfiguration
	}
	f, e := r.OpenFile("session.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, cfg, ErrConfiguration
	}
	defer f.Close()
	st, e = f.Stat()
	if e != nil || !os.SameFile(entry, st) || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 65536 {
		return nil, cfg, ErrConfiguration
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid != uint32(os.Getuid()) || sys.Nlink != 1 {
		return nil, cfg, ErrConfiguration
	}
	raw, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil || len(raw) > 65536 || !uniqueJSON(raw) {
		return nil, cfg, ErrConfiguration
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil, cfg, ErrConfiguration
	}
	for key := range fields {
		switch key {
		case "version", "admission_policy", "settings", "presentation":
		default:
			return nil, cfg, ErrConfiguration
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&cfg) != nil || d.Decode(new(any)) != io.EOF || cfg.Version != 1 || (cfg.Policy != "none" && cfg.Policy != "cg1") {
		return nil, cfg, ErrConfiguration
	}
	if cfg.Presentation != nil {
		if _, e := presentation(cfg.Presentation); e != nil {
			return nil, cfg, ErrPresentation
		}
	}
	return raw, cfg, nil
}

// Token keys are compared after JSON unescaping, in every object, including
// objects inside arrays. Escaped spellings cannot evade duplicate detection.
// A depth cap and the caller's byte bound keep adversarial work finite.
func uniqueJSON(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 64 {
			return false
		}
		t, e := d.Token()
		if e != nil {
			return false
		}
		delim, container := t.(json.Delim)
		if !container {
			return true
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				t, e := d.Token()
				key, ok := t.(string)
				if e != nil || !ok || seen[key] {
					return false
				}
				seen[key] = true
				if !value(depth + 1) {
					return false
				}
			}
		case '[':
			for d.More() {
				if !value(depth + 1) {
					return false
				}
			}
		default:
			return false
		}
		end, e := d.Token()
		return e == nil && ((delim == '{' && end == json.Delim('}')) || (delim == '[' && end == json.Delim(']')))
	}
	return value(0) && d.Decode(new(any)) == io.EOF
}

func presentation(raw json.RawMessage) (nt.GrantPresentationV1, error) {
	if len(raw) > 21944 || !uniqueJSON(raw) {
		return nt.GrantPresentationV1{}, ErrPresentation
	}
	p, e := nt.DecodeGrantPresentation(raw)
	if e != nil || !uniqueJSON(p.Bytes) || len(bytes.TrimSpace(p.Bytes)) == 0 || bytes.TrimSpace(p.Bytes)[0] != '{' {
		return nt.GrantPresentationV1{}, ErrPresentation
	}
	return p, nil
}
