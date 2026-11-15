package config

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

// EnvelopeRosterPath selects a local host roster; no default roster or discovery.
// Bad/missing configuration is observation unavailability, never a delivery error.
func EnvelopeRosterPath(p Paths) string {
	base := p.Base
	if p.Root != "" {
		base = p.Root
	}
	path := filepath.Join(base, "envelope-observe.json")
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > 4096 {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return ""
	}
	var c struct {
		RosterPath string `json:"roster_path"`
	}
	if json.Unmarshal(raw, &c) != nil || !filepath.IsAbs(c.RosterPath) {
		return ""
	}
	return c.RosterPath
}
