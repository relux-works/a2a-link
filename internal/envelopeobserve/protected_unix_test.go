//go:build unix

package envelopeobserve

import (
	"os"
	"syscall"
	"testing"
	"time"
)

type fileInfo struct {
	mode os.FileMode
	uid  uint32
}

func (f fileInfo) Name() string       { return "fixture" }
func (f fileInfo) Size() int64        { return 0 }
func (f fileInfo) Mode() os.FileMode  { return f.mode }
func (f fileInfo) ModTime() time.Time { return time.Time{} }
func (f fileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fileInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }

// Proves the ownership instrument accepts only root-controlled ordinary files
// and protected directories; agent-owned read-only bytes confer no host trust.
func TestProtectedOwnership(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("agent-only ownership contract")
	}
	for _, tc := range []struct {
		name      string
		info      fileInfo
		dir, want bool
	}{
		{"root-file", fileInfo{0o644, 0}, false, true},
		{"agent-readonly", fileInfo{0o444, uint32(os.Geteuid())}, false, false},
		{"other-owner", fileInfo{0o444, 65534}, false, false},
		{"root-group-write", fileInfo{0o664, 0}, false, false},
		{"root-world-write", fileInfo{0o646, 0}, false, false},
		{"root-symlink", fileInfo{os.ModeSymlink | 0o444, 0}, false, false},
		{"root-fifo", fileInfo{os.ModeNamedPipe | 0o444, 0}, false, false},
		{"root-dir", fileInfo{os.ModeDir | 0o755, 0}, true, true},
		{"writable-parent", fileInfo{os.ModeDir | 0o777, 0}, true, false},
		{"file-parent", fileInfo{0o644, 0}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := protectedInfo(tc.info, tc.dir); got != tc.want {
				t.Fatalf("got %v", got)
			}
		})
	}
}
