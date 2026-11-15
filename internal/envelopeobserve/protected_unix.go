//go:build unix

package envelopeobserve

import (
	"os"
	"syscall"
)

func protectedInfo(st os.FileInfo, directory bool) bool {
	stat, ok := st.Sys().(*syscall.Stat_t)
	// The agent must not be able to chmod/replace the roster or any ancestor.
	return ok && os.Geteuid() != 0 && stat.Uid == 0 && st.Mode().Perm()&0o022 == 0 &&
		(directory && st.IsDir() || !directory && st.Mode().IsRegular())
}
