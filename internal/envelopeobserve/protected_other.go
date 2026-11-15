//go:build !unix

package envelopeobserve

import "os"

// No qualified protected-file ownership adapter exists on these platforms.
func protectedInfo(os.FileInfo, bool) bool { return false }
