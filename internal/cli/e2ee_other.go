//go:build !darwin && !linux

package cli

import (
	"context"
	"errors"

	"github.com/relux-works/a2a-swarm/internal/config"
)

// E2EE custody exists only on the supported a2ad hosts (macOS and Linux).
func cmdE2EE(context.Context, *App, []string) error {
	return errors.New("e2ee: e2ee_custody_unavailable")
}

// Without custody the generated registration password is used as before and
// nothing is retained.
func (a *App) e2eeAccountPassword(_ context.Context, _ config.Paths, _, _, _, _, generated string) (string, bool, error) {
	return generated, false, nil
}
