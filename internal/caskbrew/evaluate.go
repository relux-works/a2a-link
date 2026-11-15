package caskbrew

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/relux-works/a2a-swarm/internal/cask"
)

// Evaluate uses only the real public pinned brew CLI in an isolated runner
// prefix. It evaluates canonical authenticated Ruby and never installs a cask.
func Evaluate(ctx context.Context, prefix string, ruby []byte, m cask.Manifest) error {
	canonical, e := cask.Render(m)
	if e != nil {
		return e
	}
	if string(canonical) != string(ruby) {
		return errors.New("cask-derivation-mismatch")
	}
	runner, e := filepath.EvalSymlinks(os.Getenv("RUNNER_TEMP"))
	if e != nil || runner == "" {
		return errors.New("brew-runner-prefix-required")
	}
	actual, e := filepath.EvalSymlinks(prefix)
	if e != nil || actual != filepath.Clean(prefix) || !strings.HasPrefix(actual, runner+string(filepath.Separator)) {
		return errors.New("brew-runner-prefix-required")
	}
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "HEAD")
	cmd.Dir = prefix
	source, e := cmd.Output()
	if e != nil || strings.TrimSpace(string(source)) != "bc63375ac3a4d6debb1ceb441ae6e22854f0909a" {
		return errors.New("brew-source-pin")
	}
	cmd = exec.CommandContext(ctx, "git", "status", "--porcelain", "--untracked-files=all")
	cmd.Dir = prefix
	dirty, e := cmd.Output()
	if e != nil || len(dirty) != 0 {
		return errors.New("brew-source-dirty")
	}
	state, e := os.MkdirTemp(runner, "a2a-brew-evaluate-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(state)
	env := []string{}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key == "HOME" || strings.HasPrefix(key, "HOMEBREW_") || strings.HasPrefix(key, "GITHUB_") || strings.HasPrefix(key, "GH_") || strings.HasPrefix(key, "ACTIONS_") || strings.HasPrefix(key, "MACOS_") || strings.HasPrefix(key, "ASC_") {
			continue
		}
		env = append(env, entry)
	}
	for _, dir := range []string{"home", "cache", "logs", "tmp"} {
		if e = os.Mkdir(filepath.Join(state, dir), 0700); e != nil {
			return e
		}
	}
	env = append(env, "HOME="+filepath.Join(state, "home"), "HOMEBREW_CACHE="+filepath.Join(state, "cache"), "HOMEBREW_LOGS="+filepath.Join(state, "logs"), "HOMEBREW_TEMP="+filepath.Join(state, "tmp"), "HOMEBREW_NO_AUTO_UPDATE=1", "HOMEBREW_NO_ANALYTICS=1", "HOMEBREW_NO_INSTALL_FROM_API=1", "HOMEBREW_NO_ENV_HINTS=1")
	run := func(args ...string) ([]byte, error) {
		c := exec.CommandContext(ctx, filepath.Join(prefix, "bin/brew"), args...)
		c.Env = env
		out, e := c.Output()
		if e != nil {
			return nil, errors.New("brew-evaluation-command")
		}
		return out, nil
	}
	version, e := run("--version")
	if e != nil || strings.TrimSpace(string(version)) != "Homebrew 7.0.13" {
		return errors.New("brew-version-pin")
	}
	if _, e = run("tap-new", "--no-git", "relux-works/release-candidate"); e != nil {
		return e
	}
	tap, e := run("--repository", "relux-works/release-candidate")
	if e != nil {
		return e
	}
	expected := filepath.Join(prefix, "Library/Taps/relux-works/homebrew-release-candidate")
	if strings.TrimSpace(string(tap)) != expected {
		return errors.New("brew-local-tap-path")
	}
	if e = os.MkdirAll(filepath.Join(expected, "Casks"), 0700); e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(expected, "Casks/a2a.rb"), ruby, 0600); e != nil {
		return e
	}
	if _, e = run("trust", "relux-works/release-candidate"); e != nil {
		return e
	}
	info, e := run("info", "--cask", "--json=v2", "--variations", "relux-works/release-candidate/a2a")
	if e != nil {
		return e
	}
	platform := runtime.GOOS + "/" + runtime.GOARCH
	return Verify(info, ruby, m, prefix, platform)
}
