package caskbrew

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

type tapRead func(...string) ([]byte, error)

// VerifyTapRepository inspects the complete signed feature diff against the
// independently fetched tap main. All Git operations are read-only; no caller
// supplied path-list file can hide a staged file or an unrelated commit.
func VerifyTapRepository(ctx context.Context, dir, base string, ruby []byte) error {
	return verifyTapRepository(base, ruby, func(args ...string) ([]byte, error) {
		c := exec.CommandContext(ctx, "git", args...)
		c.Dir = dir
		c.Env = append(os.Environ(), "GIT_OPTIONAL_LOCKS=0")
		return c.Output()
	})
}
func verifyTapRepository(base string, ruby []byte, read tapRead) error {
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(base) {
		return errors.New("tap-base-contract")
	}
	value := func(args ...string) (string, error) {
		raw, e := read(args...)
		return strings.TrimSpace(string(raw)), e
	}
	origin, e := value("remote", "get-url", "origin")
	if e != nil || (origin != "git@github.com:relux-works/homebrew-tap.git" && origin != "https://github.com/relux-works/homebrew-tap.git") {
		return errors.New("tap-repository-refused")
	}
	branch, e := value("symbolic-ref", "--short", "HEAD")
	if e != nil || branch == "" || branch == "main" {
		return errors.New("tap-feature-branch-required")
	}
	main, e := value("rev-parse", "refs/remotes/origin/main")
	if e != nil || main != base {
		return errors.New("tap-base-mismatch")
	}
	dirty, e := value("status", "--porcelain", "--untracked-files=all")
	if e != nil || dirty != "" {
		return errors.New("tap-worktree-dirty")
	}
	if _, e = read("merge-base", "--is-ancestor", base, "HEAD"); e != nil {
		return errors.New("tap-base-not-ancestor")
	}
	diff, e := value("diff", "--name-only", base, "HEAD", "--")
	if e != nil {
		return errors.New("tap-diff-read")
	}
	if e = VerifyTapDiff(strings.Split(diff, "\n")); e != nil {
		return e
	}
	// Inspect every introduced commit, not only the last. Custody's configured
	// allowed-signers authority must verify each bot object before opening the PR.
	commits, e := value("log", "--format=%G? %an <%ae>", base+"..HEAD")
	if e != nil || commits == "" {
		return errors.New("tap-signature-read")
	}
	for _, line := range strings.Split(commits, "\n") {
		if line != "G Relux Nexus <262682706+reluxbot@users.noreply.github.com>" {
			return errors.New("tap-signed-bot-commit-required")
		}
	}
	actual, e := read("show", "HEAD:Casks/a2a.rb")
	if e != nil || !bytes.Equal(actual, ruby) {
		return errors.New("tap-proposal-derivation-mismatch")
	}
	return nil
}
