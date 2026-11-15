package caskbrew

import (
	"errors"
	"strings"
	"testing"
)

// Complete feature diff, clean repository, expected base, verified bot signatures and exact committed cask are required; inspection issues only reads.
func TestCustodyRepositoryReadGate(t *testing.T) {
	base := strings.Repeat("a", 40)
	ruby := []byte("canonical fixture")
	for _, tc := range []struct{ name, want string }{{"valid", ""}, {"wrong-origin", "tap-repository-refused"}, {"main-branch", "tap-feature-branch-required"}, {"wrong-base", "tap-base-mismatch"}, {"dirty", "tap-worktree-dirty"}, {"not-ancestor", "tap-base-not-ancestor"}, {"hidden-extra", "tap-diff-outside-a2a"}, {"unsigned", "tap-signed-bot-commit-required"}, {"foreign-author", "tap-signed-bot-commit-required"}, {"earlier-unsigned", "tap-signed-bot-commit-required"}, {"changed-cask", "tap-proposal-derivation-mismatch"}} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			read := func(args ...string) ([]byte, error) {
				calls++
				key := strings.Join(args, " ")
				result := ""
				switch key {
				case "remote get-url origin":
					result = "git@github.com:relux-works/homebrew-tap.git"
					if tc.name == "wrong-origin" {
						result = "https://example.invalid/repo"
					}
				case "symbolic-ref --short HEAD":
					result = "release/a2a"
					if tc.name == "main-branch" {
						result = "main"
					}
				case "rev-parse refs/remotes/origin/main":
					result = base
					if tc.name == "wrong-base" {
						result = strings.Repeat("b", 40)
					}
				case "status --porcelain --untracked-files=all":
					if tc.name == "dirty" {
						result = " M Casks/curator.rb"
					}
				case "merge-base --is-ancestor " + base + " HEAD":
					if tc.name == "not-ancestor" {
						return nil, errors.New("fixture refusal")
					}
				case "diff --name-only " + base + " HEAD --":
					result = "Casks/a2a.rb"
					if tc.name == "hidden-extra" {
						result += "\nCasks/curator.rb"
					}
				case "log --format=%G? %an <%ae> " + base + "..HEAD":
					result = "G Relux Nexus <262682706+reluxbot@users.noreply.github.com>"
					if tc.name == "unsigned" {
						result = "N Relux Nexus <262682706+reluxbot@users.noreply.github.com>"
					}
					if tc.name == "foreign-author" {
						result = "G Another Author <other@example.invalid>"
					}
					if tc.name == "earlier-unsigned" {
						result += "\nN Relux Nexus <262682706+reluxbot@users.noreply.github.com>"
					}
				case "show HEAD:Casks/a2a.rb":
					if tc.name == "changed-cask" {
						return []byte("changed"), nil
					}
					return ruby, nil
				default:
					t.Fatalf("unexpected or mutating Git command: %q", args)
				}
				return []byte(result + "\n"), nil
			}
			e := verifyTapRepository(base, ruby, read)
			if tc.want == "" {
				if e != nil || calls != 8 {
					t.Fatal(e, calls)
				}
			} else if e == nil || e.Error() != tc.want {
				t.Fatalf("want %s, got %v", tc.want, e)
			}
		})
	}
}
