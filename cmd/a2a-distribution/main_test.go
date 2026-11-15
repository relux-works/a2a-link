package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The qualification switch cannot authorize the manifest signing route;
// malformed bindings also refuse without creating the selected output.
func TestDistributionCLIRefusals(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	base := []string{"manifest", "-root", filepath.Join("..", ".."), "-out", out, "-qualification", "-tag", "v0.1.2", "-commit", strings.Repeat("a", 40), "-tag-object", strings.Repeat("b", 40)}
	if e := run(context.Background(), base); e == nil || e.Error() != "production-fixture-trust-refused" {
		t.Fatal(e)
	}
	bad := append([]string{}, base...)
	for i, x := range bad {
		if x == "-tag" {
			bad[i+1] = "v0.1.2-rc.1"
		}
	}
	if e := run(context.Background(), bad); e == nil || e.Error() != "release-version-not-stable" {
		t.Fatal(e)
	}
	if _, e := os.Stat(out); !os.IsNotExist(e) {
		t.Fatal("refusal left output")
	}
}

// Read-only Git operations bind the actual checkout/archive/epoch. A changed
// archive, timestamp or commit is rejected with its specific association error;
// no test tag, commit, source modification or build is created here.
func TestDistributionSourceArchiveBinding(t *testing.T) {
	root := filepath.Join("..", "..")
	ctx := context.Background()
	git := func(args ...string) string {
		t.Helper()
		c := exec.Command("git", args...)
		c.Dir = root
		b, e := c.Output()
		if e != nil {
			t.Fatal(e)
		}
		return strings.TrimSpace(string(b))
	}
	sha := git("rev-parse", "HEAD")
	epoch, e := strconv.ParseInt(git("show", "-s", "--format=%ct", "HEAD"), 10, 64)
	if e != nil {
		t.Fatal(e)
	}
	c := exec.Command("git", "archive", "--format=tar", sha)
	c.Dir = root
	b, e := c.Output()
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(t.TempDir(), "source.tar")
	if e = os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
	if e = sourceBinding(ctx, root, p, sha, epoch); e != nil {
		t.Fatal("matching source", e)
	}
	if e = sourceBinding(ctx, root, p, sha, epoch+1); e == nil || e.Error() != "linux-source-epoch" {
		t.Fatal(e)
	}
	if e = sourceBinding(ctx, root, p, strings.Repeat("0", 40), epoch); e == nil || e.Error() != "linux-source-checkout" {
		t.Fatal(e)
	}
	if e = os.WriteFile(p, append(b, 1), 0600); e != nil {
		t.Fatal(e)
	}
	if e = sourceBinding(ctx, root, p, sha, epoch); e == nil || e.Error() != "linux-source-archive-binding" {
		t.Fatal(e)
	}
}
