// a2a-distribution is a repository build tool. It never publishes or installs.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/relux-works/a2a-swarm/internal/darwinrelease"
	"github.com/relux-works/a2a-swarm/internal/sharedrelease"
)

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: a2a-distribution tools|linux|collect|crosscheck|crossbuild|assemble|manifest|reconcile")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	root := fs.String("root", ".", "reviewed source checkout")
	dist := fs.String("dist", "dist", "GoReleaser outputs or complete platform input directory")
	out := fs.String("out", "", "new private output directory (must not exist)")
	tag := fs.String("tag", "", "expected stable release tag")
	commit := fs.String("commit", "", "expected source commit")
	tagObject := fs.String("tag-object", "", "expected annotated tag object")
	archive := fs.String("source-archive", "", "git archive --format=tar of source commit")
	epoch := fs.Int64("epoch", 0, "source commit timestamp")
	inputsFile := fs.String("inputs", "", "private closed artifact input JSON for macOS assembly")
	releaseID := fs.Int64("release-id", 0, "recorded draft ID for read-only recovery")
	artifactZIP := fs.String("artifact-zip", "", "captured private artifact ZIP")
	artifactID := fs.Int64("artifact-id", 0, "immutable artifact ID")
	artifactRun := fs.Int64("artifact-run", 0, "producer workflow run ID")
	artifactDigest := fs.String("artifact-sha256", "", "producer upload ZIP SHA256")
	platform := fs.String("platform", "", "darwin or linux producer")
	binary := fs.String("binary", "", "independent macOS-cross-built Linux executable")
	arch := fs.String("arch", "", "Linux architecture for independent byte check")
	qualification := fs.Bool("qualification", false, "non-production Linux evidence only; no signing")
	if e := fs.Parse(args[1:]); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return errors.New("usage: unexpected argument")
	}
	tools, e := sharedrelease.LoadTools(*root)
	if e != nil {
		return e
	}
	if args[0] == "tools" {
		return sharedrelease.VerifyTools(tools)
	}
	b := sharedrelease.Binding{Tag: *tag, Commit: *commit, TagObject: *tagObject}
	if e = b.Validate(); e != nil {
		return e
	}
	if *out == "" && args[0] != "crosscheck" && args[0] != "reconcile" {
		return errors.New("usage: -out required")
	}
	switch args[0] {
	case "assemble":
		if *qualification {
			return errors.New("production-fixture-trust-refused")
		}
		if e = sourceBinding(ctx, *root, *archive, b.Commit, *epoch); e != nil {
			return e
		}
		a, e := darwinrelease.Admit(ctx, *root, b.Tag, b.TagObject)
		if e != nil {
			return e
		}
		if a.Commit != b.Commit {
			return errors.New("assembly-admitted-commit-mismatch")
		}
		raw, e := os.ReadFile(*inputsFile)
		if e != nil {
			return e
		}
		var inputs sharedrelease.AssemblyInputs
		if e = sharedrelease.DecodeExact(raw, &inputs); e != nil {
			return e
		}
		evidence, e := sharedrelease.AssembleInputs(ctx, *root, *out, *archive, b, *epoch, inputs)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(evidence)
	case "reconcile":
		if *qualification {
			return errors.New("production-fixture-trust-refused")
		}
		state, e := sharedrelease.ReconcileCandidate(ctx, b, *releaseID, *dist)
		if e != nil {
			return e
		}
		if state == "public" {
			if e = sharedrelease.PublicReadback(ctx, b, *dist); e != nil {
				return e
			}
			observed, e := sharedrelease.ReconcileCandidate(ctx, b, *releaseID, *dist)
			if e != nil {
				return e
			}
			if observed != "public" {
				return errors.New("public-readback-state-changed")
			}
			state = "public; all authenticated public asset bytes match"
		}
		fmt.Fprintln(os.Stdout, "read-only reconciliation:", state)
		return nil
	case "crossbuild":
		if e = sourceBinding(ctx, *root, *archive, b.Commit, *epoch); e != nil {
			return e
		}
		if e = sharedrelease.VerifyCrossSource(*dist, *archive, b); e != nil {
			return e
		}
		if e = sharedrelease.BuildIndependentLinux(ctx, *root, *out, *arch); e != nil {
			return e
		}
		if e = sharedrelease.CompareLinuxBuild(*root, *dist, *out, *arch, b, *epoch); e != nil {
			os.Remove(*out)
			return e
		}
		return nil
	case "crosscheck":
		if e = sourceBinding(ctx, *root, *archive, b.Commit, *epoch); e != nil {
			return e
		}
		if e = sharedrelease.VerifyCrossSource(*dist, *archive, b); e != nil {
			return e
		}
		return sharedrelease.CompareLinuxBuild(*root, *dist, *binary, *arch, b, *epoch)
	case "collect":
		if *qualification {
			return errors.New("production-fixture-trust-refused")
		}
		a, e := darwinrelease.Admit(ctx, *root, b.Tag, b.TagObject)
		if e != nil {
			return e
		}
		if a.Commit != b.Commit {
			return errors.New("artifact-admitted-commit-mismatch")
		}
		return sharedrelease.CaptureBundle(ctx, *artifactZIP, *out, b, sharedrelease.ArtifactReference{ID: *artifactID, RunID: *artifactRun, SHA256: *artifactDigest, Platform: *platform})
	case "linux":
		if e = sharedrelease.VerifyTools(tools); e != nil {
			return e
		}
		if e = sourceBinding(ctx, *root, *archive, b.Commit, *epoch); e != nil {
			return e
		}
		trust := "qualification"
		if !*qualification {
			a, e := darwinrelease.Admit(ctx, *root, b.Tag, b.TagObject)
			if e != nil {
				return e
			}
			if a.Commit != b.Commit {
				return errors.New("linux-admitted-commit-mismatch")
			}
			trust = "production"
		}
		if e = sharedrelease.PrepareLinux(*root, *dist, *out, *archive, b, *epoch, trust, tools); e != nil {
			return e
		}
		if !*qualification {
			sum := filepath.Join(*out, "linux-checksums.txt")
			c := exec.CommandContext(ctx, "cosign", "sign-blob", "--yes", "--output-signature", sum+".sig", "--output-certificate", sum+".pem", sum)
			if e = c.Run(); e != nil {
				os.RemoveAll(*out)
				return errors.New("linux-checksum-keyless-sign-refused")
			}
			if e = sharedrelease.Cosign(ctx, sum, sum+".sig", sum+".pem", b, sharedrelease.Workflow); e != nil {
				os.RemoveAll(*out)
				return e
			}
		}
		return nil
	case "manifest":
		if *qualification {
			return errors.New("production-fixture-trust-refused")
		}
		a, e := darwinrelease.Admit(ctx, *root, b.Tag, b.TagObject)
		if e != nil {
			return e
		}
		if a.Commit != b.Commit {
			return errors.New("manifest-admitted-commit-mismatch")
		}
		return sharedrelease.SealManifest(ctx, b, *dist, *out)
	default:
		return errors.New("usage: unknown distribution command")
	}
}

// The source archive, checkout, and epoch must describe the same Git object.
// Compilation is offline and buildvcs=false; the archive is explicit evidence.
func sourceBinding(ctx context.Context, root, archive, commit string, epoch int64) error {
	git := func(args ...string) (string, error) {
		c := exec.CommandContext(ctx, "git", args...)
		c.Dir = root
		b, e := c.Output()
		return strings.TrimSpace(string(b)), e
	}
	head, e := git("rev-parse", "HEAD")
	if e != nil || head != commit {
		return errors.New("linux-source-checkout")
	}
	dirty, e := git("status", "--porcelain", "--untracked-files=all")
	if e != nil || dirty != "" {
		return errors.New("linux-source-dirty")
	}
	stamp, e := git("show", "-s", "--format=%ct", commit)
	if e != nil || stamp != strconv.FormatInt(epoch, 10) {
		return errors.New("linux-source-epoch")
	}
	b, e := os.ReadFile(archive)
	if e != nil {
		return errors.New("linux-source-archive")
	}
	c := exec.CommandContext(ctx, "git", "archive", "--format=tar", commit)
	c.Dir = root
	h := sha256.New()
	c.Stdout = h
	if e = c.Run(); e != nil || hex.EncodeToString(h.Sum(nil)) != sharedrelease.Hash(b) {
		return errors.New("linux-source-archive-binding")
	}
	return nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if e := run(ctx, os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "a2a-distribution:", e)
		os.Exit(1)
	}
}
