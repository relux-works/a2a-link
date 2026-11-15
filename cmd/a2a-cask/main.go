// Command a2a-cask derives the a2a Homebrew cask from the signed platform
// manifest. It is the single gated entry point. It renders and never
// publishes.
//
//	a2a-cask -manifest release-assets.json -signature release-assets.json.sig \
//	  (-certificate CERT -certificate-identity ID -certificate-oidc-issuer ISS | -fixture-key PUB) \
//	  -checksums checksums.txt -checksums linux-checksums.txt -assets-dir DIR -out a2a.rb
//
// Every input is required, and the steps run in a fixed order. Any refusal
// writes nothing.
//  1. Authenticity: cosign verify-blob on a private copy of the manifest bytes,
//     which are read once and are the same bytes then parsed. Production uses
//     keyless, with the expected certificate identity and issuer. -fixture-key
//     is qualification-only FIXTURE TRUST and is logged as such; it is never
//     production authority.
//  2. Schema: the closed manifest schema (internal/cask.ParseManifest).
//  3. Binding: every referenced archive digest must equal both the checksum
//     files and the actual bytes in -assets-dir.
//  4. Render, then an atomic write of -out.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/relux-works/a2a-swarm/internal/cask"
	"github.com/relux-works/a2a-swarm/internal/caskbrew"
	"github.com/relux-works/a2a-swarm/internal/sharedrelease"
)

type files []string

func (f *files) String() string     { return strings.Join(*f, ",") }
func (f *files) Set(v string) error { *f = append(*f, v); return nil }

// verifier authenticates the manifest bytes at path against its signature.
type verifier func(manifest, signature string) error

func main() {
	if err := run(os.Args[1:], os.Stderr, nil); err != nil {
		fmt.Fprintln(os.Stderr, "a2a-cask:", err)
		os.Exit(1)
	}
}

// cosignVerifier runs cosign verify-blob with exactly one trust mode.
func cosignVerifier(args []string) verifier {
	return func(manifest, signature string) error {
		cmd := exec.Command("cosign", append(append([]string{"verify-blob", "--signature", signature}, args...), manifest)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("manifest-authenticity: cosign verify-blob refused: %s", strings.TrimSpace(string(out)))
		}
		return nil
	}
}

func run(args []string, log io.Writer, verify verifier) error {
	fs := flag.NewFlagSet("a2a-cask", flag.ContinueOnError)
	manifest := fs.String("manifest", "", "signed platform manifest (release-assets.json)")
	signature := fs.String("signature", "", "manifest signature")
	certificate := fs.String("certificate", "", "keyless signing certificate (production)")
	identity := fs.String("certificate-identity", "", "expected keyless certificate identity (production)")
	issuer := fs.String("certificate-oidc-issuer", "", "expected keyless OIDC issuer (production)")
	fixtureKey := fs.String("fixture-key", "", "qualification-only fixture public key (FIXTURE TRUST)")
	tag := fs.String("tag", "", "independently verified stable tag (production)")
	commit := fs.String("commit", "", "independently verified source commit (production)")
	tagObject := fs.String("tag-object", "", "independently verified annotated tag object (production)")
	assets := fs.String("assets-dir", "", "directory holding the referenced archives")
	out := fs.String("out", "", "cask file to write")
	proposed := fs.String("proposed", "", "custody: proposed cask bytes (verification only)")
	brewInfo := fs.String("brew-info", "", "custody: pinned Homebrew evaluated JSON")
	brewPrefix := fs.String("brew-prefix", "", "custody: isolated evaluation prefix")
	brewPlatform := fs.String("brew-platform", "", "custody: evaluated OS/architecture")
	tapDir := fs.String("tap-dir", "", "custody: existing signed tap feature checkout (read-only)")
	tapBase := fs.String("tap-base", "", "custody: independently fetched tap main commit")
	rendererRevision := fs.String("renderer-revision", "", "custody: clean renderer checkout revision")
	var sums files
	fs.Var(&sums, "checksums", "qualified platform checksum file (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifest == "" || *signature == "" || *assets == "" || (*out == "" && *proposed == "") || len(sums) == 0 || fs.NArg() != 0 {
		return errors.New("usage: -manifest, -signature, -checksums, -assets-dir and -out are required")
	}
	keyless := *certificate != "" || *identity != "" || *issuer != ""
	switch {
	case keyless && *fixtureKey != "":
		return errors.New("usage: choose keyless verification or -fixture-key, not both")
	case keyless && (*certificate == "" || *identity == "" || *issuer == ""):
		return errors.New("usage: keyless verification needs -certificate, -certificate-identity and -certificate-oidc-issuer")
	case !keyless && *fixtureKey == "":
		return errors.New("usage: an authenticity mode is required")
	}
	bound := sharedrelease.Binding{Tag: *tag, Commit: *commit, TagObject: *tagObject}
	if keyless {
		if err := bound.Validate(); err != nil {
			return err
		}
		if *identity != sharedrelease.Identity(sharedrelease.Workflow, bound.Tag) || *issuer != sharedrelease.Issuer {
			return errors.New("manifest-workflow-identity-refused")
		}
	}
	if verify == nil {
		if !keyless {
			fmt.Fprintln(log, "a2a-cask: authenticity: FIXTURE TRUST (qualification only, not production authority)")
			verify = cosignVerifier([]string{"--key", *fixtureKey, "--insecure-ignore-tlog=true"})
		}
	}
	// 1. Authenticity, on the exact bytes that are then parsed: the manifest
	// is read ONCE; cosign verifies a private copy of those captured bytes,
	// and the same bytes are parsed. A later change to the path is irrelevant.
	raw, err := os.ReadFile(*manifest)
	if err != nil {
		return fmt.Errorf("manifest-unreadable: %s", *manifest)
	}
	var m cask.Manifest
	if keyless {
		// Production accepts only the complete /2 aggregate and pinned keyless
		// source claims. Fixture /1 manifests never reach this route.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		production, err := sharedrelease.VerifyProduction(ctx, raw, *signature, *certificate, *assets, bound, nil)
		if err != nil {
			return err
		}
		m = production.Cask()
	} else {
		// Fixture trust cannot authorize the production schema, even if the
		// fixture signature is otherwise cryptographically valid.
		var header struct {
			Schema string `json:"schema"`
		}
		if json.Unmarshal(raw, &header) == nil && header.Schema == sharedrelease.Schema {
			return errors.New("production-fixture-trust-refused")
		}
		private, err := os.MkdirTemp("", "a2a-cask-manifest-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(private)
		captured := filepath.Join(private, "release-assets.json")
		if err := os.WriteFile(captured, raw, 0o600); err != nil {
			return err
		}
		if err := verify(captured, *signature); err != nil {
			return err
		}
		// 2. Schema.
		m, err = cask.ParseManifest(raw)
		if err != nil {
			return err
		}
	}
	// 3. Binding.
	digests := map[string]string{}
	for _, path := range sums {
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("checksums-unreadable: %s", path)
		}
		err = cask.ParseChecksums(f, digests)
		f.Close()
		if err != nil {
			return err
		}
	}
	if err := cask.Bind(m, digests, *assets); err != nil {
		return err
	}
	// Custody is read-only and repeats production authentication and binding.
	if *proposed != "" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if !keyless || *brewInfo == "" || *brewPrefix == "" || *brewPlatform == "" || *tapDir == "" || *tapBase == "" || *rendererRevision != bound.Commit || *out != "" {
			return errors.New("custody-input-contract")
		}
		head, e := exec.Command("git", "rev-parse", "HEAD").Output()
		if e != nil || strings.TrimSpace(string(head)) != *rendererRevision {
			return errors.New("custody-renderer-revision")
		}
		dirty, e := exec.Command("git", "status", "--porcelain", "--untracked-files=all").Output()
		if e != nil || len(dirty) != 0 {
			return errors.New("custody-renderer-dirty")
		}
		ruby, e := os.ReadFile(*proposed)
		if e != nil {
			return e
		}
		info, e := os.ReadFile(*brewInfo)
		if e != nil {
			return e
		}
		if e = caskbrew.Verify(info, ruby, m, *brewPrefix, *brewPlatform); e != nil {
			return e
		}
		if e = caskbrew.VerifyTapRepository(ctx, *tapDir, *tapBase, ruby); e != nil {
			return e
		}
		return json.NewEncoder(log).Encode(map[string]string{"result": "custody-prepared-not-published", "manifest_sha256": sharedrelease.Hash(raw), "renderer_revision": *rendererRevision, "cask_sha256": sharedrelease.Hash(ruby), "tag": bound.Tag, "tag_object": bound.TagObject})
	}
	if *brewInfo != "" || *brewPrefix != "" || *brewPlatform != "" || *tapDir != "" || *tapBase != "" || *rendererRevision != "" {
		return errors.New("custody-input-contract")
	}
	// 4. Render and write atomically.
	body, err := cask.Render(m)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(*out), ".a2a-cask-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), *out)
}
