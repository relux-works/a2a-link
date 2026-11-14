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
//  1. Authenticity: cosign verify-blob on the manifest bytes. Production uses
//     keyless, with the expected certificate identity and issuer. -fixture-key
//     is qualification-only FIXTURE TRUST and is logged as such; it is never
//     production authority.
//  2. Schema: the closed manifest schema (internal/cask.ParseManifest).
//  3. Binding: every referenced archive digest must equal both the checksum
//     files and the actual bytes in -assets-dir.
//  4. Render, then an atomic write of -out.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/relux-works/a2a-swarm/internal/cask"
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
	assets := fs.String("assets-dir", "", "directory holding the referenced archives")
	out := fs.String("out", "", "cask file to write")
	var sums files
	fs.Var(&sums, "checksums", "qualified platform checksum file (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifest == "" || *signature == "" || *assets == "" || *out == "" || len(sums) == 0 || fs.NArg() != 0 {
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
	if verify == nil {
		if keyless {
			verify = cosignVerifier([]string{"--certificate", *certificate, "--certificate-identity", *identity, "--certificate-oidc-issuer", *issuer})
		} else {
			fmt.Fprintln(log, "a2a-cask: authenticity: FIXTURE TRUST (qualification only, not production authority)")
			verify = cosignVerifier([]string{"--key", *fixtureKey, "--insecure-ignore-tlog=true"})
		}
	}
	// 1. Authenticity, on the exact bytes that are then parsed.
	raw, err := os.ReadFile(*manifest)
	if err != nil {
		return fmt.Errorf("manifest-unreadable: %s", *manifest)
	}
	if err := verify(*manifest, *signature); err != nil {
		return err
	}
	if again, err := os.ReadFile(*manifest); err != nil || string(again) != string(raw) {
		return errors.New("manifest-changed-during-verification")
	}
	// 2. Schema.
	m, err := cask.ParseManifest(raw)
	if err != nil {
		return err
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
