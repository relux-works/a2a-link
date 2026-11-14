// Command a2a-cask renders the a2a Homebrew cask from release checksum files.
//
//	a2a-cask -version X.Y.Z -checksums FILE [-checksums FILE ...] [-verify-dir DIR] -out FILE
//
// -checksums may repeat (for example the Darwin checksums.txt and the Linux
// linux-checksums.txt). With -verify-dir, every referenced archive in DIR is
// re-hashed and must match before anything is written. It only renders; it
// never publishes.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/relux-works/a2a-swarm/internal/cask"
)

type files []string

func (f *files) String() string     { return strings.Join(*f, ",") }
func (f *files) Set(v string) error { *f = append(*f, v); return nil }

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "a2a-cask:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("a2a-cask", flag.ContinueOnError)
	version := fs.String("version", "", "stable release version, X.Y.Z")
	verify := fs.String("verify-dir", "", "directory holding the referenced archives to re-hash")
	out := fs.String("out", "", "cask file to write")
	var sums files
	fs.Var(&sums, "checksums", "sha256sum-format checksum file (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *version == "" || *out == "" || len(sums) == 0 || fs.NArg() != 0 {
		return fmt.Errorf("%w: -version, -checksums and -out are required", cask.ErrUsage)
	}
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
	body, err := cask.Render(*version, digests)
	if err != nil {
		return err
	}
	if *verify != "" {
		if err := cask.VerifyFiles(*verify, *version, digests); err != nil {
			return err
		}
	}
	return os.WriteFile(*out, body, 0o644)
}
