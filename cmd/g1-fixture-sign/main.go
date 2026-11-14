// g1-fixture-sign produces only a public-fixture co-signature, never an envelope or grant.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/relux-works/a2a-swarm/internal/cg1cosign"
	"github.com/relux-works/a2a-swarm/internal/matrix"
	"io"
	"os"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "fixture co-signature refused")
		os.Exit(1)
	}
}
func run(args []string, output io.Writer) error {
	fs := flag.NewFlagSet("g1-fixture-sign", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fixture := fs.String("fixture", "", "public fixture alice or bob")
	path := fs.String("envelope", "", "exact envelope file")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *path == "" {
		return cg1cosign.ErrInvalid
	}
	f, e := os.Open(*path)
	if e != nil {
		return e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, matrix.EnvelopeMaxBytes+1))
	if e != nil {
		return e
	}
	out, e := cg1cosign.FixtureSign(b, *fixture)
	if e != nil {
		return e
	}
	return json.NewEncoder(output).Encode(out)
}
