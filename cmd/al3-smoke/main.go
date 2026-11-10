// al3-smoke is an opt-in bounded worker, never an identity provisioner or daemon.
package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/relux-works/a2a-swarm/internal/al3smoke"
	_ "github.com/relux-works/a2a-swarm/internal/cg1"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

type durableOutput struct{ *os.File }

func (w durableOutput) Write(b []byte) (int, error) {
	n, e := w.File.Write(b)
	if e == nil {
		e = w.File.Sync()
	}
	return n, e
}
func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "al3: smoke refused (private details withheld)")
		os.Exit(1)
	}
}
func run() error {
	var o al3smoke.Options
	var output string
	var timeout time.Duration
	flag.StringVar(&o.Base, "config-root", "", "absolute existing host config root")
	flag.StringVar(&o.Identity, "identity", "", "existing CG1 Nostr identity")
	flag.StringVar(&o.Peer, "peer", "", "peer public key")
	flag.StringVar(&o.Relay, "relay", "", "supplied relay URL; observed route only")
	flag.StringVar(&o.Role, "role", "", "a initiates ping, b replies pong")
	flag.StringVar(&o.RunID, "run-id", "", "shared fresh 16 lowercase hex digits")
	flag.StringVar(&output, "output", "", "absolute new public evidence file")
	flag.DurationVar(&timeout, "timeout", 60*time.Second, "bounded run, maximum 2m")
	flag.Parse()
	if flag.NArg() != 0 || o.Validate() != nil || timeout < time.Second || timeout > 2*time.Minute || !filepath.IsAbs(output) || filepath.Clean(output) != output {
		return al3smoke.ErrSmoke
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	f, e := openOutput(output)
	if e != nil {
		return al3smoke.ErrSmoke
	}
	defer f.Close()
	return al3smoke.Run(ctx, o, durableOutput{f})
}

// Persist the newly created directory entry before any output can authorize a
// mailbox receipt. Existing files and symlinked parents are never replaced.
func openOutput(path string) (*os.File, error) {
	parent := filepath.Dir(path)
	actual, e := filepath.EvalSymlinks(parent)
	if e != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || actual != parent {
		return nil, al3smoke.ErrSmoke
	}
	dir, e := os.Open(parent)
	if e != nil {
		return nil, e
	}
	defer dir.Close()
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return nil, e
	}
	if e = dir.Sync(); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
