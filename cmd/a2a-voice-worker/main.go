// Command a2a-voice-worker is the optional native inference process.
package main

import (
	"os"

	"github.com/relux-works/a2a-swarm/internal/voiceworker"
)

func main() {
	// The worker validates and holds the model directory through native use.
	os.Exit(voiceworker.Worker(os.Args[1:], os.Stdin))
}
