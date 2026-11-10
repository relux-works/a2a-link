package cli

// Fork build-time registration. Matrix sessions retain Nostr:false and cannot
// construct CG1. The NIP-17 engine wiring is a separate delivery unit.
import _ "github.com/relux-works/a2a-swarm/internal/cg1"
