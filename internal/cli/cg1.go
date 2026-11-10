package cli

// Fork build-time registration. Matrix sessions retain Nostr:false and cannot
// construct CG1. Nostr sessions open it only after the adapter authenticates Self.
import _ "github.com/relux-works/a2a-swarm/internal/cg1"
