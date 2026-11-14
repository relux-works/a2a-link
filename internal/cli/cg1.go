package cli

// Fork build-time registration. cg1 remains Nostr-only; cg1-matrix requires
// protected per-identity configuration, a verified envelope and a co-signature.
import _ "github.com/relux-works/a2a-swarm/internal/cg1"
