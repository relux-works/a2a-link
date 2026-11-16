# Nostr-only CG1 admission foundation

The `cg1` factory described here remains Nostr-only. The separate
[cg1-matrix Track A policy](g1-gate-1.md) uses the same seam with a verified
Ed25519 envelope and a per-message BIP-340 co-signature. The modern grantcheck
pin requires explicit W and rejects old unpinned state; no live migration is
performed by this source change.


This fork registers `cg1` through `RegisterNostrOnly` at build time. Matrix CLI
and Courier sessions open with `Nostr:false`, so selecting cg1 there refuses
startup before policy configuration, sends or uploads. The separate
[host-selected Nostr session](nostr-session.md) supplies the authenticated AL2
transport boundary. The module path remains the upstream a2a-swarm path so
that the published transport's import refers to one transport registry.

The fork uses Go 1.26 and selects grantcheck and rental-gateway/kernelbind
from the same landed snapshot named in [the current pins](g1-gate-1.md#source-pins-and-scope);
it has no local replaces. LICENSE and NOTICE are
byte-identical to upstream PR251 commit 5880b68929d3f83c64fb13719707e894ea1dec16.
That PR was open when this work was prepared; copying its proposed files is not
a claim that upstream licensing/public-release authorization has completed.

## Trusted Nostr input contract for AL2

The reference is `relux-works/a2a-transport-nostr` commit
`4ac03aed0a7cab0e8be30a4cd9e1ca8a621db1e9` (N2 seam/N3a conformance/N3b drain),
whose public seam imports a2a-swarm at db64f2d1. In
`nostrtransport/adapter_sync.go`, verifyWrap calls UnwrapDM, validates participants
and creates Event.Sender from the verified inner seal sender, Event.ID from the
rumor ID and Event.Time from its authenticated created_at. Its `savedEvent.event`
projection keeps those values. Neither Raw nor message body is identity proof.

The engine constructs admission.TrustedNostrInbound with:

| Field | Trusted producer |
| --- | --- |
| Sender | Exact lowercase x-only key from verified transport Event.Sender |
| Recipient | Local authenticated transport Self().ID; verifyWrap established delivery to it |
| EventID | Transport Event.ID, the authenticated rumor ID |
| Time | Transport Event.Time, Unix-second precision |
| Presentation | Separately extracted, untrusted complete grant-cert and grant ID; checked by CG1 |

Config.NostrPubkey must equal that local transport identity and is supplied by
the authenticated engine, not caller flags/body. The adapter validates the tuple,
rejects absent/invalid metadata and ignores the legacy Matrix Sender/Body fields.
The Go type is an engine trust contract, not a cryptographic verifier. Never
unmarshal an incoming body's claims into it. Nil Presentation means no supplied
proof and allows CG1's same-identity admitted cache; a non-nil malformed proof
never falls back. Private held state retains the trusted tuple for rechecking;
AL2 commits it only with the verified event and preserves cursor semantics.

TrustedNostrOutbound contains one exact recipient from the transport-validated
conversation. It is not Message.To or a caller-provided body field. Before each
recipient's signing/encryption/send, including retries and reconnects, invoke
Outbound with the local engine identity and that recipient. There is no outbound
event ID yet before signing. Multi-recipient authorization and its atomicity are
AL2 responsibilities; one successful check does not authorize other recipients.
A Live result is a current observation, never a queued reusable permission token.

## Host provisioning

The existing engine derives StateDir beneath the authenticated identity home.
Provision `<StateDir>/cg1.json` mode 0600, a regular single-link owned file:

- version:1 for the unchanged pay/regtest policy, or version:2;
- profile, network, genesis: required exact members in version 2, forbidden in version 1;
  see the [shared policy rules](g1-gate-1.md#per-identity-protected-configuration);
  `profile` is `pay` or `trust`, with an explicit admitted network/genesis pair;
  trust has no network or genesis default;
- agent_name and landlord_name: distinct approved id/ names;
- issuer_pubkey: approved lowercase x-only grant-signing public key;
- executor_key: this consumer's required lowercase x-only executor pin for pay,
  or exactly the empty string for trust;
- max_tip_age_seconds: required integer A > 0;
- max_future_skew_seconds: required integer F in [0, 600], a bench ceiling;
- minimum_height: required integer FLOOR in [0, 2147483647];
- terms: required contract-hash to canonical unpadded-base64url contract map;
  pay retains its terms-v2 startup validator; trust is validated and bound by CG1
  against the presented Grant v3 before admission;
- timeout_ms: an integer from 1 through 5000;
- rpc: host, port, username, password for the verifier's own read-only node.

The route is explicit literal loopback, valid port, username `w3-observer` and a
16..256-byte password, matching the published read-only RPC contract. Provision
credentials privately; no real credentials or hostnames belong in examples or
source. No environment fallback, message field, flag or arbitrary path selects
policy config. Unknown/duplicate/null fields, trailing data, oversized files,
symlinks/hardlinks and permissive modes refuse startup with closed diagnostics.
No RPC request is needed to construct the checker. The host must separately
qualify read-only rpcauth/rpcwhitelist and the pinned regtest node.

CG1 owns `<StateDir>/cg1-state/`, separately from the admission queue/config.
Its persisted identity/name/key pins, clock high-water, proof cache and closure
history survive reopening. Do not delete or substitute state to regain capacity.
No private input or RPC error text is returned in admission decisions.

## Routing, locks and refusal codes

Both hooks invoke the shared protected-policy constructor and real grantcheck
backend. Version 2 checks the node's chain and genesis before each grant check;
version 1 retains its implicit pay/regtest pins and backend-only node checks. Inbound Live reaches ordinary
delivery; inbound no_grant/not_yet/expired or proven closure routes to Exchange;
these states never allow an outbound send. Current identity expiry is instead a
named `identity_expired` refusal in both directions, closed and nonretryable. Outbound requires a previously live
admitted proof and rechecks it. Scope remains CG1 metadata, not execution authority.

The fork explicitly extends admission's reason vocabulary with CG1's exact codes:
`live`, `no_grant`, `not_yet`, `expired`, `seal_spent`, `landlord_rotated`,
`landlord_changed`, `identity_expired`, `identity_pending`, `grant_pending`, `binding_mismatch`,
`invalid_presentation`, `oversize`, `invalid_peer`, `verifier_unavailable`,
`state_unavailable`, `clock_invalid`, `cancelled`, `busy`, `check_failed`.
Only verifier/state unavailable, clock invalid, cancelled, busy, grant pending
and identity pending are retryable. Unknown or inconsistent verdict/retry/closure
combinations become definite check_failed. Existing upstream reason codes remain.

Issue431 F1: the upstream inbound seam holds state/mailbox/queue locks. Each CG1
call gets its own <=5s context budget (earlier caller cancellation wins); the
session owns a loopback-only read RPC client with redirects and keepalive disabled.
Closing the checker cancels in-flight calls and closes idle connections. No detached worker or unbounded authorization
queue is created. CG1's try-lock and durable cross-process lock own concurrent
state; the upstream session mutex alone is not cross-process serialization.
Cancellation never returns Live. This bounds cooperative RPC work, not a kernel
filesystem syscall stalled by the OS. Keep identity state on qualified storage.

Issue431 F2: the matrixtransport registry factory creates an unguarded Matrix
client and is NOT adopted as a CG1 transport. Existing Matrix none behavior is
unchanged. AL2 explicitly installs admission on its authenticated Nostr path;
calling a transport directly is not an admission boundary.

Issue431 F3: upstream Matrix attach/voice uploads precede the send guard. CG1
cannot start a Matrix session, so it cannot use that path. AL2 rejects Nostr
media before upload until it supplies a separate reviewed pre-upload contract;
a later event refusal cannot undo an upload. State/account-data/membership and
redactions remain outside the message seam. This foundation does not claim to
fix unrelated upstream hardening issues F5-F11.

## Validation tools and limits

- `go test -race -count=1 ./internal/cg1 ./internal/admission` covers configuration,
  tuple validation, exact routing, cancellation/close, real child-process lock
  contention, read-only RPC boundaries and refusal controls.
- `go test -race -count=1 -run 'Test(Admission|CG1)' ./internal/cli` exercises the
  actual build registration, Matrix startup refusal and existing delivery gates.
- `internal/cli/testdata/admission-base` holds exact e68c9a10 mailbox/state/request
  fixtures captured from the unmodified upstream scenarios. Candidate tests
  compare bytes; they cannot regenerate fixtures. Same-tree nil-policy controls
  remain alongside the independent baseline.
- `CG1_REGTEST=1 CG1_RUN_ROOT=<fresh-absolute-root>
  CG1_CORE_DAEMON=<pinned-namecoind> CG1_CORE_CLI=<pinned-namecoin-cli>
  go test -race -count=1 -run '^TestCoreAdmission$' -v ./internal/cg1` checks the
  real issuer, published CG1/K1 and isolated Core. It uses only generated fixture
  custody and stops its recorded node PID. Never publish the private/ subdirectory.
- Launch from an absolute physical task-owned scratch checkout with HOME,
  config, caches and temporary directories inside the same root. Keep macOS
  socket fixture paths short enough for the existing 103-byte limit; never
  move test writes into a shared host temporary directory or SDK.
- `go vet ./internal/cg1 ./internal/admission ./internal/cli`, `go mod verify`,
  `go mod tidy -diff`, `gofmt -l` and `git diff --check` are the remaining checks.

The foundation alone does not activate NIP-17; see the AL2 session contract for
that path. Matrix identity mapping, S1 resolver, owner bypass, media authorization,
deployment and mainnet acceptance remain outside this unit.

Remaining integration work is recorded in [UNRESOLVED_QUESTIONS.md](../UNRESOLVED_QUESTIONS.md).

The required grant configuration now also includes `executor_key`,
`max_tip_age_seconds` (A), `max_future_skew_seconds` (F), `minimum_height`
(FLOOR), and canonical `terms` indexed by contract hash. None defaults;
explicit zero F/FLOOR is permitted. The interim bench freshness rule's hidden
age bound is A + F and is superseded by LIP-0022 once accepted. See the
[required fields and provisioning contract](g1-gate-1.md#per-identity-protected-configuration).
The Nostr constructor also requires these fields; older protected configuration
and differently bound durable state refuse rather than being migrated silently.
